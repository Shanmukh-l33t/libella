"""AWS cloud posture audit: read-only, scope-enforced, evidence-bound.

boto3 talks to an operator-supplied endpoint (the moto CloudLab, a localstack,
or an authorized real account). Every call is checked against a read-only
allowlist before it leaves the process: a posture assessment must never mutate
the account it looks at, so a write API is a programming error, not a finding.
"""
import datetime
import ipaddress
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .db import DB
from .evidence import EvidenceStore
from .findings import FindingPipeline
from .scope import ALWAYS_BLOCKED, Scope

READ_ONLY_PREFIXES = ("Describe", "List", "Get", "Lookup", "Head")
STALE_KEY_DAYS = 90
SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}
# Actions that turn "can call these" into "can become admin" when paired with PassRole.
ESCALATION_PRIMS = {
    "iam:attachuserpolicy", "iam:putuserpolicy", "iam:createpolicyversion",
    "iam:setdefaultpolicyversion", "iam:createaccesskey", "iam:createloginprofile",
    "iam:updateloginprofile", "iam:attachrolepolicy", "iam:putrolepolicy",
    "sts:assumerole", "lambda:createfunction", "ec2:runinstances",
}


class ReadOnlyViolation(PermissionError):
    """Raised before the wire if anything but a read API is attempted."""


class Clients:
    """boto3 client factory with a hard read-only gate + call ledger."""

    def __init__(self, endpoint_url: str, region: str, creds: dict):
        self.kwargs = {
            "endpoint_url": endpoint_url, "region_name": region,
            "aws_access_key_id": creds["access_key_id"],
            "aws_secret_access_key": creds["secret_access_key"],
        }
        if creds.get("session_token"):
            self.kwargs["aws_session_token"] = creds["session_token"]
        self.calls: list[str] = []

    def _guard(self, model, **_):
        if not model.name.startswith(READ_ONLY_PREFIXES):
            raise ReadOnlyViolation(f"cloud audit attempted write API {model.name}")
        self.calls.append(model.name)

    def client(self, service: str):
        c = boto3.client(service, **self.kwargs)
        c.meta.events.register("before-call", self._guard)
        return c


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _statements(document: dict) -> list[dict]:
    if not isinstance(document, dict):
        return []
    return [s for s in _as_list(document.get("Statement", [])) if isinstance(s, dict)]


def _allows(statement: dict, action: str) -> bool:
    return statement.get("Effect") == "Allow" and any(
        a.lower() in (action.lower(), "*") for a in _as_list(statement.get("Action", [])))


def _cand(title, cwe, severity, confidence, endpoint, description, impact, remediation,
          evidence_id, quote, dedup_key) -> dict:
    return {
        "title": title, "cwe": cwe, "owasp": "A05:2021 Security Misconfiguration",
        "severity": severity, "confidence": confidence, "endpoint": endpoint,
        "description": description, "impact": impact, "remediation": remediation,
        "evidence_ids": [evidence_id], "quote": quote, "quote_in": "cloud_fact",
        "proof_request": {"method": "CLOUD", "url": endpoint}, "dedup_key": dedup_key,
    }


class _Ctx:
    """Everything a check needs; one instance per assessment."""

    def __init__(self, clients, pipeline, evidence, engagement_id, intent_id,
                 account_id, region):
        self.clients = clients
        self.pipeline = pipeline
        self.evidence = evidence
        self.eng = engagement_id
        self.intent_id = intent_id
        self.account_id = account_id
        self.region = region
        self.base = f"aws://{account_id}/{region}"

    def record(self, kind: str, facts: dict, observation: str) -> str:
        ev = self.evidence.put_json(self.eng, facts, kind)
        self.pipeline.record_observation(self.eng, self.intent_id, kind, observation, ev["id"])
        return ev["id"]


# --- IAM: wildcard admin + privilege-escalation paths -----------------------------

def _policy_documents(iam) -> list[dict]:
    """Every policy document in the account: managed (local), attached, inline."""
    out = []
    for p in iam.list_policies(Scope="Local")["Policies"]:
        ver = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
        out.append({"label": p["PolicyName"], "arn": p["Arn"],
                    "document": ver["PolicyVersion"]["Document"]})
    for user in iam.list_users()["Users"]:
        name = user["UserName"]
        for name_inline in iam.list_user_policies(UserName=name)["PolicyNames"]:
            doc = iam.get_user_policy(UserName=name, PolicyName=name_inline)["PolicyDocument"]
            out.append({"label": f"{name}/{name_inline}", "arn": f"user:{name}/{name_inline}",
                        "document": doc})
    return out


def _check_iam(ctx: _Ctx) -> list[dict]:
    iam = ctx.clients.client("iam")
    policies = _policy_documents(iam)
    ev = ctx.record("cloud_iam_posture", {
        "account_id": ctx.account_id, "policies": policies,
        "users": [u["UserName"] for u in iam.list_users()["Users"]],
    }, f"iam: {len(policies)} policy documents inspected")
    out = []
    for p in policies:
        endpoint = f"aws:iam::{ctx.account_id}:policy/{p['label']}"
        for st in _statements(p["document"]):
            if st.get("Effect") != "Allow":
                continue
            actions = [a.lower() for a in _as_list(st.get("Action", []))]
            resources = [str(r) for r in _as_list(st.get("Resource", []))]
            full_admin = "*" in actions and "*" in resources
            service_admin = "*" in resources and any(a.endswith(":*") for a in actions)
            if full_admin or service_admin:
                out.append(_cand(
                    f"IAM policy '{p['label']}' grants wildcard permissions",
                    "CWE-732", "critical" if full_admin else "high", "high", endpoint,
                    f"Statement allows {actions} on {resources}.",
                    "Any principal holding this policy can administer or destroy the account.",
                    "Replace with least-privilege actions on specific resource ARNs.",
                    ev, f"wildcard: {p['label']}", f"cloud-iam-wildcard:{endpoint}"))
            passed_role = any(a == "iam:passrole" for a in actions) and "*" in resources
            escalate = passed_role and any(a in ESCALATION_PRIMS for a in actions)
            if escalate:
                out.append(_cand(
                    f"IAM policy '{p['label']}' enables privilege escalation",
                    "CWE-269", "high", "high", endpoint,
                    "iam:PassRole on '*' combined with an admin-granting action "
                    f"({sorted(set(actions) & ESCALATION_PRIMS)}).",
                    "A holder can pass a privileged role to a service they control and "
                    "obtain that role's permissions.",
                    "Scope iam:PassRole to specific role ARNs; drop policy-mutation rights.",
                    ev, f"passrole: {p['label']}", f"cloud-iam-privesc:{endpoint}"))
    return out


# --- S3: public exposure + default encryption -------------------------------------

def _s3_facts(s3) -> list[dict]:
    facts = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        row = {"bucket": name}
        try:
            row["public_access_block"] = s3.get_public_access_block(
                Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            row["public_access_block"] = None
            row["public_access_block_error"] = e.response["Error"]["Code"]
        try:
            row["policy"] = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError as e:
            row["policy"] = None
            row["policy_error"] = e.response["Error"]["Code"]
        try:
            row["encryption"] = s3.get_bucket_encryption(Bucket=name)[
                "ServerSideEncryptionConfiguration"]
        except ClientError as e:
            row["encryption"] = None
            row["encryption_error"] = e.response["Error"]["Code"]
        facts.append(row)
    return facts


def _public_statement(policy_json: str | None) -> bool:
    import json
    if not policy_json:
        return False
    try:
        doc = json.loads(policy_json)
    except ValueError:
        return False
    for st in _statements(doc):
        principal = st.get("Principal")
        if st.get("Effect") == "Allow" and (
                principal == "*" or (isinstance(principal, dict) and "*" in
                                     _as_list(principal.get("AWS", [])))):
            return True
    return False


def _check_s3(ctx: _Ctx) -> list[dict]:
    s3 = ctx.clients.client("s3")
    buckets = _s3_facts(s3)
    ev = ctx.record("cloud_s3_posture", {"buckets": buckets},
                    f"s3: {len(buckets)} buckets inspected")
    out = []
    for b in buckets:
        name = b["bucket"]
        pab = b["public_access_block"] or {}
        blocked = all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                           "BlockPublicPolicy", "RestrictPublicBuckets"))
        endpoint = f"aws:s3:::{name}"
        if _public_statement(b["policy"]) and not blocked:
            out.append(_cand(
                f"S3 bucket '{name}' is publicly accessible", "CWE-284", "high", "high",
                endpoint, "Bucket policy allows Principal '*' and public access block "
                "does not neutralise it.",
                "Anyone on the internet can read the bucket; data leak by design.",
                "Set all four public access block flags and remove the public statement.",
                ev, f"public bucket: {name}", f"cloud-s3-public:{endpoint}"))
        elif not blocked:
            out.append(_cand(
                f"S3 bucket '{name}' lacks public access block", "CWE-732", "low", "high",
                endpoint, "One or more Block Public Access flags are unset.",
                "A future policy or ACL mistake becomes internet-exposed immediately.",
                "Enable all four public access block settings on the bucket/account.",
                ev, f"pab off: {name}", f"cloud-s3-pab:{endpoint}"))
        if not b["encryption"]:
            out.append(_cand(
                f"S3 bucket '{name}' has no default encryption", "CWE-311", "medium", "high",
                endpoint, "No ServerSideEncryptionConfiguration on the bucket.",
                "Objects written without explicit SSE are stored in plaintext at rest.",
                "Enable default SSE-S3 or SSE-KMS on the bucket.",
                ev, f"unencrypted: {name}", f"cloud-s3-enc:{endpoint}"))
    return out


# --- Network: world-open ingress ---------------------------------------------------

def _check_security_groups(ctx: _Ctx) -> list[dict]:
    ec2 = ctx.clients.client("ec2")
    groups = ec2.describe_security_groups()["SecurityGroups"]
    ev = ctx.record("cloud_sg_posture", {"security_groups": groups},
                    f"ec2: {len(groups)} security groups inspected")
    out = []
    for g in groups:
        exposed = []
        for perm in g.get("IpPermissions", []):
            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                      if r.get("CidrIpv6") == "::/0"]
            if not cidrs:
                continue
            if perm.get("IpProtocol") in ("-1", "all"):
                lo, hi, proto = 0, 65535, "all"
            else:
                lo, hi = perm.get("FromPort"), perm.get("ToPort")
                proto = perm.get("IpProtocol")
                if not isinstance(lo, int) or not isinstance(hi, int):
                    continue
            hit = sorted(p for p in SENSITIVE_PORTS if lo <= p <= hi)
            exposed.append((cidrs, lo, hi, proto, hit))
        for cidrs, lo, hi, proto, hit in exposed:
            portspec = f"{lo}-{hi}" if lo != hi else str(lo)
            endpoint = f"aws:ec2:{ctx.region}:security-group/{g['GroupId']}"
            label = f"{g.get('GroupName')} ({g['GroupId']})"
            out.append(_cand(
                f"Security group {label} exposes {portspec}/{proto} to the internet",
                "CWE-284", "high" if hit else "medium", "high", endpoint,
                f"Ingress from {cidrs} on {proto}/{portspec}"
                + (f" (sensitive ports {hit})" if hit else "") + ".",
                "Management/remote-access services reachable from the whole internet; "
                "brute force and exploitation attempts follow immediately.",
                "Restrict source ranges to bastion/VPN CIDRs and remove default-open rules.",
                ev, f"open {cidrs}:{proto}/{portspec}",
                f"cloud-sg-open:{g['GroupId']}:{','.join(cidrs)}:{proto}:{portspec}"))
    return out


# --- Logging: CloudTrail + Config ---------------------------------------------------

def _check_logging(ctx: _Ctx) -> list[dict]:
    ct = ctx.clients.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    statuses = {t["Name"]: ct.get_trail_status(Name=t["Name"]) for t in trails}
    try:
        recorders = ctx.clients.client("config").describe_configuration_recorders()[
            "ConfigurationRecorders"]
    except ClientError as e:
        recorders = []
        config_error = e.response["Error"]["Code"]
    else:
        config_error = None
    ev = ctx.record("cloud_logging_posture", {
        "trails": trails,
        "trail_status": {k: {"IsLogging": v.get("IsLogging"),
                             "LatestDeliveryError": v.get("LatestDeliveryError")}
                         for k, v in statuses.items()},
        "config_recorders": recorders, "config_error": config_error,
    }, f"logging: {len(trails)} trails, {len(recorders)} config recorders")
    out = []
    if not trails:
        out.append(_cand("CloudTrail is not configured", "CWE-778", "high", "high",
                         f"aws:cloudtrail:{ctx.account_id}",
                         "describe_trails returned no trail for the account/region.",
                         "API activity is unrecorded; intrusion and misuse are not "
                         "detectable after the fact.",
                         "Create a multi-region trail with log file validation and "
                         "delivery to a protected bucket.",
                         ev, "trails: 0", f"cloud-trail-missing:{ctx.account_id}"))
    for name, st in statuses.items():
        if not st.get("IsLogging"):
            out.append(_cand(f"CloudTrail '{name}' is not logging", "CWE-778", "high", "high",
                             f"aws:cloudtrail:{ctx.account_id}/{name}",
                             f"get_trail_status({name}).IsLogging is false.",
                             "The trail exists but records nothing; the audit gap is silent.",
                             "Start logging and alert on trail status changes.",
                             ev, f"logging off: {name}", f"cloud-trail-off:{name}"))
    if not recorders and config_error is None:
        out.append(_cand("AWS Config has no configuration recorder", "CWE-778", "low", "high",
                         f"aws:config:{ctx.account_id}",
                         "describe_configuration_recorders returned none.",
                         "Resource configuration drift and non-compliance go untracked.",
                         "Enable AWS Config with a recorder covering all resource types.",
                         ev, "recorders: 0", f"cloud-config-missing:{ctx.account_id}"))
    return out


# --- Encryption at rest: EBS + RDS ---------------------------------------------------

def _check_encryption(ctx: _Ctx) -> list[dict]:
    ec2 = ctx.clients.client("ec2")
    volumes = ec2.describe_volumes()["Volumes"]
    rds = ctx.clients.client("rds")
    instances = rds.describe_db_instances()["DBInstances"]
    ev = ctx.record("cloud_encryption_posture", {
        "volumes": [{"VolumeId": v["VolumeId"], "Encrypted": v.get("Encrypted"),
                     "Size": v.get("Size")} for v in volumes],
        "db_instances": [{"DBInstanceIdentifier": d["DBInstanceIdentifier"],
                          "StorageEncrypted": d.get("StorageEncrypted"),
                          "Engine": d.get("Engine")} for d in instances],
    }, f"encryption: {len(volumes)} volumes, {len(instances)} rds instances")
    out = []
    for v in volumes:
        if not v.get("Encrypted"):
            endpoint = f"aws:ec2:{ctx.region}:volume/{v['VolumeId']}"
            out.append(_cand(f"EBS volume {v['VolumeId']} is unencrypted", "CWE-311",
                             "medium", "high", endpoint,
                             "DescribeVolumes reports Encrypted=false.",
                             "Snapshots and the underlying volume are readable if storage "
                             "media or backups leak.",
                             "Enable EBS encryption by default and re-create the volume "
                             "encrypted.", ev, f"unencrypted volume: {v['VolumeId']}",
                             f"cloud-ebs-enc:{endpoint}"))
    for d in instances:
        if not d.get("StorageEncrypted"):
            name = d["DBInstanceIdentifier"]
            endpoint = f"aws:rds:{ctx.region}:db/{name}"
            out.append(_cand(f"RDS instance '{name}' storage is unencrypted", "CWE-311",
                             "high", "high", endpoint,
                             "DescribeDBInstances reports StorageEncrypted=false.",
                             "Database contents and automated snapshots are plaintext at rest.",
                             "Re-create the instance with storage encryption (KMS) enabled.",
                             ev, f"unencrypted rds: {name}", f"cloud-rds-enc:{endpoint}"))
    return out


# --- Root account + credential age ---------------------------------------------------

def _check_root(ctx: _Ctx) -> list[dict]:
    iam = ctx.clients.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    ev = ctx.record("cloud_root_posture", {"summary_map": summary},
                    f"root: AccountMFAEnabled={summary.get('AccountMFAEnabled')}")
    if summary.get("AccountMFAEnabled") != 1:
        return [_cand(
            "Root account has no MFA", "CWE-306", "high", "high",
            f"aws:iam::{ctx.account_id}:root",
            "GetAccountSummary reports AccountMFAEnabled=0.",
            "Root credentials protected by a password alone; a single leak hands over "
            "the whole account.",
            "Enable a hardware or virtual MFA device on the root account and stop using "
            "root for daily work.", ev, "AccountMFAEnabled: 0",
            f"cloud-root-mfa:{ctx.account_id}")]
    return []


def _check_credential_age(ctx: _Ctx) -> list[dict]:
    iam = ctx.clients.client("iam")
    now = datetime.datetime.now(datetime.timezone.utc)
    keys, stale = [], []
    for user in iam.list_users()["Users"]:
        for k in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
            created = k["CreateDate"]
            age = (now - created).days if created else None
            row = {"user": user["UserName"], "access_key_id": k["AccessKeyId"],
                   "status": k.get("Status"), "age_days": age,
                   "created": str(created)}
            keys.append(row)
            if age is not None and age > STALE_KEY_DAYS:
                stale.append(row)
    ev = ctx.record("cloud_credential_age", {"access_keys": keys,
                                             "threshold_days": STALE_KEY_DAYS},
                    f"credentials: {len(keys)} access keys, {len(stale)} older than "
                    f"{STALE_KEY_DAYS}d")
    return [_cand(
        f"Access key for '{r['user']}' is {r['age_days']} days old", "CWE-324", "medium",
        "high", f"aws:iam::{ctx.account_id}:user/{r['user']}/access-key/{r['access_key_id']}",
        f"Access key created {r['created']} exceeds the {STALE_KEY_DAYS}-day rotation window.",
        "Long-lived keys accumulate in scripts and CI; rotation never invalidates a leak.",
        "Rotate the key, shorten its lifetime, prefer role-based credentials.",
        ev, f"key age {r['age_days']}d: {r['access_key_id']}",
        f"cloud-key-age:{ctx.account_id}:{r['access_key_id']}") for r in stale]


CHECKS = (
    ("iam", _check_iam),
    ("s3", _check_s3),
    ("security_groups", _check_security_groups),
    ("logging", _check_logging),
    ("encryption", _check_encryption),
    ("root_mfa", _check_root),
    ("credential_age", _check_credential_age),
)


def _validate_inputs(endpoint_url: str, region: str, creds: dict) -> None:
    """Trust-boundary validation: boto3 would happily dial a metadata IP."""
    p = urlparse(endpoint_url if isinstance(endpoint_url, str) else "")
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("endpoint must be an http(s) URL")
    try:
        addr = ipaddress.ip_address(p.hostname)
    except ValueError:
        addr = None
    if addr is not None and any(addr in net for net in ALWAYS_BLOCKED):
        raise ValueError(f"refusing metadata/link-local endpoint {p.hostname}")
    if not isinstance(region, str) or not region.strip():
        raise ValueError("region required")
    if not isinstance(creds, dict) or not {"access_key_id", "secret_access_key"} <= set(creds):
        raise ValueError("creds must carry access_key_id and secret_access_key")


def assess_cloud(endpoint_url: str, region: str, creds: dict, db: DB,
                 evidence: EvidenceStore, pipeline: FindingPipeline, scope: Scope,
                 engagement_id: str, *, intent_id: str | None = None) -> dict:
    """Run the read-only posture checks; return a summary of what was found.

    Refuses (and audits) the run when the account/endpoint is out of scope.
    A single failing check degrades to an observation, never aborts the audit.
    """
    try:
        _validate_inputs(endpoint_url, region, creds)
    except ValueError as e:
        db.emit(engagement_id, "cloud_audit_failed",
                {"endpoint": endpoint_url if isinstance(endpoint_url, str) else None,
                 "region": region, "error": str(e)})
        return {"ok": False, "error": str(e), "checks": {}, "findings": []}
    clients = Clients(endpoint_url, region, creds)
    try:
        identity = clients.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as e:
        reason = f"cannot authenticate against {endpoint_url}: {e}"
        db.emit(engagement_id, "cloud_audit_failed", {"endpoint": endpoint_url,
                                                      "region": region, "error": reason})
        return {"ok": False, "error": reason, "checks": {}, "findings": []}
    account_id = identity["Account"]
    decision = scope.check_cloud(account_id, endpoint_url)
    if not decision.allowed:
        db.emit(engagement_id, "scope_refusal", {
            "url": endpoint_url, "account_id": account_id,
            "reason": decision.reason, "tool": "cloud_audit"})
        return {"ok": False, "refused": True, "reason": decision.reason,
                "account_id": account_id, "checks": {}, "findings": []}

    ctx = _Ctx(clients, pipeline, evidence, engagement_id, intent_id, account_id, region)
    results, findings, evidence_ids, errors = {}, [], [], {}
    for name, fn in CHECKS:
        try:
            cands = fn(ctx)
        except (ClientError, BotoCoreError) as e:
            errors[name] = str(e)
            db.emit(engagement_id, "cloud_check_error", {"check": name, "error": str(e)})
            continue
        results[name] = len(cands)
        for cand in cands:
            submitted = pipeline.submit_candidate(engagement_id, cand, intent_id)
            findings.append(submitted["id"])
            evidence_ids.extend(cand["evidence_ids"])
    db.emit(engagement_id, "cloud_audit", {
        "endpoint": endpoint_url, "region": region, "account_id": account_id,
        "results": results, "findings": len(findings), "errors": sorted(errors),
    })
    return {
        "ok": not errors, "account_id": account_id, "endpoint": endpoint_url,
        "region": region, "checks": results, "findings": findings,
        "evidence_ids": sorted(set(evidence_ids)), "errors": errors,
        "read_calls": sorted(set(clients.calls)),
    }
