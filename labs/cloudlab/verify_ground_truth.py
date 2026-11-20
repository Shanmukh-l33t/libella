"""Verify CloudLab ground truth: every seed present in vuln, fixed in hardened.

Usage: python labs/cloudlab/verify_ground_truth.py
Starts both twins itself (ephemeral ports), asserts with boto3 only, stops them.
Exit code 0 means the lab is a valid positive/negative fixture.
"""
import datetime
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).parent))
import labctl  # noqa: E402

TRUTH = json.loads(Path(__file__).with_name("ground_truth.json").read_text())
STALE_DAYS = 90


def _iam_policy(iam, name):
    arn = iam.get_policy(PolicyArn=f"arn:aws:iam::{TRUTH['account_id']}:policy/{name}")
    p = arn["Policy"]
    doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
    return doc["PolicyVersion"]["Document"]


def _flatten_actions(doc):
    sts = doc.get("Statement", [])
    sts = sts if isinstance(sts, list) else [sts]
    return [a for st in sts for a in
            (st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action")])]


def probes(c):
    """c: dict of boto3 clients. Returns {seed_id: bool present}."""
    iam, s3, ec2, rds = c["iam"], c["s3"], c["ec2"], c["rds"]
    out = {}
    try:
        doc = _iam_policy(iam, "cloudlab-admin-wildcard")
        out["CL-01"] = "*" in _flatten_actions(doc)
    except ClientError:
        out["CL-01"] = False
    try:
        acts = [str(a).lower() for a in _flatten_actions(_iam_policy(iam, "cloudlab-dev-passrole"))]
        out["CL-02"] = "iam:passrole" in acts and "iam:attachuserpolicy" in acts
    except ClientError:
        out["CL-02"] = False

    buckets = {b["Name"] for b in s3.list_buckets()["Buckets"]}
    data = next((b for b in buckets if b.endswith("-data")), None)
    public = pab_missing = unencrypted = False
    if data:
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=data)["Policy"])
            sts = policy.get("Statement", [])
            public = any(st.get("Principal") == "*" for st in (sts if isinstance(sts, list) else [sts]))
        except ClientError:
            public = False
        try:
            s3.get_public_access_block(Bucket=data)
            pab_missing = False
        except ClientError:
            pab_missing = True
        try:
            s3.get_bucket_encryption(Bucket=data)
            unencrypted = False
        except ClientError:
            unencrypted = True
    out["CL-03"], out["CL-04"], out["CL-05"] = public, pab_missing, unencrypted

    world = False
    for g in ec2.describe_security_groups()["SecurityGroups"]:
        for perm in g.get("IpPermissions", []):
            cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + \
                    [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
            if {"0.0.0.0/0", "::/0"} & set(cidrs):
                world = True
    out["CL-06"] = world

    trails = c["cloudtrail"].describe_trails(includeShadowTrails=False)["trailList"]
    out["CL-07"] = not trails or not any(
        c["cloudtrail"].get_trail_status(Name=t["Name"]).get("IsLogging") for t in trails)
    out["CL-08"] = not c["config"].describe_configuration_recorders()["ConfigurationRecorders"]
    out["CL-09"] = any(not v.get("Encrypted") for v in ec2.describe_volumes()["Volumes"])
    out["CL-10"] = any(not d.get("StorageEncrypted")
                       for d in rds.describe_db_instances()["DBInstances"])
    out["CL-11"] = iam.get_account_summary()["SummaryMap"]["AccountMFAEnabled"] != 1
    now = datetime.datetime.now(datetime.timezone.utc)
    out["CL-12"] = any((now - k["CreateDate"]).days > STALE_DAYS
                       for u in iam.list_users()["Users"]
                       for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"])
    return out


def clients_for(endpoint):
    kw = dict(endpoint_url=endpoint, region_name=TRUTH["region"],
              aws_access_key_id="cloudlab", aws_secret_access_key="cloudlab")
    return {svc: boto3.client(svc, **kw) for svc in
            ("iam", "s3", "ec2", "rds", "cloudtrail", "config")}


def main() -> int:
    got = {}
    for mode in ("vuln", "hardened"):
        endpoint, proc = labctl.start_lab(mode)
        try:
            got[mode] = probes(clients_for(endpoint))
        finally:
            labctl.stop_lab(proc)

    fails, rows = [], []
    for seed in TRUTH["seeds"]:
        sid = seed["id"]
        v, h = got["vuln"][sid], got["hardened"][sid]
        rows.append((sid, v, h, seed["title"]))
        if not v:
            fails.append(f"vuln: {sid} {seed['title']} NOT seeded")
        if h:
            fails.append(f"hardened: {sid} {seed['title']} still present (twin not fixed)")
    print(f"{'seed':6} {'vuln':>4} {'hard':>4}  title")
    for sid, v, h, title in rows:
        print(f"{sid:6} {int(v):>4} {int(h):>4}  {title}")
    if fails:
        print("FAILURES:")
        for f in fails:
            print(" -", f)
        return 1
    print(f"ALL GROUND-TRUTH CHECKS PASS: {len(rows)} seeds fire only in vuln mode; "
          "hardened twin is clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
