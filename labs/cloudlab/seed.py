"""Seed a moto-backed AWS account with a vulnerable or hardened configuration.

Both twins carry the same resource inventory (IAM users/policies, an S3 bucket,
a security group, an EBS volume, an RDS instance, CloudTrail, root credentials)
so a posture scan compares like with like: vuln fails every check, hardened
passes every one. Everything here is fake and in-memory; nothing leaves the box.

`seed(mode, ...)` talks to the moto endpoint only through boto3 (write APIs),
which is why this lives in labs/ and not under src/libella.
"""
import datetime
import json
import time

import boto3

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
STALE_KEY_DAYS = 400


def _client(service: str, endpoint_url: str, region: str):
    return boto3.client(
        service, endpoint_url=endpoint_url, region_name=region,
        aws_access_key_id="cloudlab", aws_secret_access_key="cloudlab",
    )


def _policy(iam, name: str, document: dict) -> str:
    arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document))["Policy"]["Arn"]
    return arn


def _private_bucket(s3, bucket: str) -> None:
    """Block all public access + default SSE-S3 encryption (the hardened shape)."""
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    })


def _age_access_key(iam, user: str, days: int):
    """Backdate a key so the credential-age check has something to find.

    moto (like AWS) exposes no API to set CreateDate, so the lab mutates the
    backend object after creation. shortcoming: needs moto's private model;
    upgrade path is a real AWS account or a moto release that seeds key age.
    """
    from moto.iam.models import iam_backends

    key = iam.create_access_key(UserName=user)["AccessKey"]
    try:
        backend = iam_backends[ACCOUNT_ID]["aws"]
        obj = next(a for a in backend.users[user].access_keys
                   if a.access_key_id == key["AccessKeyId"])
        obj.create_date = datetime.datetime.now(datetime.timezone.utc) - \
            datetime.timedelta(days=days)
    except (KeyError, AttributeError, StopIteration) as e:
        raise RuntimeError(f"cannot backdate access key in this moto version: {e!r}") from e


def _enable_root_mfa():
    """moto reports root MFA via a backend flag it never sets through an API."""
    from moto.iam.models import iam_backends

    iam_backends[ACCOUNT_ID]["aws"].account_summary._account_mfa_enabled = 1


def seed(mode: str, endpoint_url: str, region: str = REGION) -> dict:
    if mode not in ("vuln", "hardened"):
        raise ValueError(f"mode must be vuln|hardened, got {mode!r}")
    vuln = mode == "vuln"
    tag = mode
    iam = _client("iam", endpoint_url, region)
    s3 = _client("s3", endpoint_url, region)
    ec2 = _client("ec2", endpoint_url, region)
    rds = _client("rds", endpoint_url, region)

    bucket = f"cloudlab-{tag}-data"

    # --- IAM: wildcard admin + privilege-escalation path, or a scoped policy ---
    if vuln:
        admin = _policy(iam, "cloudlab-admin-wildcard", {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        escalate = _policy(iam, "cloudlab-dev-passrole", {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "iam:AttachUserPolicy", "iam:CreatePolicyVersion"],
                "Resource": "*",
            }],
        })
        iam.create_user(UserName="lab-admin")
        iam.attach_user_policy(UserName="lab-admin", PolicyArn=admin)
        iam.create_user(UserName="lab-dev")
        iam.attach_user_policy(UserName="lab-dev", PolicyArn=escalate)
        _age_access_key(iam, "lab-dev", STALE_KEY_DAYS)
    else:
        scoped = _policy(iam, "cloudlab-scoped-read", {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        })
        iam.create_user(UserName="lab-admin")
        iam.attach_user_policy(UserName="lab-admin", PolicyArn=scoped)
        iam.create_user(UserName="lab-dev")
        iam.attach_user_policy(UserName="lab-dev", PolicyArn=scoped)
        _age_access_key(iam, "lab-dev", 30)
        _enable_root_mfa()

    # --- S3: public bucket (no block, public policy, no default encryption) ---
    s3.create_bucket(Bucket=bucket)
    if vuln:
        s3.put_bucket_policy(Bucket=bucket, Policy=(
            '{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow",'
            '"Principal":"*","Action":"s3:GetObject",'
            f'"Resource":"arn:aws:s3:::{bucket}/*"}}]}}'
        ))
    else:
        _private_bucket(s3, bucket)

    # --- EC2: world-open 22/3389 vs a private-range-only rule; EBS encryption ---
    vpc = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]
    if vuln:
        ec2.authorize_security_group_ingress(
            GroupName=ec2.create_security_group(
                GroupName="cloudlab-open", Description="lab open ingress",
                VpcId=vpc["VpcId"])["GroupId"],
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]} for p in (22, 3389)],
        )
    else:
        ec2.authorize_security_group_ingress(
            GroupName=ec2.create_security_group(
                GroupName="cloudlab-restricted", Description="lab private ingress",
                VpcId=vpc["VpcId"])["GroupId"],
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
        )
    ec2.create_volume(AvailabilityZone=f"{region}a", Size=8, Encrypted=not vuln)

    # --- RDS: storage encryption at rest ---
    rds.create_db_instance(
        DBInstanceIdentifier=f"cloudlab-{tag}-db", Engine="postgres",
        DBInstanceClass="db.t3.micro", AllocatedStorage=20, MasterUsername="labadmin",
        MasterUserPassword="SI_SECRET_PASSWORD_CLOUDLAB_Q4", StorageEncrypted=not vuln,
    )

    # --- Logging: trail + config recorder only on the hardened twin ---
    if not vuln:
        trail_bucket = f"cloudlab-{tag}-trail"
        s3.create_bucket(Bucket=trail_bucket)
        ct = _client("cloudtrail", endpoint_url, region)
        ct.create_trail(Name="cloudlab-trail", S3BucketName=trail_bucket)
        ct.start_logging(Name="cloudlab-trail")
        cfg = _client("config", endpoint_url, region)
        cfg.put_configuration_recorder(ConfigurationRecorder={
            "name": "default", "roleARN": f"arn:aws:iam::{ACCOUNT_ID}:role/cloudlab-config"})
        cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": trail_bucket})
        cfg.start_configuration_recorder(ConfigurationRecorderName="default")
        _private_bucket(s3, trail_bucket)

    return {
        "mode": mode, "endpoint": endpoint_url, "region": region, "account_id": ACCOUNT_ID,
        "bucket": bucket, "seeded_at": time.time(),
    }
