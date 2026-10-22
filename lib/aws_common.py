"""
Shared helpers for the tools in this repo: AWS sessions and clients, FMS
policy listing, region resolution, and a few small parsing helpers.

Intent: keep AWS access and run-time setup identical across the tools, so a
fix (retries, region handling, .env loading) applies everywhere, and no tool
has to import another tool.

Importing this module loads .env (python-dotenv) and sets up logging, so
every tool behaves the same. Tools must call truststore.inject_into_ssl()
before importing this module (it imports boto3; see fmm_nacl_audit.py).
"""
from __future__ import annotations

import logging
import os
from typing import Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("aws_common")

PROTO_NUM_TO_NAME = {"-1": "any", "all": "any", "ip": "any", "any": "any",
                     "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}


def _g(d: dict | None, key: str, default):
    """dict.get that also treats an explicit null as missing (FMS emits e.g. "securityGroups": null)."""
    if not d:
        return default
    v = d.get(key)
    return default if v is None else v


def normalize_proto(p: str | int | None) -> str:
    """Normalise a protocol given as name or number to 'tcp', 'udp', 'icmp', 'icmpv6', 'any' or the number."""
    if p is None:
        return "any"
    s = str(p).strip().lower()
    return PROTO_NUM_TO_NAME.get(s, s)


def get_session(profile: str | None, region: str) -> boto3.Session:
    """boto3 session for a profile (None = default credentials) and region."""
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session):
    """boto3 client with adaptive retries, so large scans ride out API throttling."""
    cfg = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    return session.client(service, config=cfg)


def list_policies(fms) -> Iterator[dict]:
    """Iterate the summaries of every Firewall Manager policy in the session's region."""
    paginator = fms.get_paginator("list_policies")
    for page in paginator.paginate():
        yield from _g(page, "PolicyList", [])


def get_policy(fms, policy_id: str) -> dict:
    """Fetch one Firewall Manager policy by id (the Policy object)."""
    return fms.get_policy(PolicyId=policy_id)["Policy"]


def resolve_regions(profile: str | None, region_args: list[str] | None, all_regions: bool,
                    service: str = "fms") -> list[str]:
    """Regions to scan.

    --region is repeatable and comma-separable (default AWS_REGION, else us-east-1).
    --all-regions enumerates the account's enabled regions that offer `service`:
    "fms" for Firewall Manager tools, "ec2" for tools that only read EC2/VPC resources.
    """
    if all_regions:
        session = get_session(profile, os.getenv("AWS_REGION", "us-east-1"))
        enabled = {r["RegionName"] for r in get_client("ec2", session).describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])["Regions"]}
        offered = set(session.get_available_regions(service))
        regions = sorted(enabled & offered)
        log.info("--all-regions: %d enabled regions offering %s: %s", len(regions), service, ", ".join(regions))
        return regions
    out: list[str] = []
    for item in region_args or []:
        for r in item.split(","):
            r = r.strip()
            if r and r not in out:
                out.append(r)
    if not out:
        out = [x.strip() for x in os.getenv("AWS_REGION", "us-east-1").split(",") if x.strip()]
    return out


def err_text(e: Exception) -> str:
    """Short error text for an AWS ClientError ("Code: Message") or any other exception."""
    if isinstance(e, ClientError):
        return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
    return f"{type(e).__name__}: {e}"
