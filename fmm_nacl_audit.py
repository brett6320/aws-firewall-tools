#!/usr/bin/env python3
"""
AWS Firewall Manager (FMS) network ACL audit.

Intent: FMS NACL policies only control the first and last rules of each
NACL; teams add their own rules in between. This tool shows, across every
member account, which NACLs no longer carry the policy's rules in the right
order, which are close to the rules-per-NACL limit (FMS remediation needs
spare slots), and which hold duplicate or misplaced rules, so they can be
fixed before remediation fails or traffic is affected.

Companion to fmm_rule_parity.py. For each FMS NETWORK_ACL_COMMON policy, finds the
member accounts in scope (from FMS compliance status), reads the live network
ACLs in each account through a matching local AWS profile, and reports:

  * first / last rules that are missing, different, or out of position
    compared to the policy's NetworkAclEntrySet
  * network ACLs whose rule count per direction is at the limit (default 30)
    or within headroom of it (default 3)
  * duplicate rules (identical entry at more than one rule number)
  * in-scope network ACLs not tagged FMManaged=true
  * VPC default network ACLs holding anything besides the '*' deny-all rules
    (default NACLs are never checked against the policy)

The expected rules (SecurityServicePolicyData.PolicyOption.NetworkAclCommonPolicy
.NetworkAclEntrySet) come from a policy file when one is given (get-policy JSON,
the Policy object, or a bare NetworkAclEntrySet); otherwise from the live policy.
--compare-live diffs a policy file against the live policy and checks NACLs
against both.

Member account profiles are found in the local AWS config by account id;
profiles ending in -priv or -cpar are never used.

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports
    # Firewall Manager administrator (security) account id. Its local profile is
    # found by account id; --profile overrides, AWS_PROFILE is the fallback.
    FMM_ADMIN_ACCOUNT=
    # NACL rules-per-direction limit
    FMM_NACL_LIMIT=30
    # Flag NACLs within this many rules of the limit
    FMM_NACL_HEADROOM=3

Reports: text on screen, plus auto-saved HTML (interactive: filter, sort,
unique counts of accounts/VPCs/NACLs...), CSV and JSON under
reports/fmm_nacl_audit/YYYY-MM-DD/.

Usage:

    ./fmm_nacl_audit.py --region us-east-1
    ./fmm_nacl_audit.py --policy-file prod-nacl.json --compare-live

Exit codes: 0 clean, 1 error or warning findings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

import truststore

# Must run before boto3/urllib3 import: they capture ssl.SSLContext at import time,
# and a context built from the pre-injection class recurses forever in its options setter.
truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import DEFAULT_EXCLUDE_SUFFIXES, pick_profile, profile_lookup, resolve_admin_profile  # noqa: E402
from lib.aws_common import err_text, _g, get_client, get_policy, get_session, list_policies, normalize_proto, resolve_regions

log = logging.getLogger("fmm_nacl_audit")

NACL_POLICY_TYPE = "NETWORK_ACL_COMMON"
DEFAULT_RULE_MIN = 32767          # 32767 (IPv4 '*') and 32768 (IPv6 '*') are the immutable defaults
LAST_RULE_MAX = 32766
CUSTOM_RANGE = (5000, 32000)      # FMS guidance: custom rules live between these numbers
DEFAULT_LIMIT = 30                # our raised rules-per-NACL quota, per direction (AWS default is 20)
DEFAULT_HEADROOM = 3              # flag NACLs within this many rules of the limit

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Entry:
    """One NACL entry, normalised so policy entries and live entries compare equal."""
    egress: bool
    action: str
    proto: str
    cidr: str
    ports: tuple[int, int] | None = None
    icmp: tuple[int, int] | None = None   # (type, code)
    number: int | None = None             # live rule number; None for policy entries

    FIELDS = ("action", "proto", "cidr", "ports", "icmp")

    @classmethod
    def from_policy(cls, e: dict) -> "Entry":
        """FMS NetworkAclEntry: same shape as an EC2 entry, minus RuleNumber."""
        return cls.from_live({**e, "RuleNumber": None})

    @classmethod
    def from_live(cls, e: dict) -> "Entry":
        """Parse an entry as returned by EC2 or FMS (PascalCase); RuleNumber is kept when present."""
        proto = normalize_proto(e.get("Protocol", "-1"))
        pr = e.get("PortRange")
        ic = e.get("IcmpTypeCode")
        return cls(
            egress=bool(e.get("Egress", False)),
            action=str(e.get("RuleAction", "")).lower(),
            proto=proto,
            cidr=_norm_cidr(e.get("CidrBlock") or e.get("Ipv6CidrBlock") or ""),
            ports=(int(pr["From"]), int(pr["To"])) if pr and proto in ("tcp", "udp") else None,
            icmp=(int(ic.get("Type", -1)), int(ic.get("Code", -1))) if ic and proto in ("icmp", "icmpv6") else None,
            number=None if e.get("RuleNumber") is None else int(e["RuleNumber"]),
        )

    def key(self) -> tuple:
        """Identity of an entry for comparison: direction plus every compared field, not the rule number."""
        return (self.egress,) + tuple(getattr(self, f) for f in self.FIELDS)

    def diff(self, other: "Entry") -> list[str]:
        """Field-level differences, expected (self) vs actual (other)."""
        out = []
        for f in self.FIELDS:
            a, b = getattr(self, f), getattr(other, f)
            if a != b:
                out.append(f"{f}: expected {_fmt_val(f, a)}, got {_fmt_val(f, b)}")
        return out

    def __str__(self) -> str:
        """Human-readable entry, e.g. '#100 ingress allow tcp 443 10.0.0.0/8'."""
        num = f"#{self.number} " if self.number is not None else ""
        extra = ""
        if self.ports:
            extra = f" {_fmt_val('ports', self.ports)}"
        elif self.icmp:
            extra = f" {_fmt_val('icmp', self.icmp)}"
        return f"{num}{'egress' if self.egress else 'ingress'} {self.action} {self.proto}{extra} {self.cidr or 'any'}"


@dataclass
class Baseline:
    """Expected first/last entries for one policy, from a file or the live policy."""
    source: str                    # 'file' or 'live'
    policy_id: str
    policy_name: str
    first: list[Entry]
    last: list[Entry]
    force_first: bool | None = None
    force_last: bool | None = None

    def block(self, which: str, egress: bool) -> list[Entry]:
        """The policy's first or last entries for one direction, in policy order."""
        return [e for e in (self.first if which == "first" else self.last) if e.egress == egress]


@dataclass
class Finding:
    """One audit result for a NACL, account or policy, as shown in the text, CSV and HTML reports."""
    severity: str                  # error | warn | info
    code: str
    region: str
    policy_name: str
    policy_id: str
    baseline: str                  # file | live | '' for non-rule findings
    account: str = ""
    profile: str = ""
    vpc_id: str = ""
    nacl_id: str = ""
    subnets: list[str] = field(default_factory=list)
    direction: str = ""
    position: str = ""             # e.g. first[2], last[1]
    expected: str = ""
    actual: str = ""
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _norm_cidr(s: str) -> str:
    """Canonical CIDR text (so '10.0.0.1/8' equals '10.0.0.0/8'); unparseable input is kept as is."""
    if not s:
        return ""
    try:
        return str(ipaddress.ip_network(s.strip(), strict=False))
    except ValueError:
        return s.strip()


def _fmt_val(f: str, v) -> str:
    """Render one compared Entry field for diff messages."""
    if v is None:
        return "-"
    if f == "ports":
        return str(v[0]) if v[0] == v[1] else f"{v[0]}-{v[1]}"
    if f == "icmp":
        return f"type={v[0]},code={v[1]}"
    return str(v) or "-"


# --------------------------------------------------------------------------- #
# Policy loading
# --------------------------------------------------------------------------- #
def _entry_set_from(obj: dict) -> dict | None:
    """NetworkAclEntrySet from a Policy object
    (SecurityServicePolicyData.PolicyOption.NetworkAclCommonPolicy.NetworkAclEntrySet),
    or a bare NetworkAclEntrySet."""
    if "FirstEntries" in obj or "LastEntries" in obj:
        return obj
    ssp = _g(obj, "SecurityServicePolicyData", None)
    if ssp is None:
        return None
    ptype = ssp.get("Type")
    if ptype and ptype != NACL_POLICY_TYPE:
        raise ValueError(f"policy type is {ptype}, not {NACL_POLICY_TYPE}")
    return _g(_g(_g(ssp, "PolicyOption", {}), "NetworkAclCommonPolicy", {}), "NetworkAclEntrySet", None)


def baseline_from_policy(policy: dict, source: str) -> Baseline:
    """Build the expected first/last rules from a policy (file or live).

    Fails closed: a policy with no entry set, or with neither first nor last entries, raises
    ValueError rather than silently checking against nothing.
    """
    es = _entry_set_from(policy)
    if es is None:
        raise ValueError(f"{source} policy: no SecurityServicePolicyData.PolicyOption."
                         "NetworkAclCommonPolicy.NetworkAclEntrySet found")
    bl = Baseline(
        source=source,
        policy_id=policy.get("PolicyId", ""),
        policy_name=policy.get("PolicyName", ""),
        first=[Entry.from_policy(e) for e in _g(es, "FirstEntries", [])],
        last=[Entry.from_policy(e) for e in _g(es, "LastEntries", [])],
        force_first=es.get("ForceRemediateForFirstEntries"),
        force_last=es.get("ForceRemediateForLastEntries"),
    )
    if not bl.first and not bl.last:
        # Fail closed: with no expected rules every NACL would look compliant.
        raise ValueError(f"{source} policy {bl.policy_name or bl.policy_id}: no first or last entries found")
    return bl


def load_policy_file(path: str) -> tuple[dict, str | None]:
    """Return (policy-ish dict, region from PolicyArn if present).
    Accepts `aws fms get-policy` output, the bare Policy object, or a bare NetworkAclEntrySet."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    region = None
    arn = doc.get("PolicyArn") or ""
    m = re.match(r"arn:aws[\w-]*:fms:([a-z0-9-]+):", arn)
    if m:
        region = m.group(1)
    return (doc["Policy"] if "Policy" in doc else doc), region


# --------------------------------------------------------------------------- #
# FMS scope
# --------------------------------------------------------------------------- #
def policy_accounts(fms, policy_id: str) -> dict[str, str]:
    """{account_id: FMS compliance status} for every member account the policy covers."""
    out: dict[str, str] = {}
    for page in fms.get_paginator("list_compliance_status").paginate(PolicyId=policy_id):
        for s in _g(page, "PolicyComplianceStatusList", []):
            statuses = {r.get("ComplianceStatus") for r in _g(s, "EvaluationResults", [])}
            status = "NON_COMPLIANT" if "NON_COMPLIANT" in statuses else (statuses.pop() if statuses else "UNKNOWN")
            out[s["MemberAccount"]] = status
    return out


def subnet_in_scope(tags: dict[str, str], policy: dict) -> bool:
    """Apply the policy's ResourceTags / ExcludeResourceTags / ResourceTagLogicalOperator."""
    want = _g(policy, "ResourceTags", [])
    if not want:
        return True
    hits = [t["Key"] in tags and (not t.get("Value") or tags[t["Key"]] == t["Value"]) for t in want]
    matched = any(hits) if str(policy.get("ResourceTagLogicalOperator", "AND")).upper() == "OR" else all(hits)
    return not matched if policy.get("ExcludeResourceTags") else matched


# --------------------------------------------------------------------------- #
# Live NACL analysis
# --------------------------------------------------------------------------- #
def _paginate(client, op: str, key: str, **kw) -> Iterator[dict]:
    """Iterate every item under `key` across all pages of a paginated EC2 call."""
    for page in client.get_paginator(op).paginate(**kw):
        yield from _g(page, key, [])


def check_block(which: str, expected: list[Entry], live: list[Entry], mk) -> list[Finding]:
    """Positional compare of one first/last block against the live entries of one direction."""
    out: list[Finding] = []
    n = len(expected)
    if not n:
        return out
    if which == "first":
        window: list[Entry | None] = live[:n] + [None] * max(0, n - len(live))
        ideal = list(range(1, n + 1))
    else:
        tail = live[-n:]
        window = [None] * (n - len(tail)) + tail
        ideal = list(range(LAST_RULE_MAX - n + 1, LAST_RULE_MAX + 1))
    for i, (exp, got) in enumerate(zip(expected, window)):
        pos = f"{which}[{i + 1}]"
        if got is not None and got.key() == exp.key():
            if got.number != ideal[i]:
                out.append(mk("info", f"{which.upper()}_RENUMBERED", pos, exp, got,
                              f"matches, but rule #{got.number} (FMS initial numbering #{ideal[i]})"))
            continue
        elsewhere = [e.number for e in live if e.key() == exp.key()]
        where = f"; same rule found at #{','.join(map(str, elsewhere))}" if elsewhere else ""
        if got is None:
            out.append(mk("error", f"{which.upper()}_MISSING", pos, exp, None,
                          f"NACL has too few entries for the {which} block{where}"))
        elif elsewhere:
            out.append(mk("error", f"{which.upper()}_OUT_OF_ORDER", pos, exp, got,
                          f"expected rule not in position{where}"))
        else:
            out.append(mk("error", f"{which.upper()}_MISMATCH", pos, exp, got, "; ".join(exp.diff(got))))
    return out


def analyze_nacl(nacl: dict, baselines: list[Baseline], ctx: dict, limit: int, headroom: int) -> list[Finding]:
    """Check one in-scope (non-default) NACL: FMManaged tag, rule-count limit, duplicate
    rules, the policy's first/last blocks for each baseline, and custom rules outside the
    5000-32000 range.
    """
    live_all = [Entry.from_live(e) for e in _g(nacl, "Entries", [])
                if int(e["RuleNumber"]) < DEFAULT_RULE_MIN]
    subnets = sorted(a["SubnetId"] for a in _g(nacl, "Associations", []))
    tags = {t["Key"]: t.get("Value", "") for t in _g(nacl, "Tags", [])}
    base = dict(**ctx, vpc_id=nacl.get("VpcId", ""), nacl_id=nacl["NetworkAclId"], subnets=subnets)
    out: list[Finding] = []

    if str(tags.get("FMManaged", "")).lower() != "true":
        out.append(Finding(severity="warn", code="NOT_FMMANAGED", baseline="", **base,
                           detail="in-scope subnet's NACL lacks FMManaged=true; FMS has not taken it over"))

    for egress in (False, True):
        direction = "egress" if egress else "ingress"
        live = sorted((e for e in live_all if e.egress == egress), key=lambda e: e.number)
        count = len(live)
        if count >= limit - headroom:
            out.append(Finding(severity="warn", code="AT_LIMIT" if count >= limit else "NEAR_LIMIT",
                               baseline="", **base, direction=direction,
                               actual=str(count), expected=f"< {limit - headroom}",
                               detail=f"{count} {direction} rules, limit {limit}"
                                      + (f", headroom {headroom}" if headroom else "")))

        # Exact duplicates: same action/proto/cidr/ports/icmp at more than one rule number.
        groups: dict[tuple, list[Entry]] = {}
        for e in live:
            groups.setdefault(e.key(), []).append(e)
        for dups in groups.values():
            if len(dups) > 1:
                out.append(Finding(severity="warn", code="DUPLICATE_RULE", baseline="", **base,
                                   direction=direction,
                                   actual=f"{Entry(**{**asdict(dups[0]), 'number': None})} at "
                                          + ", ".join(f"#{e.number}" for e in dups),
                                   detail=f"same rule at {len(dups)} rule numbers; only #{dups[0].number} "
                                          f"is ever evaluated, {len(dups) - 1} slot(s) wasted"))

        for bl in baselines:
            def mk(sev, code, pos, exp, got, detail, _bl=bl, _dir=direction):
                """Build a Finding for this NACL, baseline and direction."""
                return Finding(severity=sev, code=code, baseline=_bl.source, **base, direction=_dir,
                               position=pos, expected=str(exp) if exp else "",
                               actual=str(got) if got else "", detail=detail)
            first, last = bl.block("first", egress), bl.block("last", egress)
            out += check_block("first", first, live, mk)
            out += check_block("last", last, live, mk)

        # Custom rules numbered outside the custom range. Any entry matching a policy
        # first/last rule (any baseline, any position) is a policy rule, not custom;
        # misplaced policy rules are already reported by check_block.
        policy_keys = {e.key() for bl in baselines
                       for e in bl.block("first", egress) + bl.block("last", egress)}
        for e in live:
            if e.key() in policy_keys or CUSTOM_RANGE[0] <= e.number <= CUSTOM_RANGE[1]:
                continue
            out.append(Finding(severity="info", code="CUSTOM_OUTSIDE_RANGE", baseline="", **base,
                               direction=direction, actual=str(e),
                               detail=f"rule matches no policy first/last rule and is outside the "
                                      f"custom range {CUSTOM_RANGE[0]}-{CUSTOM_RANGE[1]}"))
    return out


def check_default_nacl(nacl: dict, ctx: dict) -> list[Finding]:
    """A VPC default NACL is outside the policy; it must hold nothing but the '*' deny-all rules."""
    subnets = sorted(a["SubnetId"] for a in _g(nacl, "Associations", []))
    base = dict(**ctx, vpc_id=nacl.get("VpcId", ""), nacl_id=nacl["NetworkAclId"], subnets=subnets)
    extra = sorted((Entry.from_live(e) for e in _g(nacl, "Entries", [])
                    if not (int(e["RuleNumber"]) >= DEFAULT_RULE_MIN
                            and str(e.get("RuleAction")).lower() == "deny")),
                   key=lambda e: (e.egress, e.number))
    out: list[Finding] = []
    for egress in (False, True):
        rules = [e for e in extra if e.egress == egress]
        if rules:
            out.append(Finding(severity="error", code="DEFAULT_NACL_NOT_DENY_ALL", baseline="", **base,
                               direction="egress" if egress else "ingress", expected="deny-all only",
                               actual=" | ".join(map(str, rules)),
                               detail=f"VPC default NACL has {len(rules)} rule(s) besides '*' deny all"))
    return out


def scan_account(account: str, profile: str, region: str, policy: dict, baselines: list[Baseline],
                 nacl_scope: str, limit: int, headroom: int, ctx: dict) -> tuple[list[Finding], int]:
    """Return (findings, NACLs checked)."""
    session = boto3.Session(profile_name=profile, region_name=region)
    actual = get_client("sts", session).get_caller_identity()["Account"]
    if actual != account:
        return [Finding(severity="error", code="PROFILE_ACCOUNT_MISMATCH", baseline="", **ctx,
                        detail=f"profile {profile} resolves to {actual}, expected {account}")], 0
    ec2 = get_client("ec2", session)
    all_nacls = list(_paginate(ec2, "describe_network_acls", "NetworkAcls"))
    defaults = [n for n in all_nacls if n.get("IsDefault")]
    nacls = [n for n in all_nacls if not n.get("IsDefault")]   # default NACLs are never policy-checked
    if nacl_scope == "fmmanaged":
        selected = [n for n in nacls
                    if any(t["Key"] == "FMManaged" and str(t.get("Value")).lower() == "true"
                           for t in _g(n, "Tags", []))]
    elif nacl_scope == "all":
        selected = nacls
    else:   # subnets: NACLs associated with subnets the policy's tag scope covers
        in_scope = {s["SubnetId"] for s in _paginate(ec2, "describe_subnets", "Subnets")
                    if subnet_in_scope({t["Key"]: t.get("Value", "") for t in _g(s, "Tags", [])}, policy)}
        selected = [n for n in nacls if any(a["SubnetId"] in in_scope for a in _g(n, "Associations", []))]
    log.info("  %s (%s) %s: %d NACLs in scope of %d non-default; %d default", account, profile, region,
             len(selected), len(nacls), len(defaults))
    findings: list[Finding] = []
    for n in defaults:
        findings += check_default_nacl(n, ctx)
    for n in selected:
        findings += analyze_nacl(n, baselines, ctx, limit, headroom)
    return findings, len(selected)


# --------------------------------------------------------------------------- #
# Policy file vs live policy
# --------------------------------------------------------------------------- #
def diff_baselines(file_bl: Baseline, live_bl: Baseline, ctx: dict) -> list[Finding]:
    """Compare a policy file's rules with the live policy's, position by position (--compare-live)."""
    out: list[Finding] = []
    for which in ("first", "last"):
        for egress in (False, True):
            direction = "egress" if egress else "ingress"
            a, b = file_bl.block(which, egress), live_bl.block(which, egress)
            for i in range(max(len(a), len(b))):
                ea = a[i] if i < len(a) else None
                eb = b[i] if i < len(b) else None
                if ea and eb and ea.key() == eb.key():
                    continue
                detail = ("; ".join(ea.diff(eb)) if ea and eb
                          else "only in policy file" if ea else "only in live policy")
                out.append(Finding(severity="warn", code="POLICY_DRIFT", baseline="file-vs-live", **ctx,
                                   direction=direction, position=f"{which}[{i + 1}]",
                                   expected=str(ea) if ea else "", actual=str(eb) if eb else "",
                                   detail=detail))
    for attr in ("force_first", "force_last"):
        if getattr(file_bl, attr) != getattr(live_bl, attr):
            out.append(Finding(severity="info", code="POLICY_DRIFT", baseline="file-vs-live", **ctx,
                               position=attr, expected=str(getattr(file_bl, attr)),
                               actual=str(getattr(live_bl, attr)),
                               detail=f"forceRemediateFor{attr.split('_')[1].title()}Entries differs"))
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
@dataclass
class Job:
    """One policy to audit in one region, with the baseline(s) to check its NACLs against."""
    region: str
    policy: dict          # live policy, or the file's Policy object (scope/tags)
    baselines: list[Baseline]


def resolve_policy_id(fms, ref: str) -> dict | None:
    """Find a policy by id or name in this region and return the full policy, or None."""
    for s in list_policies(fms):
        if ref in (s["PolicyId"], s["PolicyName"]):
            return get_policy(fms, s["PolicyId"])
    return None


def build_jobs(args, regions: list[str], findings: list[Finding]) -> list[Job]:
    """Work out which policies to audit, in which region, against which baselines.

    A policy file's ARN sets its region; otherwise the policy is searched for in every given
    region. Ambiguous or missing policies raise ValueError (fatal) rather than passing quietly.
    """
    jobs: list[Job] = []
    if args.policy_file:
        file_policy, file_region = load_policy_file(args.policy_file)
        file_bl = baseline_from_policy(file_policy, "file")
        ref = args.policy or file_bl.policy_id or file_bl.policy_name
        if not ref:
            raise ValueError("policy file has no PolicyId/PolicyName; pass --policy to find its accounts in FMS")
        if file_region:
            if args.region and file_region not in regions:
                log.warning("Policy file PolicyArn is in %s; ignoring --region %s", file_region, ",".join(regions))
            search = [file_region]
        else:
            search = regions
        found = []
        for r in search:
            pol = resolve_policy_id(get_client("fms", get_session(args.profile, r)), ref)
            if pol is not None:
                found.append((r, pol))
        if not found:
            raise ValueError(f"policy {ref!r} not found in FMS region(s) {', '.join(search)}")
        if len(found) > 1:
            raise ValueError(f"policy {ref!r} found in several regions ({', '.join(r for r, _ in found)}); "
                             "pass a single --region")
        region, live = found[0]
        file_bl.policy_id = file_bl.policy_id or live["PolicyId"]
        file_bl.policy_name = file_bl.policy_name or live["PolicyName"]
        baselines = [file_bl]
        scope_policy = file_policy if "ResourceTags" in file_policy else live
        if args.compare_live:
            live_bl = baseline_from_policy(live, "live")
            ctx = dict(region=region, policy_name=live["PolicyName"], policy_id=live["PolicyId"])
            findings += diff_baselines(file_bl, live_bl, ctx)
            baselines.append(live_bl)
        jobs.append(Job(region=region, policy={**scope_policy, "PolicyId": live["PolicyId"],
                                               "PolicyName": live["PolicyName"]}, baselines=baselines))
        return jobs

    for region in regions:
        fms = get_client("fms", get_session(args.profile, region))
        try:
            summaries = list(list_policies(fms))
        except ClientError as e:
            findings.append(Finding(severity="error", code="FMS_ERROR", region=region, policy_name="",
                                    policy_id="", baseline="", detail=f"list_policies: {err_text(e)}"))
            continue
        for s in summaries:
            if s.get("SecurityServiceType") != NACL_POLICY_TYPE:
                continue
            if args.policy and args.policy not in (s["PolicyId"], s["PolicyName"]):
                continue
            pol = get_policy(fms, s["PolicyId"])
            jobs.append(Job(region=region, policy=pol, baselines=[baseline_from_policy(pol, "live")]))
    if args.policy and not jobs and not any(f.code == "FMS_ERROR" for f in findings):
        raise ValueError(f"NACL policy {args.policy!r} not found in FMS region(s) {', '.join(regions)}; "
                         "try --region or --all-regions")
    return jobs


def run(args, regions: list[str]) -> tuple[list[Finding], dict]:
    """Audit every job: list in-scope accounts from FMS, pick each account's local profile,
    scan its NACLs, and return all findings (sorted for reporting) with run statistics.
    """
    findings: list[Finding] = []
    jobs = build_jobs(args, regions, findings)
    pmap, overrides = profile_lookup(args)
    stats = {"policies": len(jobs), "accounts": 0, "accounts_skipped": 0, "nacls": 0}

    for job in jobs:
        pid, pname = job.policy["PolicyId"], job.policy["PolicyName"]
        log.info("Region %s policy %s: %d first / %d last entries (%s)", job.region, pname,
                 len(job.baselines[0].first), len(job.baselines[0].last),
                 "+".join(b.source for b in job.baselines))
        fms = get_client("fms", get_session(args.profile, job.region))
        try:
            accounts = policy_accounts(fms, pid)
        except ClientError as e:
            findings.append(Finding(severity="error", code="FMS_ERROR", region=job.region, policy_name=pname,
                                    policy_id=pid, baseline="", detail=f"list_compliance_status: {err_text(e)}"))
            continue
        if args.account:
            wanted = {a for item in args.account for a in item.split(",") if a}
            accounts = {a: s for a, s in accounts.items() if a in wanted}
        for account, fms_status in sorted(accounts.items()):
            profile, note = pick_profile(account, pmap, overrides)
            ctx = dict(region=job.region, policy_name=pname, policy_id=pid, account=account, profile=profile or "")
            if note and profile:
                log.warning("Account %s: %s", account, note)
            if not profile:
                stats["accounts_skipped"] += 1
                findings.append(Finding(severity="error", code="NO_PROFILE", baseline="", **ctx,
                                        detail=f"no local AWS profile for account (FMS status {fms_status})"))
                continue
            try:
                f, n = scan_account(account, profile, job.region, job.policy, job.baselines,
                                    args.nacl_scope, args.limit, args.headroom, ctx)
            except (ClientError, BotoCoreError) as e:
                stats["accounts_skipped"] += 1
                findings.append(Finding(severity="error", code="ACCOUNT_ERROR", baseline="", **ctx,
                                        detail=err_text(e)))
                continue
            stats["accounts"] += 1
            stats["nacls"] += n
            findings += f

    findings.sort(key=lambda f: (f.region, f.policy_name, f.account, f.nacl_id,
                                 SEVERITY_ORDER[f.severity], f.baseline, f.direction, f.position))
    stats["by_code"] = {}
    for f in findings:
        stats["by_code"][f.code] = stats["by_code"].get(f.code, 0) + 1
    return findings, stats


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(findings: list[Finding], stats: dict, show_info: bool) -> None:
    """Print the text report: run totals, then findings grouped by region / policy / account /
    NACL. Info findings are hidden unless `show_info`.
    """
    print()
    print(f"Policies: {stats['policies']}   Accounts scanned: {stats['accounts']}   "
          f"skipped: {stats['accounts_skipped']}   NACLs checked: {stats['nacls']}")
    if stats["by_code"]:
        print("Findings: " + "   ".join(f"{k}: {v}" for k, v in sorted(stats["by_code"].items())))
    shown = [f for f in findings if show_info or f.severity != "info"]
    if not shown:
        print("\nNo drift: every in-scope NACL carries the policy's first/last rules in order and is under the limit.")
        return
    cur = None
    for f in shown:
        hdr = (f.region, f.policy_name, f.account, f.nacl_id)
        if hdr != cur:
            cur = hdr
            where = f"  account={f.account} ({f.profile})" if f.account else ""
            nacl = f"\n    nacl={f.nacl_id} vpc={f.vpc_id} subnets={','.join(f.subnets) or '-'}" if f.nacl_id else ""
            print(f"\n{f.region}  policy={f.policy_name}{where}{nacl}")
        tag = f"[{f.severity.upper():<5}] {f.code}"
        loc = " ".join(x for x in (f.baseline and f"({f.baseline})", f.direction, f.position) if x)
        print(f"      {tag} {loc}")
        if f.expected:
            print(f"          expected: {f.expected}")
        if f.actual:
            print(f"          actual:   {f.actual}")
        if f.detail:
            print(f"          {f.detail}")
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"\n({hidden} info findings hidden; --show-info to list)")


def render_html(findings: list[Finding], stats: dict, policy: str = "") -> str:
    """Build the interactive HTML report: run totals and a filterable, sortable findings table
    with unique counts of accounts, VPCs, NACLs and subnets.
    """
    sev = [f.severity for f in findings]
    cards = [(stats.get("policies", "-"), "policies"), (stats.get("accounts", "-"), "accounts scanned"),
             (stats.get("accounts_skipped", "-"), "accounts skipped"), (stats.get("nacls", "-"), "NACLs checked")]
    cards += [(sev.count(s), f"{s} findings") for s in ("error", "warn", "info")]
    meta = [f"Generated {dt.datetime.now():%Y-%m-%d %H:%M:%S}" + (f" · policy {policy}" if policy else "")]
    table = {
        "id": "findings", "title": "Findings", "row_label": "findings",
        "columns": [["severity", "Severity"], ["code", "Code"], ["region", "Region"], ["policy_name", "Policy"],
                    ["account", "Account"], ["profile", "Profile"], ["vpc_id", "VPC"], ["nacl_id", "NACL"],
                    ["subnets", "Subnets"], ["baseline", "Baseline"], ["direction", "Direction"],
                    ["position", "Position"], ["expected", "Expected"], ["actual", "Actual"], ["detail", "Detail"]],
        "rows": [asdict(f) for f in findings],
        "filters": ["severity", "code", "region", "policy_name", "account", "vpc_id", "nacl_id", "direction",
                    "baseline"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["policy_name", "Policies"], ["vpc_id", "VPCs"],
                 ["nacl_id", "NACLs"], ["subnets", "Subnets"], ["code", "Finding codes"]],
        "wrap": ["subnets", "expected", "actual", "detail"],
        "badges": {"severity": {"error": "error", "warn": "warn", "info": "info"}},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["severity", 1]],
        "hide": {"key": "severity", "values": ["info"], "label": "show info"},
        "by": {"key": "code", "label": "By code", "badge": "severity"},
    }
    return html_report.render("NACL audit report", meta=meta, cards=cards, tables=[table])


def write_outputs(findings: list[Finding], stats: dict, json_path, csv_path, html_path=None, policy: str = "") -> None:
    """Write the JSON, CSV and HTML reports to whichever paths are set."""
    for path in (json_path, csv_path, html_path):
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({"stats": stats, "findings": [asdict(f) for f in findings]}, fh, indent=2)
        log.info("Wrote JSON to %s", json_path)
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            w.writeheader()
            for f in findings:
                w.writerow({**asdict(f), "subnets": ";".join(f.subnets)})
        log.info("Wrote %d rows to %s", len(findings), csv_path)
    if html_path:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(findings, stats, policy))
        log.info("Wrote HTML to %s", html_path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 clean, 1 error/warn findings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Compare live network ACLs in FMS member accounts against a Firewall Manager NACL policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile fms-admin --region us-east-1
  %(prog)s --profile fms-admin --policy-file prod-nacl.json --compare-live
""")
    p.add_argument("--admin-account", default=os.getenv("FMM_ADMIN_ACCOUNT") or None, metavar="ACCOUNT_ID",
                   help="FMS administrator (security) account; its local profile is found like member "
                        "accounts' (env FMM_ADMIN_ACCOUNT)")
    p.add_argument("--profile", help="FMS administrator AWS profile; overrides --admin-account "
                                     "(default: profile for --admin-account, else AWS_PROFILE)")
    p.add_argument("--region", action="append",
                   help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true", help="Every enabled region that offers Firewall Manager")
    p.add_argument("--policy", help="Restrict to one NACL policy ID or name (also locates a policy file's policy)")
    p.add_argument("--policy-file", metavar="PATH",
                   help="Use this policy JSON as the expected rules (get-policy output, Policy object, "
                        "or bare NetworkAclEntrySet). Accounts still come from FMS")
    p.add_argument("--compare-live", action="store_true",
                   help="With --policy-file: also diff the file against the live FMS policy and check NACLs "
                        "against both")
    p.add_argument("--account", action="append", help="Restrict to account id(s); repeatable/comma-separated")
    p.add_argument("--account-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Force the local profile used for an account (repeatable)")
    p.add_argument("--exclude-profile-suffix", default=DEFAULT_EXCLUDE_SUFFIXES,
                   help=f"Comma-separated profile name suffixes never used (default {DEFAULT_EXCLUDE_SUFFIXES})")
    p.add_argument("--nacl-scope", choices=["subnets", "fmmanaged", "all"], default="subnets",
                   help="Which NACLs to check: those on subnets in the policy's tag scope (default), "
                        "those tagged FMManaged=true, or every NACL")
    p.add_argument("--limit", type=int, default=int(os.getenv("FMM_NACL_LIMIT", DEFAULT_LIMIT)),
                   help=f"Rules-per-direction limit (default {DEFAULT_LIMIT}, env FMM_NACL_LIMIT)")
    p.add_argument("--headroom", type=int, default=int(os.getenv("FMM_NACL_HEADROOM", DEFAULT_HEADROOM)),
                   help=f"Also flag NACLs within this many rules of --limit "
                        f"(default {DEFAULT_HEADROOM}, env FMM_NACL_HEADROOM)")
    p.add_argument("--show-info", action="store_true", help="Show info findings (renumbered, custom-range)")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout instead of text report")
    p.add_argument("--json-out", metavar="PATH", help="Write JSON report (overrides auto path)")
    p.add_argument("--csv-out", metavar="PATH", help="Write CSV report (overrides auto path)")
    p.add_argument("--html-out", metavar="PATH", help="Write HTML report (overrides auto path)")
    p.add_argument("--out-dir", default=os.getenv("FMM_REPORT_DIR", "./reports"),
                   help="Base directory for auto-saved reports (default ./reports, env FMM_REPORT_DIR)")
    p.add_argument("--no-save", action="store_true", help="Do not auto-save reports")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    if args.compare_live and not args.policy_file:
        p.error("--compare-live needs --policy-file")
    for x in args.account_profile or []:
        if "=" not in x:
            p.error(f"--account-profile expects ACCOUNT=PROFILE, got {x!r}")

    try:
        args.profile = resolve_admin_profile(args)
        regions = resolve_regions(args.profile, args.region, args.all_regions)
        findings, stats = run(args, regions)
    except (ValueError, json.JSONDecodeError, OSError) as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2

    paths = {}
    if not args.no_save:
        now = dt.datetime.now()
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", args.policy or Path(args.policy_file or "all").stem)[:48]
        stem = Path(args.out_dir) / "fmm_nacl_audit" / now.strftime("%Y-%m-%d") / f"{now.strftime('%H%M%S')}_nacl_{slug}"
        paths = {"json": f"{stem}.json", "csv": f"{stem}.csv", "html": f"{stem}.html"}
    json_path = args.json_out or paths.get("json")
    csv_path = args.csv_out or paths.get("csv")
    html_path = args.html_out or paths.get("html")
    write_outputs(findings, stats, json_path, csv_path, html_path,
                  policy=args.policy or (Path(args.policy_file).name if args.policy_file else ""))

    if args.json:
        print(json.dumps({"stats": stats, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print_report(findings, stats, args.show_info)
        saved = [x for x in (html_path, csv_path, json_path) if x]
        if saved:
            print("\nSaved:\n" + "\n".join(f"  {x}" for x in saved))

    return 1 if any(f.severity in ("error", "warn") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
