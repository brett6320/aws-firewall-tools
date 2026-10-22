#!/usr/bin/env python3
"""
Security group quota and hygiene audit.

Intent: security group changes fail when a group runs out of rule slots or a
network interface already carries the maximum number of groups, and prefix
list references use up far more slots than they appear to. This tool shows,
across accounts and regions, which groups and interfaces are at or near those
quotas before a change fails, and which groups are clean-up candidates
(unattached groups, stale references, VPC default groups that allow traffic).
It is the security group counterpart of fmm_nacl_audit.py's NACL limit check.

What it does, per account (through its verified local profile) and region:

  1. Looks up the account's quotas with Service Quotas: "Inbound or outbound
     rules per security group" (vpc / L-0EA8095F, default 60) and "Security
     groups per network interface" (vpc / L-2AFB9258, default 5). Falls back
     to the AWS default value, then to the documented defaults.
  2. Counts each group's rules per direction. A CIDR or group-reference rule
     counts 1; a rule referencing a managed prefix list counts as the list's
     MaxEntries, which is how AWS charges it against the quota.
  3. Counts the groups attached to each network interface.
  4. Lists stale references (describe_stale_security_groups), unattached
     groups, and VPC default groups that hold any rule.

Usage:

    ./sg_quota_audit.py --profile prod-admin --region us-east-1
    ./sg_quota_audit.py --all-accounts --all-regions
    ./sg_quota_audit.py --account 111122223333,444455556666 --vpc vpc-0abc

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports
    # Override the rules-per-group quota instead of looking it up
    SG_RULE_LIMIT=
    # Override the groups-per-network-interface quota instead of looking it up
    SG_PER_ENI_LIMIT=
    # Flag groups within this many rules of the limit (default 5)
    SG_RULE_HEADROOM=5
    # Flag network interfaces within this many groups of the limit (default 1)
    SG_ENI_HEADROOM=1

Reports: text on screen, plus auto-saved HTML (interactive findings table and
a sortable table of every scanned group), CSV (findings) and JSON
({stats, quotas, groups, findings}) under reports/sg_quota_audit/YYYY-MM-DD/.

Exit codes: 0 clean, 1 error or warning findings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import Target, add_account_args, check_profile_args, select_accounts  # noqa: E402
from lib.aws_common import err_text, _g, get_client, get_session, resolve_regions  # noqa: E402  (loads .env, logging)
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, exit_code, print_saved,  # noqa: E402
                        report_paths, setup_logging, write_csv, write_json, write_text)

log = logging.getLogger("sg_quota_audit")

RULE_QUOTA = ("vpc", "L-0EA8095F", 60)     # inbound or outbound rules per security group
ENI_QUOTA = ("vpc", "L-2AFB9258", 5)       # security groups per network interface
DEFAULT_HEADROOM = 5
DEFAULT_ENI_HEADROOM = 1
DIRECTIONS = ("inbound", "outbound")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One audit result for a group, network interface, account or region."""
    severity: str                 # error | warn | info
    code: str
    account: str = ""
    profile: str = ""
    region: str = ""
    vpc_id: str = ""
    resource_id: str = ""         # sg-... or eni-...
    resource_name: str = ""
    direction: str = ""           # inbound | outbound for rule-count findings
    count: int | str = ""
    limit: int | str = ""
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


@dataclass
class Quotas:
    """Quota values in force for one account and region, and where each came from."""
    account: str
    region: str
    rule_limit: int
    rule_source: str              # applied | aws-default | default | override
    eni_limit: int
    eni_source: str


@dataclass
class GroupUsage:
    """Rule usage of one security group (one row of the 'groups' table)."""
    account: str
    region: str
    vpc_id: str
    group_id: str
    name: str
    is_default: bool
    inbound_raw: int = 0
    inbound_effective: int = 0
    outbound_raw: int = 0
    outbound_effective: int = 0
    limit: int = 0
    enis: int = 0
    referenced_by: list[str] = field(default_factory=list)
    pl_weights: dict = field(default_factory=lambda: {"inbound": {}, "outbound": {}})  # pl-id -> weight used

    @property
    def peak_pct(self) -> int:
        """Highest direction's effective usage as a percentage of the limit."""
        return round(100 * max(self.inbound_effective, self.outbound_effective) / self.limit) if self.limit else 0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _env_int(name: str, default: int | None) -> int | None:
    """Integer from the environment, or the default when unset or empty."""
    v = os.getenv(name, "").strip()
    return int(v) if v else default


def _paginate(client, op: str, key: str, **kw):
    """Iterate every item under `key` across all pages of a paginated call."""
    for page in client.get_paginator(op).paginate(**kw):
        yield from _g(page, key, [])


def _name_tag(tags: list[dict] | None) -> str:
    """Value of the Name tag, or ''."""
    return next((t.get("Value", "") for t in tags or [] if t.get("Key") == "Name"), "")


def lookup_quota(sq, quota: tuple[str, str, int], override: int | None) -> tuple[int, str, bool]:
    """Quota value for one account/region: (value, source, access_denied).

    An override wins. Otherwise the applied value (GetServiceQuota), then the AWS default
    (GetAWSDefaultServiceQuota), then the documented default. access_denied is True when
    Service Quotas could not be read at all, so the caller can say defaults were used.
    """
    service, code, default = quota
    if override is not None:
        return override, "override", False
    denied = False
    for op, source in (("get_service_quota", "applied"), ("get_aws_default_service_quota", "aws-default")):
        try:
            value = getattr(sq, op)(ServiceCode=service, QuotaCode=code)["Quota"]["Value"]
            return int(value), source, False
        except ClientError as e:
            c = e.response["Error"]["Code"]
            denied = denied or c in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation")
            log.debug("%s %s: %s", op, code, c)
        except (BotoCoreError, KeyError, TypeError, ValueError) as e:
            log.debug("%s %s: %s", op, code, e)
    return default, "default", denied


def prefix_list_weights(ec2, ids: set[str]) -> tuple[dict[str, int], dict[str, str], set[str]]:
    """Quota weight of each referenced prefix list: (weights, names, unknown-weight ids).

    The weight is the list's MaxEntries. AWS-managed lists without MaxEntries, and lists
    that cannot be described, count as 1 and are returned in the unknown set.
    """
    weights: dict[str, int] = {}
    names: dict[str, str] = {}
    unknown: set[str] = set()

    def describe(batch: list[str]) -> list[dict]:
        """Describe a batch; on failure (one bad id fails the call) fall back to one id at a time."""
        try:
            return list(_paginate(ec2, "describe_managed_prefix_lists", "PrefixLists", PrefixListIds=batch))
        except ClientError as e:
            if len(batch) == 1:
                log.warning("describe_managed_prefix_lists %s: %s", batch[0], err_text(e))
                return []
            return [pl for pid in batch for pl in describe([pid])]

    ordered = sorted(ids)
    for i in range(0, len(ordered), 100):
        for pl in describe(ordered[i:i + 100]):
            names[pl["PrefixListId"]] = pl.get("PrefixListName", "")
            if pl.get("MaxEntries"):
                weights[pl["PrefixListId"]] = int(pl["MaxEntries"])
    for pid in ids:
        if pid not in weights:
            weights[pid] = 1
            unknown.add(pid)
    return weights, names, unknown


def stale_groups(ec2, vpc_id: str) -> list[dict]:
    """Groups in a VPC with stale rules (references to deleted groups or peerings)."""
    out, token = [], None
    while True:
        kw = {"VpcId": vpc_id, **({"NextToken": token} if token else {})}
        resp = ec2.describe_stale_security_groups(**kw)
        out.extend(_g(resp, "StaleSecurityGroupSet", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _stale_refs(sg: dict) -> list[str]:
    """Human-readable stale references of one stale group entry."""
    refs = []
    for direction, key in (("inbound", "StaleIpPermissions"), ("outbound", "StaleIpPermissionsEgress")):
        for perm in _g(sg, key, []):
            proto = perm.get("IpProtocol", "-1")
            ports = "" if perm.get("FromPort") in (None, -1) else f" {perm.get('FromPort')}-{perm.get('ToPort')}"
            for pair in _g(perm, "UserIdGroupPairs", []):
                peer = pair.get("GroupId") or pair.get("GroupName") or "?"
                via = f" via {pair['VpcPeeringConnectionId']}" if pair.get("VpcPeeringConnectionId") else ""
                refs.append(f"{direction} {proto}{ports} {peer}{via}")
    return refs


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def scan_region(t: Target, region: str, args) -> tuple[list[Finding], list[GroupUsage], Quotas, int]:
    """Audit one account in one region: quotas, rule usage per group, groups per network
    interface, stale references, unattached and default groups.

    Returns (findings, group usage rows, quotas, network interfaces scanned).
    """
    session = get_session(t.profile, region)
    ec2 = get_client("ec2", session)
    base = dict(account=t.account, profile=t.label, region=region)
    findings: list[Finding] = []

    rule_override = args.rule_limit
    eni_override = args.sg_per_eni_limit
    sq = None if rule_override is not None and eni_override is not None else get_client("service-quotas", session)
    rule_limit, rule_src, denied1 = lookup_quota(sq, RULE_QUOTA, rule_override)
    eni_limit, eni_src, denied2 = lookup_quota(sq, ENI_QUOTA, eni_override)
    quotas = Quotas(t.account, region, rule_limit, rule_src, eni_limit, eni_src)
    if denied1 or denied2 or "default" in (rule_src, eni_src):
        findings.append(Finding("info", "QUOTA_DEFAULTS_USED", **base,
                                detail=f"Service Quotas values not available; using rules-per-group {rule_limit} "
                                       f"({rule_src}), groups-per-interface {eni_limit} ({eni_src})"))

    vpc_filter = [{"Name": "vpc-id", "Values": args.vpc}] if args.vpc else []
    groups: dict[str, GroupUsage] = {}
    for g in _paginate(ec2, "describe_security_groups", "SecurityGroups", Filters=vpc_filter):
        groups[g["GroupId"]] = GroupUsage(t.account, region, g.get("VpcId", ""), g["GroupId"],
                                          g.get("GroupName", ""), g.get("GroupName") == "default",
                                          limit=rule_limit)

    rules = [r for r in _paginate(ec2, "describe_security_group_rules", "SecurityGroupRules")
             if r.get("GroupId") in groups]
    pl_ids = {r["PrefixListId"] for r in rules if r.get("PrefixListId")}
    weights, pl_names, unknown = prefix_list_weights(ec2, pl_ids) if pl_ids else ({}, {}, set())
    for r in rules:
        g = groups[r["GroupId"]]
        d = "outbound" if r.get("IsEgress") else "inbound"
        w = 1
        if r.get("PrefixListId"):
            pid = r["PrefixListId"]
            w = weights.get(pid, 1)
            g.pl_weights[d][pid] = g.pl_weights[d].get(pid, 0) + w
        setattr(g, f"{d}_raw", getattr(g, f"{d}_raw") + 1)
        setattr(g, f"{d}_effective", getattr(g, f"{d}_effective") + w)
        ref = _g(r, "ReferencedGroupInfo", {}).get("GroupId")
        if ref and ref in groups and ref != r["GroupId"] and r["GroupId"] not in groups[ref].referenced_by:
            groups[ref].referenced_by.append(r["GroupId"])

    enis = list(_paginate(ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=vpc_filter))
    for eni in enis:
        attached = [x["GroupId"] for x in _g(eni, "Groups", [])]
        for gid in attached:
            if gid in groups:
                groups[gid].enis += 1
        n = len(attached)
        if n >= eni_limit - args.eni_headroom:
            att = _g(eni, "Attachment", {})
            findings.append(Finding(
                "error" if n >= eni_limit else "warn",
                "ENI_AT_SG_LIMIT" if n >= eni_limit else "ENI_NEAR_SG_LIMIT", **base,
                vpc_id=eni.get("VpcId", ""), resource_id=eni["NetworkInterfaceId"],
                resource_name=eni.get("Description") or att.get("InstanceId", ""), count=n, limit=eni_limit,
                detail=f"groups: {', '.join(attached)}"))

    for g in groups.values():
        gbase = dict(**base, vpc_id=g.vpc_id, resource_id=g.group_id, resource_name=g.name)
        for d in DIRECTIONS:
            eff, raw = getattr(g, f"{d}_effective"), getattr(g, f"{d}_raw")
            if eff >= rule_limit - args.headroom:
                heavy = sorted(g.pl_weights[d].items(), key=lambda kv: -kv[1])[:3]
                parts = [f"{raw} rules count as {eff}"]
                if heavy:
                    parts.append("heaviest prefix lists: " + ", ".join(
                        f"{pid}{f' ({pl_names[pid]})' if pl_names.get(pid) else ''} {w}" for pid, w in heavy))
                if any(pid in unknown for pid in g.pl_weights[d]):
                    parts.append("AWS-managed prefix list weight not known; counted as 1")
                findings.append(Finding("error" if eff >= rule_limit else "warn",
                                        "SG_AT_LIMIT" if eff >= rule_limit else "SG_NEAR_LIMIT", **gbase,
                                        direction=d, count=eff, limit=rule_limit, detail="; ".join(parts)))
        if g.is_default and (g.inbound_raw or g.outbound_raw):
            findings.append(Finding("warn", "DEFAULT_SG_HAS_RULES", **gbase,
                                    count=g.inbound_raw + g.outbound_raw,
                                    detail=f"{g.inbound_raw} inbound, {g.outbound_raw} outbound rule(s); the VPC "
                                           f"default group should allow nothing"))
        if not g.is_default and g.enis == 0:
            refd = (f"referenced by {', '.join(sorted(g.referenced_by))}, so possibly still needed"
                    if g.referenced_by else "not referenced by other groups")
            findings.append(Finding("info", "UNATTACHED_SG", **gbase,
                                    detail=f"attached to no network interface; {refd}. May still be used by "
                                           f"launch templates or other configuration"))

    for vpc_id in sorted({g.vpc_id for g in groups.values() if g.vpc_id}):
        try:
            for sg in stale_groups(ec2, vpc_id):
                refs = _stale_refs(sg)
                findings.append(Finding("warn", "STALE_REFERENCE", **base, vpc_id=vpc_id,
                                        resource_id=sg.get("GroupId", ""), resource_name=sg.get("GroupName", ""),
                                        count=len(refs),
                                        detail="stale: " + ("; ".join(refs) if refs else "see console")))
        except ClientError as e:
            log.warning("%s %s describe_stale_security_groups %s: %s", t.account, region, vpc_id, err_text(e))
    return findings, list(groups.values()), quotas, len(enis)


def run(args, targets: list[Target], regions: list[str]) -> dict:
    """Scan every usable account in every region; unusable accounts become error findings.

    Returns {stats, quotas, groups, findings} with findings sorted for reporting.
    """
    findings: list[Finding] = []
    groups: list[GroupUsage] = []
    quotas: list[Quotas] = []
    stats = {"accounts": 0, "accounts_skipped": 0, "regions": len(regions), "groups": 0, "enis": 0}
    for t in targets:
        if not t.ok:
            stats["accounts_skipped"] += 1
            code = "PROFILE_ACCOUNT_MISMATCH" if "resolves to" in t.note else (
                "NO_PROFILE" if t.profile is None else "ACCOUNT_ERROR")
            findings.append(Finding("error", code, account=t.account, profile=t.profile or "", detail=t.note))
            continue
        scanned = False
        for region in regions:
            log.info("Account %s (%s) region %s", t.account, t.label, region)
            try:
                f, g, q, n = scan_region(t, region, args)
            except (ClientError, BotoCoreError) as e:
                findings.append(Finding("error", "ACCOUNT_ERROR", account=t.account, profile=t.label,
                                        region=region, detail=err_text(e)))
                continue
            scanned = True
            findings += f
            groups += g
            quotas.append(q)
            stats["groups"] += len(g)
            stats["enis"] += n
        stats["accounts" if scanned else "accounts_skipped"] += 1
    findings.sort(key=lambda f: (f.account, f.region, SEVERITY_ORDER[f.severity], f.code, f.vpc_id,
                                 f.resource_id, f.direction))
    groups.sort(key=lambda g: (-g.peak_pct, g.account, g.region, g.group_id))
    by_code: dict[str, int] = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    stats["by_code"] = dict(by_code)
    return {"stats": stats, "quotas": [asdict(q) for q in quotas],
            "groups": [group_row(g) for g in groups], "findings": [asdict(f) for f in findings]}


def group_row(g: GroupUsage) -> dict:
    """JSON/HTML row for a group's usage."""
    d = asdict(g)
    d["peak_pct"] = g.peak_pct
    d["referenced_by"] = sorted(g.referenced_by)
    return d


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(payload: dict, show_info: bool) -> None:
    """Print run totals, then findings grouped by account / region (info only with show_info)."""
    s = payload["stats"]
    print(f"\nAccounts scanned: {s['accounts']}   skipped: {s['accounts_skipped']}   regions: {s['regions']}   "
          f"groups: {s['groups']}   network interfaces: {s['enis']}")
    for q in payload["quotas"]:
        print(f"  {q['account']} {q['region']}: rules per group {q['rule_limit']} ({q['rule_source']}), "
              f"groups per interface {q['eni_limit']} ({q['eni_source']})")
    if s["by_code"]:
        print("Findings: " + "   ".join(f"{k}: {v}" for k, v in sorted(s["by_code"].items())))
    findings = payload["findings"]
    shown = [f for f in findings if show_info or f["severity"] != "info"]
    if not shown:
        print("\nNothing at or near a quota; no stale references or default groups with rules.")
    cur = None
    for f in shown:
        hdr = (f["account"], f["region"])
        if hdr != cur:
            cur = hdr
            print(f"\naccount={f['account']} ({f['profile'] or '-'})  region={f['region'] or '-'}")
        what = " ".join(x for x in (f["vpc_id"], f["resource_id"],
                                    f"({f['resource_name']})" if f["resource_name"] else "", f["direction"]) if x)
        usage = f" {f['count']}/{f['limit']}" if f["limit"] != "" else ""
        print(f"    [{f['severity'].upper():<5}] {f['code']} {what}{usage}")
        if f["detail"]:
            print(f"            {f['detail']}")
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"\n({hidden} info findings hidden; --show-info to list)")


def render_html(payload: dict) -> str:
    """Interactive HTML report: run totals, a findings table, and a table of every scanned group."""
    s = payload["stats"]
    sev = [f["severity"] for f in payload["findings"]]
    cards = [(s["accounts"], "accounts scanned"), (s["accounts_skipped"], "accounts skipped"),
             (s["regions"], "regions"), (s["groups"], "groups"), (s["enis"], "network interfaces")]
    cards += [(sev.count(x), f"{x} findings") for x in ("error", "warn", "info")]
    meta = [f"Generated {dt.datetime.now():%Y-%m-%d %H:%M:%S} · prefix list rules count as the list's max entries"]
    findings = {
        "id": "findings", "title": "Findings", "row_label": "findings",
        "columns": [["severity", "Severity"], ["code", "Code"], ["account", "Account"], ["profile", "Profile"],
                    ["region", "Region"], ["vpc_id", "VPC"], ["resource_id", "Resource"],
                    ["resource_name", "Name"], ["direction", "Direction"], ["count", "Count"],
                    ["limit", "Limit"], ["detail", "Detail"]],
        "rows": payload["findings"],
        "filters": ["severity", "code", "account", "region", "vpc_id", "direction"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["vpc_id", "VPCs"], ["resource_id", "Resources"],
                 ["code", "Finding codes"]],
        "wrap": ["resource_name", "detail"],
        "badges": {"severity": SEVERITY_BADGES},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["severity", 1]],
        "hide": {"key": "severity", "values": ["info"], "label": "show info"},
        "by": {"key": "code", "label": "By code", "badge": "severity"},
    }
    groups = {
        "id": "groups", "title": "Security group usage", "row_label": "groups",
        "note": "Effective counts weight prefix list rules by the list's max entries. Peak % is the fuller "
                "direction against the rules-per-group limit.",
        "columns": [["peak_pct", "Peak %"], ["account", "Account"], ["region", "Region"], ["vpc_id", "VPC"],
                    ["group_id", "Group"], ["name", "Name"], ["inbound_raw", "In rules"],
                    ["inbound_effective", "In effective"], ["outbound_raw", "Out rules"],
                    ["outbound_effective", "Out effective"], ["limit", "Limit"], ["enis", "ENIs"],
                    ["referenced_by", "Referenced by"]],
        "rows": payload["groups"],
        "filters": ["account", "region", "vpc_id"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["vpc_id", "VPCs"]],
        "wrap": ["name", "referenced_by"],
        "sort": [["peak_pct", -1]],
    }
    return html_report.render("Security group quota audit", meta=meta, cards=cards, tables=[findings, groups])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 clean, 1 error/warn findings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Find security groups and network interfaces at or near AWS quotas, stale references, "
                    "unattached groups and VPC default groups with rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-admin --region us-east-1
  %(prog)s --all-accounts --all-regions
  %(prog)s --account 111122223333 --vpc vpc-0abc --headroom 10
""")
    add_account_args(p)
    p.add_argument("--region", action="append",
                   help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true", help="Every enabled region")
    p.add_argument("--vpc", action="append", metavar="VPC_ID", help="Only these VPC(s) (repeatable)")
    p.add_argument("--rule-limit", type=int, default=_env_int("SG_RULE_LIMIT", None),
                   help="Rules-per-group quota to use instead of looking it up (env SG_RULE_LIMIT)")
    p.add_argument("--sg-per-eni-limit", type=int, default=_env_int("SG_PER_ENI_LIMIT", None),
                   help="Groups-per-network-interface quota to use instead of looking it up (env SG_PER_ENI_LIMIT)")
    p.add_argument("--headroom", type=int, default=_env_int("SG_RULE_HEADROOM", DEFAULT_HEADROOM),
                   help=f"Flag groups within N rules of the limit (default {DEFAULT_HEADROOM}, env SG_RULE_HEADROOM)")
    p.add_argument("--eni-headroom", type=int, default=_env_int("SG_ENI_HEADROOM", DEFAULT_ENI_HEADROOM),
                   help=f"Flag network interfaces within N groups of the limit "
                        f"(default {DEFAULT_ENI_HEADROOM}, env SG_ENI_HEADROOM)")
    p.add_argument("--show-info", action="store_true", help="Show info findings in the text report")
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)
    vpcs = [v.strip() for item in args.vpc or [] for v in item.split(",") if v.strip()]
    args.vpc = vpcs or None

    try:
        targets = select_accounts(args)
        regions = resolve_regions(next((t.profile for t in targets if t.ok), args.profile),
                                  args.region, args.all_regions, service="ec2")
        payload = run(args, targets, regions)
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2

    slug = "all-accounts" if args.all_accounts else "_".join(sorted({t.account for t in targets}))[:60]
    paths = report_paths(args, "sg_quota_audit", f"sgquota_{slug}")
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], payload["findings"], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(payload))

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(payload, args.show_info)
        print_saved(paths)
    return exit_code([Finding(**f) for f in payload["findings"]])


if __name__ == "__main__":
    sys.exit(main())
