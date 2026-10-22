#!/usr/bin/env python3
"""
Network ACL shadowed-rule finder.

Intent: NACL rules are evaluated in rule-number order and the first match
wins, so a rule can be partly or completely hidden by earlier rules. This
tool finds rules that can never take effect (dead rules wasting slots against
the rules-per-NACL limit) and rules whose intent is defeated by an earlier
rule of the opposite action - the usual cause of "I added an allow and it
still doesn't work".

What it does:

  1. Reads every network ACL in the selected accounts and regions
     (optionally only some VPCs / NACLs, or only FMS-managed ones).
  2. Per NACL and direction, walks the entries in rule-number order (the
     '*' default rules are skipped). Each entry becomes an exact
     protocol x port/ICMP x address box (lib/boxes.py).
  3. For each entry, works out what part of it is already matched by earlier
     entries, and by which ones:
       * SHADOWED_CONFLICT  fully covered, at least one earlier rule has the
                            opposite action: the rule never matches and its
                            intent is defeated
       * REDUNDANT          fully covered by earlier rules with the same
                            action: the rule never matches; removing it frees
                            a slot
       * PARTIALLY_SHADOWED part of it is covered by an earlier rule with the
                            opposite action; `effective` lists what it still
                            matches
       * PARTIAL_OVERLAP_SAME_ACTION (info) part of it overlaps earlier
                            same-action rules (harmless, maybe consolidatable)

Accounts: the --profile (or default credentials) account by default;
--account / --all-accounts scan member accounts through their local profiles
(found by account id, -priv / -cpar profiles never used, each verified with
sts:GetCallerIdentity).

Usage:

    ./nacl_shadow.py --profile prod-ro --region us-east-1
    ./nacl_shadow.py --all-accounts --all-regions --fmmanaged-only

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports: text on screen, plus auto-saved HTML (interactive: filter, sort,
unique counts of accounts/VPCs/NACLs...), CSV and JSON under
reports/nacl_shadow/YYYY-MM-DD/.

Exit codes: 0 clean, 1 error or warning findings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import Target, add_account_args, check_profile_args, select_accounts  # noqa: E402
from lib.aws_common import _g, get_client, get_session, resolve_regions  # noqa: E402
from lib.boxes import (Box, addr_interval, fmt_addrs, fmt_proto_ports, intersects, merge,  # noqa: E402
                       proto_port_box, remainder)
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, exit_code, print_saved,  # noqa: E402
                        report_paths, setup_logging, write_csv, write_json, write_text)

log = logging.getLogger("nacl_shadow")

TOOL = "nacl_shadow"
DEFAULT_RULE_MIN = 32767      # 32767 (IPv4 '*') and 32768 (IPv6 '*') are the immutable defaults
DEAD_CODES = ("SHADOWED_CONFLICT", "REDUNDANT")
MAX_CIDRS_SHOWN = 8           # per line in the text report; files always hold everything


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
@dataclass
class NaclRule:
    """One NACL entry as an exact access box, in rule-number order within its direction."""
    number: int
    egress: bool
    action: str          # allow | deny
    space: str           # ipv4 | ipv6
    box: Box
    text: str

    @classmethod
    def from_api(cls, e: dict) -> "NaclRule | None":
        """Build from a DescribeNetworkAcls entry; None when the entry has no usable CIDR."""
        cidr = e.get("CidrBlock") or e.get("Ipv6CidrBlock")
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (TypeError, ValueError):
            return None
        proto = str(e.get("Protocol", "-1"))
        pr = e.get("PortRange") or {}
        ic = e.get("IcmpTypeCode") or {}
        if proto in ("1", "58"):
            lo, hi = ic.get("Type", -1), ic.get("Code", -1)
        else:
            lo, hi = pr.get("From"), pr.get("To")
        protos, ports = proto_port_box(proto, lo, hi)
        egress = bool(e.get("Egress"))
        action = str(e.get("RuleAction", "")).lower()
        number = int(e["RuleNumber"])
        text = (f"#{number} {'egress' if egress else 'ingress'} {action} "
                f"{fmt_proto_ports(protos, ports)} {net}")
        return cls(number, egress, action, f"ipv{net.version}", (protos, ports, addr_interval(net)), text)

    @property
    def direction(self) -> str:
        """'ingress' or 'egress'."""
        return "egress" if self.egress else "ingress"


@dataclass
class Finding:
    """One shadowing result for a NACL entry (or an account that could not be scanned)."""
    severity: str            # error | warn | info
    code: str
    account: str = ""
    profile: str = ""
    region: str = ""
    vpc_id: str = ""
    nacl_id: str = ""
    subnets: list[str] = field(default_factory=list)
    fmmanaged: str = ""      # yes | no
    direction: str = ""
    rule_number: int | str = ""
    action: str = ""
    rule: str = ""
    shadowed_by: list[str] = field(default_factory=list)
    effective: list[str] = field(default_factory=list)
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


def fmt_boxes(space: str, boxes: list[Box]) -> list[str]:
    """Render boxes as text lines, one per protocol/port combination, CIDRs merged."""
    by_pp = defaultdict(list)
    for pr, ports, addr in merge(boxes):
        by_pp[(pr, ports)].extend(fmt_addrs(space, addr))
    return [f"{fmt_proto_ports(pr, ports)} {', '.join(addrs)}" for (pr, ports), addrs in sorted(by_pp.items())]


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def analyze_entries(entries: list[dict]) -> list[tuple[str, NaclRule, list[NaclRule], list[str]]]:
    """Find shadowing among one NACL's entries.

    Returns (code, rule, overlapping earlier rules, effective text) for every entry that is
    fully or partly matched by earlier entries in the same direction and address space.
    """
    rules = [r for r in (NaclRule.from_api(e) for e in entries
                         if int(e.get("RuleNumber", DEFAULT_RULE_MIN)) < DEFAULT_RULE_MIN) if r]
    out = []
    for egress in (False, True):
        seq = sorted((r for r in rules if r.egress == egress), key=lambda r: r.number)
        for i, r in enumerate(seq):
            hits = [o for o in seq[:i] if o.space == r.space and intersects(o.box, r.box)]
            if not hits:
                continue
            rem = remainder(r.box, [o.box for o in hits])
            opposite = [o for o in hits if o.action != r.action]
            if not rem:
                code = "SHADOWED_CONFLICT" if opposite else "REDUNDANT"
            elif opposite:
                code = "PARTIALLY_SHADOWED"
            else:
                code = "PARTIAL_OVERLAP_SAME_ACTION"
            out.append((code, r, hits, fmt_boxes(r.space, rem) if rem else []))
    return out


SEVERITY = {"SHADOWED_CONFLICT": "error", "REDUNDANT": "warn", "PARTIALLY_SHADOWED": "warn",
            "PARTIAL_OVERLAP_SAME_ACTION": "info"}
DETAIL = {
    "SHADOWED_CONFLICT": "never matches: earlier rule(s) of the opposite action take all of its traffic",
    "REDUNDANT": "never matches: earlier rule(s) with the same action already cover it; removing it frees a slot",
    "PARTIALLY_SHADOWED": "part of its traffic is taken by earlier rule(s) of the opposite action",
    "PARTIAL_OVERLAP_SAME_ACTION": "partly overlaps earlier rule(s) with the same action",
}


def nacl_matches(nacl: dict, args) -> bool:
    """Apply --vpc, --nacl and --fmmanaged-only filters."""
    if args.vpc and nacl.get("VpcId") not in args.vpc:
        return False
    if args.nacl and nacl.get("NetworkAclId") not in args.nacl:
        return False
    if args.fmmanaged_only and not is_fmmanaged(nacl):
        return False
    return True


def is_fmmanaged(nacl: dict) -> bool:
    """True when the NACL is tagged FMManaged=true by Firewall Manager."""
    tags = {t["Key"]: t.get("Value", "") for t in _g(nacl, "Tags", [])}
    return tags.get("FMManaged", "").lower() == "true"


def scan(target: Target, region: str, args, stats: dict) -> list[Finding]:
    """Scan every matching NACL of one account in one region."""
    ec2 = get_client("ec2", get_session(target.profile, region))
    findings = []
    for page in ec2.get_paginator("describe_network_acls").paginate():
        for nacl in _g(page, "NetworkAcls", []):
            if not nacl_matches(nacl, args):
                continue
            stats["nacls"] += 1
            entries = _g(nacl, "Entries", [])
            stats["rules"] += sum(1 for e in entries if int(e.get("RuleNumber", DEFAULT_RULE_MIN)) < DEFAULT_RULE_MIN)
            base = dict(account=target.account, profile=target.label, region=region, vpc_id=nacl.get("VpcId", ""),
                        nacl_id=nacl.get("NetworkAclId", ""),
                        subnets=sorted(a["SubnetId"] for a in _g(nacl, "Associations", []) if a.get("SubnetId")),
                        fmmanaged="yes" if is_fmmanaged(nacl) else "no")
            for code, r, hits, effective in analyze_entries(entries):
                findings.append(Finding(
                    severity=SEVERITY[code], code=code, **base, direction=r.direction, rule_number=r.number,
                    action=r.action, rule=r.text, shadowed_by=[o.text for o in hits], effective=effective,
                    detail=DETAIL[code] + (" (default NACL)" if nacl.get("IsDefault") else "")))
    return findings


def unscannable(t: Target) -> Finding:
    """Error finding for an account that has no usable, verified profile."""
    if t.profile is None:
        code = "NO_PROFILE"
    elif "resolves to" in t.note:
        code = "PROFILE_ACCOUNT_MISMATCH"
    else:
        code = "ACCOUNT_ERROR"
    return Finding(severity="error", code=code, account=t.account, profile=t.profile or "", detail=t.note)


def run(args, targets: list[Target], regions: list[str]) -> tuple[list[Finding], dict]:
    """Scan every usable account in every region; return sorted findings and run statistics."""
    stats = {"accounts": 0, "accounts_skipped": 0, "regions": len(regions), "nacls": 0, "rules": 0}
    findings: list[Finding] = []
    for t in targets:
        if not t.ok:
            stats["accounts_skipped"] += 1
            findings.append(unscannable(t))
            continue
        stats["accounts"] += 1
        for region in regions:
            log.info("Account %s (%s) %s: scanning NACLs", t.account, t.label, region)
            try:
                findings += scan(t, region, args, stats)
            except (ClientError, BotoCoreError) as e:
                findings.append(Finding(severity="error", code="ACCOUNT_ERROR", account=t.account,
                                        profile=t.label, region=region, detail=str(e)))
    findings.sort(key=lambda f: (f.account, f.region, f.vpc_id, f.nacl_id, f.direction != "ingress",
                                 f.rule_number if isinstance(f.rule_number, int) else -1))
    stats["dead_rules"] = sum(f.code in DEAD_CODES for f in findings)
    stats["by_code"] = {}
    for f in findings:
        stats["by_code"][f.code] = stats["by_code"].get(f.code, 0) + 1
    return findings, stats


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(findings: list[Finding], stats: dict, show_info: bool) -> None:
    """Print the text report: run totals, then findings grouped by account / region / NACL / direction."""
    print()
    print(f"Accounts scanned: {stats['accounts']}   skipped: {stats['accounts_skipped']}   "
          f"regions: {stats['regions']}   NACLs: {stats['nacls']}   rules: {stats['rules']}   "
          f"dead rules: {stats['dead_rules']}")
    if stats["by_code"]:
        print("Findings: " + "   ".join(f"{k}: {v}" for k, v in sorted(stats["by_code"].items())))
    shown = [f for f in findings if show_info or f.severity != "info"]
    if not shown:
        print("\nNo shadowed or redundant rules.")
    cur = None
    for f in shown:
        hdr = (f.account, f.region, f.nacl_id, f.direction)
        if hdr != cur:
            cur = hdr
            if f.nacl_id:
                print(f"\n{f.account} ({f.profile})  {f.region}  {f.nacl_id}  vpc={f.vpc_id}  "
                      f"fmmanaged={f.fmmanaged}  subnets={','.join(f.subnets) or '-'}  [{f.direction}]")
            else:
                print(f"\n{f.account} ({f.profile or 'no profile'})  {f.region or '-'}")
        print(f"    [{f.severity.upper():<5}] {f.code:<27} {f.rule}")
        if f.detail:
            print(f"            {f.detail}")
        for x in f.shadowed_by:
            print(f"            earlier: {x}")
        for x in f.effective:
            parts = x.split(", ")
            if len(parts) > MAX_CIDRS_SHOWN:
                x = ", ".join(parts[:MAX_CIDRS_SHOWN]) + f", ... {len(parts) - MAX_CIDRS_SHOWN} more (see CSV/JSON)"
            print(f"            still matches: {x}")
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"\n({hidden} info findings hidden; --show-info to list)")


def render_html(findings: list[Finding], stats: dict) -> str:
    """Build the interactive HTML report: run totals and a filterable findings table."""
    cards = [(stats["accounts"], "accounts scanned"), (stats["accounts_skipped"], "accounts skipped"),
             (stats["regions"], "regions"), (stats["nacls"], "NACLs"), (stats["rules"], "rules evaluated"),
             (stats["dead_rules"], "dead rules")]
    table = {
        "id": "findings", "title": "Shadowed and redundant NACL rules", "row_label": "findings",
        "note": "Entries are evaluated in rule-number order; the first match wins. 'Earlier rules' are the "
                "lower-numbered entries that take some or all of a rule's traffic.",
        "columns": [["severity", "Severity"], ["code", "Code"], ["account", "Account"], ["profile", "Profile"],
                    ["region", "Region"], ["vpc_id", "VPC"], ["nacl_id", "NACL"], ["fmmanaged", "FMManaged"],
                    ["subnets", "Subnets"], ["direction", "Direction"], ["rule_number", "Rule #"],
                    ["action", "Action"], ["rule", "Rule"], ["shadowed_by", "Earlier rules"],
                    ["effective", "Still matches"], ["detail", "Detail"]],
        "rows": [asdict(f) for f in findings],
        "filters": ["severity", "code", "account", "region", "vpc_id", "nacl_id", "direction", "fmmanaged"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["vpc_id", "VPCs"], ["nacl_id", "NACLs"],
                 ["subnets", "Subnets"]],
        "wrap": ["subnets", "rule", "shadowed_by", "effective", "detail"],
        "badges": {"severity": SEVERITY_BADGES},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["severity", 1], ["account", 1], ["nacl_id", 1], ["rule_number", 1]],
        "hide": {"key": "severity", "values": ["info"], "label": "show info"},
        "by": {"key": "code", "label": "By code", "badge": "severity"},
    }
    return html_report.render("NACL shadowed rules", cards=cards, tables=[table])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 clean, 1 error/warn findings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Find NACL rules that are shadowed by, or redundant with, earlier rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-ro --region us-east-1
  %(prog)s --all-accounts --all-regions --fmmanaged-only
  %(prog)s --account 111122223333 --vpc vpc-0123456789abcdef0
""")
    add_account_args(p)
    p.add_argument("--region", action="append",
                   help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true", help="Every enabled region")
    p.add_argument("--vpc", action="append", metavar="VPC_ID", help="Only NACLs in these VPC(s) (repeatable)")
    p.add_argument("--nacl", action="append", metavar="ACL_ID", help="Only these NACL(s) (repeatable)")
    p.add_argument("--fmmanaged-only", action="store_true", help="Only NACLs tagged FMManaged=true")
    p.add_argument("--show-info", action="store_true", help="Show info findings in the text report")
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        targets = select_accounts(args)
        regions = resolve_regions(next((t.profile for t in targets if t.ok), args.profile),
                                  args.region, args.all_regions, service="ec2")
        findings, stats = run(args, targets, regions)
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", e)
        return 2

    accounts = sorted({t.account for t in targets})
    slug = accounts[0] if len(accounts) == 1 else f"{len(accounts)}_accounts"
    paths = report_paths(args, TOOL, f"naclshadow_{slug}")
    payload = {"stats": stats, "findings": [asdict(f) for f in findings]}
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(f) for f in findings], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(findings, stats))

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(findings, stats, args.show_info)
        print_saved(paths)
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
