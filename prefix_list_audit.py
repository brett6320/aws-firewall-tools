#!/usr/bin/env python3
"""
Managed prefix list audit.

Intent: managed prefix lists are shared building blocks for security groups,
route tables and Firewall Manager policies. A full list blocks the next
change, an unused list is clutter, an oversized list silently burns security
group rule quota (every rule that references it counts its *maximum* size),
and copies of the "same" list in other accounts or regions drift apart. This
tool finds all of those, across accounts and regions, before they bite.

What it does, per account and region:

  1. Lists the managed prefix lists (customer-managed lists owned by the
     account by default; lists shared in via RAM with --include-shared;
     AWS-managed lists with --include-aws).
  2. Reads each list's entries and associations (the resources that use it).
  3. Flags lists that are full or nearly full, empty, unused, much larger than
     needed, not in an active state, or that hold overlapping entries.
  4. Across everything scanned, compares lists that share a name but are
     separate copies (different accounts or regions) and flags copies whose
     CIDRs differ from the most common version. A list shared via RAM has the
     same id everywhere, so it is one list, not a copy.

Usage:

    ./prefix_list_audit.py --profile prod-admin --region us-east-1
    ./prefix_list_audit.py --all-accounts --region us-east-1,ca-central-1 --name 'corp-*'
    ./prefix_list_audit.py --account 111122223333,444455556666 --all-regions --include-shared

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use when no --account / --all-accounts (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports
    # Flag lists within this many entries of MaxEntries
    PL_HEADROOM=2
    # Also flag lists at or above this utilisation percentage
    PL_FULL_PCT=90

Member account profiles are found in the local AWS config by account id
(profiles ending in -priv or -cpar are never used) and verified with
sts:GetCallerIdentity before use.

Reports: text on screen, plus auto-saved HTML (interactive: findings and every
list, with filters, sort and unique counts), CSV (findings) and JSON (stats,
lists with entries and associations, findings) under
reports/prefix_list_audit/YYYY-MM-DD/.

Exit codes: 0 clean, 1 error or warning findings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import ipaddress
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import Target, add_account_args, check_profile_args, select_accounts  # noqa: E402
from lib.aws_common import err_text, _g, get_client, get_session, resolve_regions  # noqa: E402  (also loads .env)
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, exit_code, print_saved,  # noqa: E402
                        report_paths, setup_logging, write_csv, write_json, write_text)

log = logging.getLogger("prefix_list_audit")

TOOL = "prefix_list_audit"
DEFAULT_HEADROOM = 2
DEFAULT_FULL_PCT = 90
OVERSIZE_FACTOR = 2               # MaxEntries >= 2 x entries ...
OVERSIZE_MIN_SPARE = 10           # ... and at least 10 spare slots
ACTIVE_STATES = {"create-complete", "modify-complete"}
MAX_PAIRS_SHOWN = 10


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class PrefixList:
    """One managed prefix list as seen from one scanned account and region."""
    account: str
    profile: str
    region: str
    prefix_list_id: str
    name: str
    family: str
    owner: str
    ownership: str                   # owned | shared | aws
    state: str
    version: int | None
    max_entries: int | None          # None for AWS-managed lists
    entries: list[dict] = field(default_factory=list)          # [{"cidr", "description"}]
    associations: list[dict] | None = None                     # None = could not be read
    tags: dict[str, str] = field(default_factory=dict)
    read_error: str = ""

    @property
    def cidrs(self) -> list[str]:
        """Entry CIDRs, normalised."""
        return [e["cidr"] for e in self.entries]

    @property
    def utilisation(self) -> float | None:
        """Entries as a percentage of MaxEntries (None when MaxEntries is unknown)."""
        if not self.max_entries:
            return None
        return round(100.0 * len(self.entries) / self.max_entries, 1)

    def resources(self) -> list[str]:
        """Associated resource ids (security groups, route tables, ...)."""
        return [a.get("ResourceId", "?") for a in self.associations or []]


@dataclass
class Finding:
    """One audit result for a prefix list or an account, as shown in every report format."""
    severity: str                    # error | warn | info
    code: str
    account: str = ""
    profile: str = ""
    region: str = ""
    prefix_list_id: str = ""
    prefix_list_name: str = ""
    owner: str = ""
    entries: int | None = None
    max_entries: int | None = None
    associations: int | None = None
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


def _norm_cidr(s: str) -> str:
    """Canonical CIDR text; unparseable input is kept as is."""
    try:
        return str(ipaddress.ip_network(s.strip(), strict=False))
    except ValueError:
        return s.strip()


def finding_for(pl: PrefixList, severity: str, code: str, detail: str) -> Finding:
    """Build a Finding carrying the list's identity and size."""
    return Finding(severity=severity, code=code, account=pl.account, profile=pl.profile, region=pl.region,
                   prefix_list_id=pl.prefix_list_id, prefix_list_name=pl.name, owner=pl.owner,
                   entries=len(pl.entries), max_entries=pl.max_entries,
                   associations=None if pl.associations is None else len(pl.associations), detail=detail)


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
def ownership_of(owner: str, account: str) -> str:
    """'aws' for AWS-managed lists, 'owned' for the scanned account's own lists, else 'shared'."""
    if owner == "AWS":
        return "aws"
    return "owned" if owner == account else "shared"


def collect_region(target: Target, region: str, args) -> list[PrefixList]:
    """Read the in-scope prefix lists of one account and region, with entries and associations.

    Per-list read failures are recorded on the list (`read_error`) instead of aborting the
    region; a failure to list prefix lists at all raises and is reported by the caller.
    """
    ec2 = get_client("ec2", get_session(target.profile, region))
    out: list[PrefixList] = []
    for page in ec2.get_paginator("describe_managed_prefix_lists").paginate():
        for p in _g(page, "PrefixLists", []):
            owner = str(p.get("OwnerId", ""))
            kind = ownership_of(owner, target.account)
            if kind == "shared" and not args.include_shared:
                continue
            if kind == "aws" and not args.include_aws:
                continue
            name = p.get("PrefixListName", "")
            if args.name and not any(fnmatch.fnmatchcase(name, pat) for pat in args.name):
                continue
            out.append(PrefixList(
                account=target.account, profile=target.label, region=region, prefix_list_id=p["PrefixListId"],
                name=name, family=p.get("AddressFamily", ""), owner=owner, ownership=kind,
                state=p.get("State", ""), version=p.get("Version"), max_entries=p.get("MaxEntries"),
                tags={t["Key"]: t.get("Value", "") for t in _g(p, "Tags", [])}))
    for pl in out:
        try:
            for page in ec2.get_paginator("get_managed_prefix_list_entries").paginate(PrefixListId=pl.prefix_list_id):
                pl.entries += [{"cidr": _norm_cidr(e["Cidr"]), "description": e.get("Description", "")}
                               for e in _g(page, "Entries", [])]
        except ClientError as e:
            pl.read_error = f"entries: {err_text(e)}"
        try:
            assoc: list[dict] = []
            for page in ec2.get_paginator("get_managed_prefix_list_associations").paginate(
                    PrefixListId=pl.prefix_list_id):
                assoc += _g(page, "PrefixListAssociations", [])
            pl.associations = assoc
        except ClientError as e:
            # Typically AccessDenied for lists shared in from another account.
            log.debug("%s %s associations: %s", region, pl.prefix_list_id, err_text(e))
            pl.associations = None
    log.info("Account %s %s: %d prefix lists", target.account, region, len(out))
    return out


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def overlapping_pairs(cidrs: list[str]) -> list[tuple[str, str]]:
    """(inner, outer) pairs where one entry is contained in (or equal to) another entry."""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    nets.sort(key=lambda n: (n.version, n.prefixlen))
    pairs = []
    for i, inner in enumerate(nets):
        for outer in nets[:i]:
            if outer.version == inner.version and inner.subnet_of(outer):
                pairs.append((str(inner), str(outer)))
    return pairs


def check_list(pl: PrefixList, headroom: int, full_pct: float) -> list[Finding]:
    """Per-list checks: state, read errors, emptiness, capacity, usage, sizing and overlaps."""
    out: list[Finding] = []
    n, mx = len(pl.entries), pl.max_entries
    if pl.read_error:
        out.append(finding_for(pl, "error", "ACCOUNT_ERROR", f"could not read {pl.read_error}"))
        return out
    if pl.state and pl.state not in ACTIVE_STATES:
        out.append(finding_for(pl, "warn", "PL_NOT_ACTIVE", f"state is {pl.state}"))
    if pl.ownership == "aws":
        return out          # AWS-managed: only usage information is meaningful
    if n == 0:
        out.append(finding_for(pl, "warn", "PL_EMPTY", "list has no entries"))
    if mx:
        if n >= mx:
            out.append(finding_for(pl, "error", "PL_FULL", f"{n}/{mx} entries; the next addition will fail"))
        elif n and (n >= mx - headroom or 100.0 * n / mx >= full_pct):
            out.append(finding_for(pl, "warn", "PL_NEAR_FULL",
                                   f"{n}/{mx} entries ({pl.utilisation}%); {mx - n} slot(s) left"))
        if n and mx >= OVERSIZE_FACTOR * n and mx - n >= OVERSIZE_MIN_SPARE:
            sgs = [r for r in pl.resources() if r.startswith("sg-")]
            used_by = f"; referenced by {len(sgs)} security group(s): {', '.join(sgs[:MAX_PAIRS_SHOWN])}" \
                      + (" ..." if len(sgs) > MAX_PAIRS_SHOWN else "") if sgs else ""
            out.append(finding_for(
                pl, "info", "PL_OVERSIZED",
                f"MaxEntries {mx} for {n} entries; every security group rule referencing this list counts "
                f"{mx} rules against the rules-per-group quota{used_by}"))
    if pl.ownership == "owned" and pl.associations == []:
        out.append(finding_for(pl, "warn", "PL_UNUSED", "no resources are associated with this list"))
    pairs = overlapping_pairs(pl.cidrs)
    if pairs:
        shown = ", ".join(f"{a} {'duplicates' if a == b else 'inside'} {b}" for a, b in pairs[:MAX_PAIRS_SHOWN])
        more = f" ... {len(pairs) - MAX_PAIRS_SHOWN} more" if len(pairs) > MAX_PAIRS_SHOWN else ""
        inner = len({a for a, _ in pairs})
        out.append(finding_for(pl, "info", "PL_OVERLAPPING_ENTRIES",
                               f"{inner} entr{'y' if inner == 1 else 'ies'} already covered by another entry "
                               f"(redundant slots): {shown}{more}"))
    return out


def check_name_drift(lists: list[PrefixList]) -> list[Finding]:
    """Flag separate copies of a same-named list (different account/region) whose CIDRs differ.

    Only owned lists are compared: a list shared via RAM keeps its id and is the same list
    wherever it appears. The reference version is the most common CIDR set among the copies
    (ties go to the first copy in account/region order).
    """
    out: list[Finding] = []
    by_name: dict[str, list[PrefixList]] = defaultdict(list)
    for pl in lists:
        if pl.ownership == "owned" and not pl.read_error:
            by_name[pl.name].append(pl)
    for name, copies in sorted(by_name.items()):
        ids = {c.prefix_list_id for c in copies}
        locations = {(c.account, c.region) for c in copies}
        if len(ids) < 2 or len(locations) < 2:
            continue
        copies = sorted(copies, key=lambda c: (c.account, c.region, c.prefix_list_id))
        sets = [frozenset(c.cidrs) for c in copies]
        counts = Counter(sets)
        ref = max(sets, key=lambda s: (counts[s], -sets.index(s)))
        ref_where = [f"{c.account}/{c.region} {c.prefix_list_id}" for c, s in zip(copies, sets) if s == ref]
        if len(counts) == 1:
            continue
        for c, s in zip(copies, sets):
            if s == ref:
                continue
            added, removed = sorted(s - ref), sorted(ref - s)
            parts = []
            if added:
                parts.append(f"extra: {', '.join(added[:MAX_PAIRS_SHOWN])}"
                             + (f" ... {len(added) - MAX_PAIRS_SHOWN} more" if len(added) > MAX_PAIRS_SHOWN else ""))
            if removed:
                parts.append(f"missing: {', '.join(removed[:MAX_PAIRS_SHOWN])}"
                             + (f" ... {len(removed) - MAX_PAIRS_SHOWN} more" if len(removed) > MAX_PAIRS_SHOWN
                                else ""))
            out.append(finding_for(
                c, "warn", "PL_NAME_DRIFT",
                f"differs from the most common '{name}' ({len(ref)} entries, in {'; '.join(ref_where[:3])}"
                f"{' ...' if len(ref_where) > 3 else ''}): {'; '.join(parts)}"))
    return out


def dedupe_shared(lists: list[PrefixList]) -> list[PrefixList]:
    """Lists to run per-list checks on: one record per prefix list id, preferring the owner's view.

    A list shared via RAM shows up in every account it is shared with; checking it once
    avoids repeating the same finding for each consumer account.
    """
    best: dict[str, PrefixList] = {}
    rank = {"owned": 0, "aws": 1, "shared": 2}
    for pl in lists:
        cur = best.get(pl.prefix_list_id)
        if cur is None or rank[pl.ownership] < rank[cur.ownership]:
            best[pl.prefix_list_id] = pl
    return list(best.values())


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
def run(args, regions: list[str], targets: list[Target]) -> tuple[list[PrefixList], list[Finding], dict]:
    """Scan every selected account and region, then check each list and cross-copy drift."""
    lists: list[PrefixList] = []
    findings: list[Finding] = []
    stats = {"accounts": 0, "accounts_skipped": 0, "regions": len(regions), "prefix_lists": 0}
    for t in targets:
        if not t.ok:
            stats["accounts_skipped"] += 1
            code = "NO_PROFILE" if not t.profile else "PROFILE_ACCOUNT_MISMATCH"
            findings.append(Finding("error", code, account=t.account, profile=t.profile or "", detail=t.note))
            continue
        scanned = False
        for region in regions:
            try:
                lists += collect_region(t, region, args)
                scanned = True
            except (ClientError, BotoCoreError) as e:
                findings.append(Finding("error", "ACCOUNT_ERROR", account=t.account, profile=t.label, region=region,
                                        detail=f"describe_managed_prefix_lists: {err_text(e)}"))
        stats["accounts" if scanned else "accounts_skipped"] += 1
    for pl in dedupe_shared(lists):
        findings += check_list(pl, args.headroom, args.full_pct)
    findings += check_name_drift(lists)
    stats["prefix_lists"] = len({pl.prefix_list_id for pl in lists})
    findings.sort(key=lambda f: (f.account, f.region, f.prefix_list_name, f.prefix_list_id,
                                 SEVERITY_ORDER[f.severity], f.code))
    stats["by_code"] = dict(sorted(Counter(f.code for f in findings).items()))
    return lists, findings, stats


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def list_rows(lists: list[PrefixList]) -> list[dict]:
    """One row per list for the HTML 'lists' table."""
    return [{"account": pl.account, "profile": pl.profile, "region": pl.region,
             "prefix_list_id": pl.prefix_list_id, "prefix_list_name": pl.name, "family": pl.family,
             "ownership": pl.ownership, "owner": pl.owner, "state": pl.state, "entries": len(pl.entries),
             "max_entries": pl.max_entries if pl.max_entries is not None else "",
             "utilisation": pl.utilisation if pl.utilisation is not None else "",
             "associations": "" if pl.associations is None else len(pl.associations),
             "resources": pl.resources()} for pl in sorted(lists, key=lambda p: (p.account, p.region, p.name))]


def payload(lists: list[PrefixList], findings: list[Finding], stats: dict) -> dict:
    """JSON report: stats, every list with its entries and associations, and the findings."""
    return {"stats": stats,
            "lists": [{**asdict(pl), "utilisation": pl.utilisation} for pl in lists],
            "findings": [asdict(f) for f in findings]}


def print_report(lists: list[PrefixList], findings: list[Finding], stats: dict, show_info: bool) -> None:
    """Print the text report: run totals, then findings grouped by account / region / list."""
    print()
    print(f"Accounts scanned: {stats['accounts']}   skipped: {stats['accounts_skipped']}   "
          f"regions: {stats['regions']}   prefix lists: {stats['prefix_lists']}")
    if stats["by_code"]:
        print("Findings: " + "   ".join(f"{k}: {v}" for k, v in stats["by_code"].items()))
    shown = [f for f in findings if show_info or f.severity != "info"]
    if not shown:
        print("\nNo issues found.")
    cur = None
    for f in shown:
        hdr = (f.account, f.region, f.prefix_list_id)
        if hdr != cur:
            cur = hdr
            if f.prefix_list_id:
                size = f"{f.entries}/{f.max_entries if f.max_entries is not None else '-'} entries"
                assoc = "associations unknown" if f.associations is None else f"{f.associations} association(s)"
                print(f"\n{f.account} {f.region}  {f.prefix_list_id} {f.prefix_list_name}  ({size}, {assoc})")
            else:
                print(f"\n{f.account} {f.region}".rstrip())
        print(f"    [{f.severity.upper():<5}] {f.code}  {f.detail}")
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"\n({hidden} info findings hidden; --show-info to list)")


def render_html(lists: list[PrefixList], findings: list[Finding], stats: dict) -> str:
    """Interactive HTML report: run totals, a findings table and a table of every list."""
    sev = Counter(f.severity for f in findings)
    cards = [(stats["accounts"], "accounts scanned"), (stats["accounts_skipped"], "accounts skipped"),
             (stats["regions"], "regions"), (stats["prefix_lists"], "prefix lists")]
    cards += [(sev.get(s, 0), f"{s} findings") for s in ("error", "warn", "info")]
    meta = [f"Generated {dt.datetime.now():%Y-%m-%d %H:%M:%S}"]
    findings_table = {
        "id": "findings", "title": "Findings", "row_label": "findings",
        "columns": [["severity", "Severity"], ["code", "Code"], ["account", "Account"], ["region", "Region"],
                    ["prefix_list_id", "Prefix list"], ["prefix_list_name", "Name"], ["owner", "Owner"],
                    ["entries", "Entries"], ["max_entries", "Max"], ["associations", "Associations"],
                    ["detail", "Detail"]],
        "rows": [asdict(f) for f in findings],
        "filters": ["severity", "code", "account", "region", "prefix_list_name"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["prefix_list_id", "Lists"],
                 ["code", "Finding codes"]],
        "wrap": ["detail"],
        "badges": {"severity": SEVERITY_BADGES},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["severity", 1], ["account", 1], ["region", 1]],
        "hide": {"key": "severity", "values": ["info"], "label": "show info"},
        "by": {"key": "code", "label": "By code", "badge": "severity"},
    }
    lists_table = {
        "id": "lists", "title": "Prefix lists", "row_label": "lists",
        "note": "Utilisation is entries / MaxEntries. Associations are blank when they could not be read "
                "(usually lists shared in from another account).",
        "columns": [["account", "Account"], ["region", "Region"], ["prefix_list_id", "Prefix list"],
                    ["prefix_list_name", "Name"], ["family", "Family"], ["ownership", "Ownership"],
                    ["owner", "Owner"], ["state", "State"], ["entries", "Entries"], ["max_entries", "Max"],
                    ["utilisation", "Used %"], ["associations", "Associations"], ["resources", "Resources"]],
        "rows": list_rows(lists),
        "filters": ["account", "region", "family", "ownership", "state", "prefix_list_name"],
        "uniq": [["account", "Accounts"], ["region", "Regions"], ["prefix_list_name", "Names"]],
        "wrap": ["resources"],
        "badges": {"ownership": {"owned": "ok", "shared": "info", "aws": "info"}},
        "sort": [["utilisation", -1]],
        "by": {"key": "ownership", "label": "By ownership", "badge": None},
    }
    return html_report.render("Prefix list audit", meta=meta, cards=cards, tables=[findings_table, lists_table])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 clean, 1 error/warn findings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Audit managed prefix lists: capacity, usage, sizing, overlaps and drift between "
                    "same-named copies across accounts and regions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-admin --region us-east-1
  %(prog)s --all-accounts --region us-east-1,ca-central-1 --name 'corp-*'
  %(prog)s --account 111122223333 --all-regions --include-shared
""")
    add_account_args(p)
    p.add_argument("--region", action="append",
                   help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true", help="Every enabled region")
    p.add_argument("--name", action="append", metavar="GLOB",
                   help="Only lists whose name matches this glob (repeatable), e.g. 'corp-*'")
    p.add_argument("--include-shared", action="store_true",
                   help="Also audit lists shared into the account via RAM (owned by another account)")
    p.add_argument("--include-aws", action="store_true",
                   help="Also include AWS-managed lists (state and usage only)")
    p.add_argument("--headroom", type=int, default=int(os.getenv("PL_HEADROOM", DEFAULT_HEADROOM)),
                   help=f"Flag lists within N entries of MaxEntries (default {DEFAULT_HEADROOM}, env PL_HEADROOM)")
    p.add_argument("--full-pct", type=float, default=float(os.getenv("PL_FULL_PCT", DEFAULT_FULL_PCT)),
                   help=f"Also flag lists at or above this utilisation %% (default {DEFAULT_FULL_PCT}, "
                        f"env PL_FULL_PCT)")
    p.add_argument("--show-info", action="store_true", help="Show info findings in the text report")
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        regions = resolve_regions(args.profile, args.region, args.all_regions, service="ec2")
        targets = select_accounts(args)
        lists, findings, stats = run(args, regions, targets)
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2

    accounts = sorted({t.account for t in targets})
    slug = "_".join(accounts) if len(accounts) <= 3 else f"{len(accounts)}accounts"
    paths = report_paths(args, TOOL, f"pl_{slug}")
    data = payload(lists, findings, stats)
    if paths["json"]:
        write_json(paths["json"], data)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(f) for f in findings], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(lists, findings, stats))

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print_report(lists, findings, stats, args.show_info)
        print_saved(paths)
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
