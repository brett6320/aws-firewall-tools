#!/usr/bin/env python3
"""
Security group migration check.

Intent: before removing an old security group in favour of a new one, find
everything the old group is attached to, check that the new group is
attached there too, and show exactly what access each resource would lose
(or gain) when the old group is removed - so the removal can be signed off
per resource instead of hoped for.

What it does:

  1. Takes the old group(s) (--old) and the new group(s) (--new) as ids or
     ARNs, in one or more accounts (several accounts via ARNs).
  2. Finds every network interface the old group is attached to: EC2
     instances, Lambda functions, load balancers, RDS, VPC endpoints, EFS
     mount targets ... (each labelled from its interface metadata, best
     effort; requester-managed interfaces are changed through their service).
  3. For each resource, with its access computed exactly from the rules of
     the groups attached (protocol x ports x addresses, prefix lists
     expanded, lib/boxes.py):
       * whether the new group(s) are attached, and in the resource's VPC
       * the access lost if the old group(s) are removed from the groups
         attached today, and the old rules responsible
       * when a new group is not attached yet, the projected change if it
         were attached and the old removed: access lost and access gained
     Status per resource:
       * READY             new attached, removing old loses nothing
       * ACCESS_LOST       new attached, but removing old loses access
       * NEW_NOT_ATTACHED  new not attached (projected change shown)
       * OLD_REDUNDANT     new not attached, but removing old loses nothing
       * NEW_IN_OTHER_VPC  a new group is in another VPC than the resource
  4. Lists rules in other groups that reference the old group ("from
     sg-old"), and whether the same rule exists referencing the new group;
     REFERENCE_NOT_MIRRORED means migrated resources would lose that access.

References to an old group are treated as references to its new group
(paired by position when as many new as old groups are given, or all to the
single new group), so "from sg-old" becoming "from sg-new" is not reported as
a change. --no-equate-references turns this off.

Accounts: each account is read with its own profile, as in
sg_rule_inventory.py: --profile for its own account, other accounts named by
ARNs through their local profiles (never -priv / -cpar), bare ids in the
--profile account, else the single ARN account, else AWS_PROFILE / default.

Resources whose change is identical (status, access lost / gained, rules
responsible) are listed together as one group in the text and HTML reports;
the CSV / JSON keep one row per resource with its group id.

Reports: text summary on screen (--show-changes lists the access changes),
plus auto-saved HTML (interactive: filter by status, resource type, VPC ...),
CSV (one row per resource) and JSON under reports/sg_migration_check/DATE/.

Usage:

    ./sg_migration_check.py --old sg-0123456789abcdef0 --new sg-0fedcba9876543210 --region us-east-1
    ./sg_migration_check.py --old arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \\
        --new arn:aws:ec2:us-east-1:111122223333:security-group/sg-0fedcba9876543210 --show-changes

Exit codes: 0 every resource READY (or none attached), 1 anything else to
review, 2 fatal error.

Read-only. Only Describe / Get calls are made.
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

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import add_profile_args, check_profile_args  # noqa: E402
from lib.aws_common import _g, err_text, get_client  # noqa: E402
from lib.boxes import Box, fmt_addrs, fmt_proto_ports, intersects, merge, remainder  # noqa: E402
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, print_saved, report_paths,  # noqa: E402
                        setup_logging, write_csv, write_json, write_text)
from lib.security_groups import (SG, SgRule, load_groups, parse_account_targets,  # noqa: E402
                                 resolve_account_profiles, split_specs, spec_accounts)

log = logging.getLogger("sg_migration_check")
TOOL = "sg_migration_check"
MAX_CIDRS_SHOWN = 8
Access = dict[str, list[Box]]          # address space -> disjoint boxes


# --------------------------------------------------------------------------- #
# Access arithmetic
# --------------------------------------------------------------------------- #
def access_of(gids: list[str], rules: dict[str, list[SgRule]], egress: bool, rename: dict[str, str]) -> Access:
    """Union of the access granted by the groups' rules in one direction, as disjoint boxes per
    address space. Group-reference spaces are renamed with `rename` (old -> new)."""
    acc: Access = defaultdict(list)
    for gid in gids:
        for r in rules.get(gid, []):
            if r.egress != egress:
                continue
            for sp, b in r.boxes:
                sp = rename.get(sp, sp)
                acc[sp].extend(remainder(b, acc[sp]))
    return {sp: merge(bs) for sp, bs in acc.items() if bs}


def minus(a: Access, b: Access) -> Access:
    """Access in a that is not in b."""
    out = {}
    for sp, boxes in a.items():
        rest = [p for x in boxes for p in remainder(x, b.get(sp, []))]
        if rest:
            out[sp] = merge(rest)
    return out


def fmt_access(acc: Access, egress: bool, rename: dict[str, str] | None = None) -> list[str]:
    """'tcp 443 from 10.0.0.0/8, ...' lines, one per protocol / ports. A reference that stands
    for an old group and its new group reads 'sg-new / sg-old'."""
    prep = "to" if egress else "from"
    was = defaultdict(list)
    for old, new in (rename or {}).items():
        was[new].append(old[3:])
    by_pp = defaultdict(list)
    for sp, boxes in sorted(acc.items()):
        for pr, ports, addr in boxes:
            by_pp[(pr, ports)].extend(f"{a} / {' / '.join(was[sp])}" if sp in was else a for a in fmt_addrs(sp, addr))
    return [f"{fmt_proto_ports(pr, ports)} {prep} {', '.join(a)}" for (pr, ports), a in sorted(by_pp.items())]


def responsible(acc: Access, gids: list[str], rules: dict[str, list[SgRule]], egress: bool,
                rename: dict[str, str]) -> list[str]:
    """Rules of `gids` that grant part of `acc`."""
    out = []
    for gid in gids:
        for r in rules.get(gid, []):
            if r.egress == egress and any(intersects(b, x) for sp, b in r.boxes for x in acc.get(rename.get(sp, sp), [])):
                out.append(f"{gid} {r.rule_id} {r}" + (f' "{r.description}"' if r.description else ""))
    return out


# --------------------------------------------------------------------------- #
# Resources
# --------------------------------------------------------------------------- #
def resource_of(n: dict) -> tuple[str, str]:
    """(resource type, label) for a network interface, from its attachment, type and
    description (best effort)."""
    att, kind, desc = _g(n, "Attachment", {}), n.get("InterfaceType") or "interface", n.get("Description") or ""
    if att.get("InstanceId"):
        return "ec2-instance", att["InstanceId"]
    if kind == "lambda" or desc.startswith("AWS Lambda VPC ENI-"):
        name = desc[len("AWS Lambda VPC ENI-"):]
        parts = name.split("-")
        return "lambda", "-".join(parts[:-5]) if len(parts) > 5 else name or n["NetworkInterfaceId"]
    if desc.startswith("ELB "):
        return "load-balancer", desc[4:]
    if desc.startswith("RDSNetworkInterface"):
        return "rds", desc
    if kind == "vpc_endpoint" or desc.startswith("VPC Endpoint Interface"):
        return "vpc-endpoint", desc.split()[-1] if desc else n["NetworkInterfaceId"]
    if desc.startswith("EFS mount target"):
        return "efs", desc
    if n.get("RequesterManaged"):
        return f"managed ({n.get('RequesterId', '?')})", desc or n["NetworkInterfaceId"]
    return kind, desc or n["NetworkInterfaceId"]


def find_interfaces(session, old_ids: list[str]) -> list[dict]:
    """Network interfaces with any of the old groups attached."""
    ec2 = get_client("ec2", session)
    out = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "group-id", "Values": old_ids}]):
        out.extend(_g(page, "NetworkInterfaces", []))
    return out


def find_references(session, old_ids: list[str]) -> dict[str, list[dict]]:
    """Groups (same account and region, other than the old ones) with a rule referencing an old
    group: {group_id: all its SecurityGroupRule dicts}, so a mirroring rule can be found."""
    ec2 = get_client("ec2", session)
    gids = set()
    for name in ("ip-permission.group-id", "egress.ip-permission.group-id"):
        for page in ec2.get_paginator("describe_security_groups").paginate(
                Filters=[{"Name": name, "Values": old_ids}]):
            gids |= {g["GroupId"] for g in _g(page, "SecurityGroups", [])}
    gids -= set(old_ids)                      # an old group's references to itself go with it
    out: dict[str, list[dict]] = defaultdict(list)
    if gids:
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": sorted(gids)}]):
            for r in _g(page, "SecurityGroupRules", []):
                out[r["GroupId"]].append(r)
    return out


@dataclass
class ResourceRow:
    """One network interface carrying an old group, and what removing the old group does."""
    severity: str
    status: str
    resource_type: str
    resource: str
    eni_id: str
    account: str
    region: str
    vpc_id: str
    groups: list[str]
    old_attached: list[str]
    new_attached: list[str]
    new_missing: list[str]
    lost: list[str] = field(default_factory=list)              # removing old, groups as attached today
    lost_rules: list[str] = field(default_factory=list)
    projected_lost: list[str] = field(default_factory=list)    # new attached + old removed
    projected_gained: list[str] = field(default_factory=list)
    detail: str = ""
    managed_by: str = ""             # requester of a requester-managed interface
    change_group: str = ""           # resources with identical access changes share a group (G1, G2 ...)


CSV_COLUMNS = list(ResourceRow.__dataclass_fields__)


def review(n: dict, account: str, region: str, olds: list[str], news: list[str], groups: dict[str, SG],
           rules: dict[str, list[SgRule]], rename: dict[str, str]) -> ResourceRow:
    """The migration status of one network interface."""
    cur = [g["GroupId"] for g in _g(n, "Groups", [])]
    old_here = [g for g in olds if g in cur]
    new_here, new_missing = [g for g in news if g in cur], [g for g in news if g not in cur]
    after = [g for g in cur if g not in old_here]
    projected = after + [g for g in new_missing if g not in after]
    rtype, label = resource_of(n)
    lost, lost_rules, plost, pgained = [], [], [], []
    for egress in (False, True):
        before_acc = access_of(cur, rules, egress, rename)
        gone = minus(before_acc, access_of(after, rules, egress, rename))
        lost += [f"[{'egress' if egress else 'ingress'}] {x}" for x in fmt_access(gone, egress, rename)]
        lost_rules += responsible(gone, old_here, rules, egress, rename)
        if new_missing:
            proj = access_of(projected, rules, egress, rename)
            plost += [f"[{'egress' if egress else 'ingress'}] {x}" for x in fmt_access(minus(before_acc, proj), egress, rename)]
            pgained += [f"[{'egress' if egress else 'ingress'}] {x}" for x in fmt_access(minus(proj, before_acc), egress, rename)]
    vpc = n.get("VpcId", "")
    other_vpc = [g for g in news if g in groups and groups[g].vpc_id and groups[g].vpc_id != vpc]
    if other_vpc:
        status, sev, detail = "NEW_IN_OTHER_VPC", "error", (
            "; ".join(f"{g} is in {groups[g].vpc_id}" for g in other_vpc) +
            ", not the resource's VPC; cannot be attached here")
    elif not new_missing:
        status, sev, detail = (("ACCESS_LOST", "error", "new group attached, but removing the old group loses access")
                               if lost else ("READY", "info", "new group attached; removing the old group loses nothing"))
    elif lost:
        status, sev, detail = "NEW_NOT_ATTACHED", "error", (
            "new group not attached; removing the old group now loses access" +
            ("" if plost else "; with the new group attached nothing would be lost"))
    else:
        status, sev, detail = "OLD_REDUNDANT", "warn", ("new group not attached, but removing the old group loses "
                                                        "nothing: other groups attached already grant its access")
    return ResourceRow(sev, status, rtype, label, n["NetworkInterfaceId"], account, region, vpc, cur, old_here,
                       new_here, new_missing, lost, lost_rules, plost, pgained, detail,
                       n.get("RequesterId", "?") if n.get("RequesterManaged") else "")


def change_groups(rows: list[ResourceRow]) -> list[dict]:
    """Resources whose access change is identical (status, missing new groups, access lost /
    gained and the rules responsible) as one group each; sets each row's change_group."""
    groups: dict[str, list[ResourceRow]] = {}
    for r in sorted(rows, key=lambda r: (SEVERITY_ORDER[r.severity], r.status, r.resource_type, r.resource, r.eni_id)):
        key = json.dumps([r.status, r.new_missing, r.lost, r.lost_rules, r.projected_lost, r.projected_gained, r.detail])
        groups.setdefault(key, []).append(r)
    out = []
    for i, rs in enumerate(groups.values(), 1):
        gid, r = f"G{i}", rs[0]
        for x in rs:
            x.change_group = gid
        out.append({
            "change_group": gid, "severity": r.severity, "status": r.status, "count": len(rs),
            "resources": [f"{x.resource_type} {x.resource} ({x.eni_id}, {x.vpc_id}"
                          + (f", managed by {x.managed_by}" if x.managed_by else "") + ")" for x in rs],
            "resource_types": sorted({x.resource_type for x in rs}), "vpcs": sorted({x.vpc_id for x in rs}),
            "accounts": sorted({x.account for x in rs}), "new_missing": r.new_missing, "lost": r.lost,
            "lost_rules": r.lost_rules, "projected_lost": r.projected_lost, "projected_gained": r.projected_gained,
            "detail": r.detail + ("; requester-managed interfaces are changed through their service"
                                  if any(x.managed_by for x in rs) else "")})
    return out


def check_references(by_group: dict[str, list[dict]], old_ids: list[str], account: str, region: str,
                     rename: dict[str, str]) -> list[dict]:
    """For each rule referencing an old group, whether the same group has the same rule (direction,
    protocol / ports) referencing the old group's new group."""
    out = []
    for gid, rs in by_group.items():
        parsed = [SgRule.from_api(r) for r in rs]
        for r in parsed:
            if r.peer not in old_ids:
                continue
            old = r.peer
            new = rename.get(f"sg:{old}", "")[3:]
            same = new and any(o.peer == new and o.egress == r.egress and o.key()[1] == r.key()[1] for o in parsed)
            out.append({"severity": "info" if same else "warn",
                        "status": "REFERENCE_MIRRORED" if same else "REFERENCE_NOT_MIRRORED",
                        "account": account, "region": region, "group_id": gid, "rule_id": r.rule_id,
                        "direction": r.direction, "rule": str(r), "description": r.description,
                        "references": old, "new_group": new,
                        "detail": (f"a matching rule references {new}" if same else
                                   f"no matching rule references {new or 'a new group'}; resources moved to the new "
                                   f"group lose this access")})
    return out


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def cut(lines: list[str]) -> list[str]:
    """Lines with their address lists cut at MAX_CIDRS_SHOWN."""
    out = []
    for x in lines:
        head, sep, addrs = x.rpartition(" from " if " from " in x else " to ")
        a = addrs.split(", ")
        out.append(f"{head}{sep}{', '.join(a[:MAX_CIDRS_SHOWN])}" +
                   (f", ... {len(a) - MAX_CIDRS_SHOWN} more" if len(a) > MAX_CIDRS_SHOWN else ""))
    return out


def print_report(payload: dict, rows: list[ResourceRow], cgroups: list[dict], refs: list[dict], show: bool) -> None:
    """Summary per group of resources with identical access changes; the changes and responsible
    rules only with `show`."""
    print()
    for a in payload["accounts"]:
        print(f"account {a['account']} via {('profile ' + a['profile']) if a['profile'] else 'default credentials'} "
              f"({a['profile_source']})")
    print(f"old: {', '.join(payload['old'])}   new: {', '.join(payload['new'])}")
    if payload["rename"]:
        print("references treated as equivalent: " + ", ".join(f"{o} -> {n}" for o, n in payload["rename"].items()))
    for w in payload["warnings"]:
        print(f"[WARN ] {w}")
    counts = defaultdict(int)
    for r in rows:
        counts[r.status] += 1
    print(f"\n{len(rows)} resource(s) with an old group attached: " +
          (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"))
    if rows:
        print(f"{len(cgroups)} distinct change(s); resources with identical changes are listed together")
    for g in cgroups:
        extra = f"  lost: {len(g['lost'])}" if g["lost"] else ""
        if g["new_missing"]:
            extra += f"  if new attached: -{len(g['projected_lost'])} / +{len(g['projected_gained'])}"
        print(f"  [{g['severity'].upper():<5}] {g['status']:<17} {g['change_group']}: {g['count']} resource(s){extra}")
        for x in g["resources"]:
            print(f"      {x}")
        if show:
            print(f"      {g['detail']}")
            for title, xs in (("lost if old removed", g["lost"]), ("old rules responsible", g["lost_rules"]),
                              ("if new attached, lost", g["projected_lost"]),
                              ("if new attached, gained", g["projected_gained"])):
                for x in (cut(xs) if "rules" not in title else xs):
                    print(f"      {title}: {x}")
    if refs:
        nm = sum(x["status"] == "REFERENCE_NOT_MIRRORED" for x in refs)
        print(f"\n{len(refs)} rule(s) in other groups reference an old group; {nm} without a matching rule for the new")
        for x in refs if show else [x for x in refs if x["status"] == "REFERENCE_NOT_MIRRORED"]:
            print(f"  [{x['severity'].upper():<5}] {x['status']:<22} {x['group_id']} {x['rule_id']} {x['rule']}")
    if not show:
        print("(--show-changes lists the access lost / gained per resource and the rules responsible)")


def render_html(payload: dict, rows: list[ResourceRow], cgroups: list[dict], refs: list[dict]) -> str:
    """Interactive HTML: one row per group of resources with identical access changes (filter by
    status, type, VPC ...) and the references."""
    status_badge = {"READY": "ok", "ACCESS_LOST": "error", "NEW_NOT_ATTACHED": "error", "NEW_IN_OTHER_VPC": "error",
                    "OLD_REDUNDANT": "warn", "REFERENCE_NOT_MIRRORED": "warn", "REFERENCE_MIRRORED": "ok"}
    tables = [{
        "id": "r", "title": "Resources with an old group attached", "row_label": "distinct changes",
        "note": "Resources with identical access changes share a row. Lost = access lost when the old group is "
                "removed from the groups attached today. Projected = if the missing new group were attached and "
                "the old removed. References to an old group count as references to its new group"
                + ("." if payload["rename"] else " (off).") + " The CSV / JSON have one row per resource.",
        "columns": [["severity", "Severity"], ["status", "Status"], ["count", "Resources"],
                    ["resources", "Resources (interface, VPC)"], ["resource_types", "Types"], ["vpcs", "VPCs"],
                    ["accounts", "Accounts"], ["new_missing", "New not attached"], ["lost", "Lost if old removed"],
                    ["lost_rules", "Old rules responsible"], ["projected_lost", "If new attached: lost"],
                    ["projected_gained", "If new attached: gained"], ["detail", "Detail"]],
        "rows": cgroups,
        "filters": ["severity", "status", "resource_types", "accounts", "vpcs", "new_missing"],
        "wrap": ["resources", "lost", "lost_rules", "projected_lost", "projected_gained", "detail"],
        "badges": {"severity": SEVERITY_BADGES, "status": status_badge},
        "order": {"severity": list(SEVERITY_ORDER)},
        "lines": ["resources", "lost", "lost_rules", "projected_lost", "projected_gained"],
        "uniq": [["resources", "resources"], ["resource_types", "types"], ["vpcs", "VPCs"], ["accounts", "accounts"]],
        "by": {"key": "status", "label": "By status", "badge": "severity"},
        "sort": [["severity", 1], ["status", 1], ["count", -1]]}]
    if refs:
        tables.append({
            "id": "x", "title": "Rules in other groups that reference an old group", "row_label": "rules",
            "columns": [["severity", "Severity"], ["status", "Status"], ["group_id", "Group"], ["rule_id", "Rule"],
                        ["direction", "Direction"], ["rule", "Rule text"], ["references", "References"],
                        ["new_group", "New group"], ["description", "Description"], ["detail", "Detail"]],
            "rows": refs, "filters": ["severity", "status", "group_id", "direction"], "wrap": ["detail", "description"],
            "badges": {"severity": SEVERITY_BADGES, "status": status_badge},
            "uniq": [["group_id", "groups"]], "sort": [["severity", 1], ["group_id", 1]]})
    counts = defaultdict(int)
    for r in rows:
        counts[r.status] += 1
    cards = [(len(rows), "interfaces"), (len({r.resource for r in rows}), "resources"),
             (len(cgroups), "distinct changes")] + [(v, k) for k, v in sorted(counts.items())] + \
        ([(sum(x["status"] == "REFERENCE_NOT_MIRRORED" for x in refs), "references not mirrored")] if refs else [])
    meta = ["Accounts: " + "; ".join(f"{a['account']} via {a['profile'] or 'default credentials'}" for a in payload["accounts"]),
            f"Old: {', '.join(payload['old'])} · New: {', '.join(payload['new'])} · generated {payload['generated']} · "
            "read-only report"]
    meta += [f"Warning: {w}" for w in payload["warnings"]]
    # many list columns: use the full window width
    return html_report.render("Security group migration check", meta=meta, cards=cards, tables=tables,
                              extra_html="<style>body{max-width:none}</style>")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 all READY, 1 something to review, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Check a security group migration: where the old group is attached, whether the new group is "
                    "attached there too, and the access each resource loses or gains when the old is removed. "
                    "Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --region us-east-1 --old sg-0123456789abcdef0 --new sg-0fedcba9876543210
  %(prog)s --old arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \\
           --new arn:aws:ec2:us-east-1:111122223333:security-group/sg-0fedcba9876543210 --show-changes
""")
    p.add_argument("--old", nargs="+", action="extend", required=True, metavar="SG",
                   help="Old security group id(s) / ARN(s) to be removed")
    p.add_argument("--new", nargs="+", action="extend", required=True, metavar="SG",
                   help="New security group id(s) / ARN(s) replacing them")
    p.add_argument("--profile", default=None,
                   help="AWS profile, used for its own account (and for bare ids). Other accounts named by ARNs "
                        "use their local profiles (never -priv/-cpar); with no ARNs, default AWS_PROFILE")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or None,
                   help="Region for bare ids (default AWS_REGION, then the profile's region)")
    p.add_argument("--no-equate-references", action="store_true",
                   help="Do not treat references to an old group as references to its new group")
    p.add_argument("--show-changes", action="store_true",
                   help="Text report: list the access lost / gained per resource and the rules responsible "
                        "(the HTML / CSV / JSON reports always include them)")
    add_profile_args(p)
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        specs = args.old + args.new
        arn_accounts = spec_accounts(specs)
        bare_ids = any(not t.startswith("arn:") for t in split_specs(specs))
        profiles, bare_account = resolve_account_profiles(args, arn_accounts, bare_ids)
        default_region = args.region or (boto3.Session(profile_name=profiles[bare_account][0]).region_name
                                         if bare_account else None)
        olds = [(a or bare_account, r, g) for a, r, g in parse_account_targets(args.old, default_region, False)]
        news = [(a or bare_account, r, g) for a, r, g in parse_account_targets(args.new, default_region, False)]
        if set(g for *_, g in olds) & set(g for *_, g in news):
            raise ValueError("a group cannot be both old and new")
        old_ids, new_ids = [g for *_, g in olds], [g for *_, g in news]
        pairs = dict(zip(old_ids, new_ids)) if len(old_ids) == len(new_ids) else \
            {o: new_ids[0] for o in old_ids} if len(new_ids) == 1 else {}
        rename = {} if args.no_equate_references else {f"sg:{o}": f"sg:{n}" for o, n in pairs.items()}
        warnings = []
        if not args.no_equate_references and not pairs:
            warnings.append("references not equated: give one new group, or as many new as old groups")

        def session(account, region):
            """boto3 session for the account's profile in `region`."""
            return boto3.Session(profile_name=profiles[account][0], region_name=region)

        interfaces, refs = [], []                 # (account, region, eni dict)
        for account, region in dict.fromkeys((a, r) for a, r, _ in olds):
            ids = [g for a, r, g in olds if (a, r) == (account, region)]
            s = session(account, region)
            interfaces += [(account, region, n) for n in find_interfaces(s, ids)]
            refs += check_references(find_references(s, ids), ids, account, region,
                                     rename or {f"sg:{o}": f"sg:{n}" for o, n in pairs.items()})
        # load every group attached to those interfaces, plus the old and new groups
        wanted = defaultdict(set)
        for a, r, g in olds + news:
            wanted[(a, r)].add(g)
        for a, r, n in interfaces:
            wanted[(a, r)] |= {g["GroupId"] for g in _g(n, "Groups", [])}
        groups, rules = {}, {}
        for (a, r), gids in wanted.items():
            gs, rs, ws = load_groups(lambda reg, a=a: session(a, reg), [(r, g) for g in sorted(gids)])
            groups.update({g.group_id: g for g in gs})
            rules.update(rs)
            warnings += [f"prefix list {w}; matched by id only" for w in ws]
        for gid, rs in rules.items():               # self-references are references to the group itself
            for x in rs:
                if x.peer == "self":
                    x.boxes = [(f"sg:{gid}", b) for _, b in x.boxes]
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e) if isinstance(e, ClientError) else e)
        return 2

    rows = [review(n, a, r, old_ids, new_ids, groups, rules, rename) for a, r, n in interfaces]
    cgroups = change_groups(rows)
    used = sorted({a for a, _, _ in olds + news})
    payload = {"generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "accounts": [{"account": a, "profile": profiles[a][0], "profile_source": profiles[a][1]} for a in used],
               "old": old_ids, "new": new_ids, "rename": {o: n for o, n in pairs.items()} if rename else {},
               "groups": [asdict(g) for g in groups.values()], "warnings": warnings,
               "resources": [asdict(r) for r in rows], "change_groups": cgroups, "references": refs}
    paths = report_paths(args, TOOL, f"sgmigration_{old_ids[0]}_to_{new_ids[0]}")
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(r) for r in rows], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(payload, rows, cgroups, refs))
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(payload, rows, cgroups, refs, args.show_changes)
        print_saved(paths)
    ok = all(r.status == "READY" for r in rows) and not any(x["status"] == "REFERENCE_NOT_MIRRORED" for x in refs)
    return 0 if ok and not warnings else 1


if __name__ == "__main__":
    sys.exit(main())
