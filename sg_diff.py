#!/usr/bin/env python3
"""
Security group rule diff.

Finds access granted by a "left" security group that the "right" security
group(s) do not grant. Groups are given as ARNs or group IDs, all in one
account; the first is the left group and every further group is a right
group. With several right groups, left access is checked against their
combined access (as if all were attached to the same ENI), so a range split
across two right groups counts as granted. Ingress and egress are checked
separately. Access the right groups grant beyond the left is not reported.

Rules are compared by the access they grant, not by how they are written:

  * each rule becomes a set of (protocol x port/ICMP range x address range)
    boxes; prefix lists are expanded to their current CIDR entries
  * a left rule is MISSING when nothing in the right groups overlaps it
  * PARTIAL when the right groups grant only part of it
  * for both, `uncovered` is the exact absent access (CIDRs, ports, ICMP)
  * COVERED (info) when the right groups grant all of it through different
    rules (a prefix list vs. its CIDRs, a /16 vs. two /17s, a broader rule)
  * IDENTICAL (info) when a right group has the same rule
    (protocol, ports and peer; descriptions are ignored)

Security group references are matched by group ID (a self-reference in the
left group matches a self-reference in any right group). Prefix lists that cannot be read are
compared by ID only and reported. Descriptions are shown for reference only.

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Region for bare group IDs when --region not given (ARNs carry their own)
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_drift.py).
truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from fmm_parity import _g, get_client  # noqa: E402  (also loads .env)

log = logging.getLogger("sg_diff")

ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):security-group/(sg-[0-9a-f]+)$")
ID_RE = re.compile(r"^sg-[0-9a-f]{8,17}$")

PROTO_NUMS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
PROTO_NAMES = {v: k for k, v in PROTO_NUMS.items()}
ALL_PROTOS = (0, 255)
ALL_PORTS = (0, 65535)
SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}
MAX_CIDRS_SHOWN = 8

Interval = tuple[int, int]
Box = tuple[Interval, Interval, Interval]   # protocol, port (or ICMP type*256+code), address


# --------------------------------------------------------------------------- #
# Box arithmetic
# --------------------------------------------------------------------------- #
def intersects(a: Box, b: Box) -> bool:
    return all(x[0] <= y[1] and y[0] <= x[1] for x, y in zip(a, b))


def subtract(a: Box, b: Box) -> list[Box]:
    """a minus b, as disjoint boxes."""
    if not intersects(a, b):
        return [a]
    out, cur = [], list(a)
    for d in range(len(a)):
        lo, hi = cur[d]
        blo, bhi = b[d]
        if lo < blo:
            out.append(tuple(cur[:d] + [(lo, blo - 1)] + cur[d + 1:]))
            lo = blo
        if hi > bhi:
            out.append(tuple(cur[:d] + [(bhi + 1, hi)] + cur[d + 1:]))
            hi = bhi
        cur[d] = (lo, hi)
    return out


def merge(boxes) -> list[Box]:
    """Coalesce boxes that differ in one dimension only and touch or overlap there."""
    boxes = set(boxes)
    changed = True
    while changed:
        changed = False
        for d in range(3):
            groups = defaultdict(list)
            for b in boxes:
                groups[b[:d] + b[d + 1:]].append(b[d])
            merged_set = set()
            for rest, ivs in groups.items():
                ivs.sort()
                merged = [ivs[0]]
                for lo, hi in ivs[1:]:
                    if lo <= merged[-1][1] + 1:
                        merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
                    else:
                        merged.append((lo, hi))
                changed |= len(merged) < len(ivs)
                merged_set.update(rest[:d] + (iv,) + rest[d:] for iv in merged)
            boxes = merged_set
    return sorted(boxes)


def remainder(box: Box, others: list[Box]) -> list[Box]:
    pieces = [box]
    for o in others:
        pieces = [q for p in pieces for q in subtract(p, o)]
        if not pieces:
            break
    return pieces


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def proto_num(p) -> int | None:
    """None = all protocols."""
    s = str(p).strip().lower()
    if s in ("-1", "all", ""):
        return None
    return PROTO_NUMS[s] if s in PROTO_NUMS else int(s)


def proto_port_box(proto, from_port, to_port) -> tuple[Interval, Interval]:
    p = proto_num(proto)
    if p is None:
        return ALL_PROTOS, ALL_PORTS
    if p in (6, 17):
        if from_port in (None, -1):
            return (p, p), ALL_PORTS
        return (p, p), (from_port, to_port)
    if p in (1, 58):            # FromPort = ICMP type, ToPort = code, -1 = any
        if from_port in (None, -1):
            return (p, p), ALL_PORTS
        if to_port in (None, -1):
            return (p, p), (from_port * 256, from_port * 256 + 255)
        return (p, p), (from_port * 256 + to_port,) * 2
    return (p, p), ALL_PORTS


def fmt_proto_ports(pr: Interval, ports: Interval) -> str:
    if pr == ALL_PROTOS:
        return "all traffic"
    if pr[0] != pr[1]:
        return f"protocols {pr[0]}-{pr[1]}" + ("" if ports == ALL_PORTS else f" ports {ports[0]}-{ports[1]}")
    p = pr[0]
    name = PROTO_NAMES.get(p, f"proto {p}")
    if ports == ALL_PORTS:
        return f"{name} all" if p in PROTO_NAMES else name
    if p in (1, 58):
        def tc(v):
            return f"{v // 256}/{v % 256}"
        lo, hi = ports
        if lo % 256 == 0 and hi == lo + 255:
            return f"{name} type {lo // 256}"
        if lo == hi:
            return f"{name} type {lo // 256} code {lo % 256}"
        if lo % 256 == 0 and hi % 256 == 255:
            return f"{name} types {lo // 256}-{hi // 256}"
        return f"{name} type/code {tc(lo)}-{tc(hi)}"
    return f"{name} {ports[0]}" if ports[0] == ports[1] else f"{name} {ports[0]}-{ports[1]}"


def addr_interval(net) -> Interval:
    return int(net.network_address), int(net.broadcast_address)


def fmt_addrs(space: str, iv: Interval) -> list[str]:
    if space not in ("ipv4", "ipv6"):
        return [space.split(":", 1)[1]]
    cls = ipaddress.IPv4Address if space == "ipv4" else ipaddress.IPv6Address
    return [str(n) for n in ipaddress.summarize_address_range(cls(iv[0]), cls(iv[1]))]


@dataclass
class SG:
    group_id: str
    name: str
    vpc_id: str
    owner: str
    region: str

    def __str__(self):
        return f"{self.group_id} ({self.name}, {self.vpc_id}, {self.region})"


@dataclass
class SgRule:
    group_id: str
    rule_id: str
    egress: bool
    proto: str
    from_port: int | None
    to_port: int | None
    peer: str            # CIDR, pl-..., sg-..., or "self"
    peer_kind: str       # ipv4 | ipv6 | pl | sg
    description: str = ""
    peer_label: str = ""
    boxes: list[tuple[str, Box]] = field(default_factory=list)

    @classmethod
    def from_api(cls, r: dict) -> "SgRule":
        gid = r["GroupId"]
        if r.get("CidrIpv4"):
            kind, peer = "ipv4", str(ipaddress.ip_network(r["CidrIpv4"], strict=False))
        elif r.get("CidrIpv6"):
            kind, peer = "ipv6", str(ipaddress.ip_network(r["CidrIpv6"], strict=False))
        elif r.get("PrefixListId"):
            kind, peer = "pl", r["PrefixListId"]
        else:
            ref = _g(r, "ReferencedGroupInfo", {})
            kind, peer = "sg", ref.get("GroupId", "?")
            if peer == gid:
                peer = "self"
        return cls(group_id=gid, rule_id=r.get("SecurityGroupRuleId", ""), egress=bool(r.get("IsEgress")),
                   proto=str(r.get("IpProtocol", "-1")), from_port=r.get("FromPort"), to_port=r.get("ToPort"),
                   peer=peer, peer_kind=kind, description=r.get("Description") or "")

    @property
    def direction(self) -> str:
        return "egress" if self.egress else "ingress"

    def key(self) -> tuple:
        return (self.egress, proto_port_box(self.proto, self.from_port, self.to_port), self.peer)

    def expand(self, prefix_lists: dict[str, list[str] | None]) -> None:
        pr, ports = proto_port_box(self.proto, self.from_port, self.to_port)
        if self.peer_kind in ("ipv4", "ipv6"):
            cidrs = [self.peer]
        elif self.peer_kind == "pl" and prefix_lists.get(self.peer) is not None:
            cidrs = prefix_lists[self.peer]
        else:
            self.boxes = [(f"{self.peer_kind}:{self.peer}", (pr, ports, (0, 0)))]
            return
        self.boxes = []
        for c in cidrs:
            net = ipaddress.ip_network(c, strict=False)
            self.boxes.append((f"ipv{net.version}", (pr, ports, addr_interval(net))))

    def __str__(self) -> str:
        pr, ports = proto_port_box(self.proto, self.from_port, self.to_port)
        prep = "to" if self.egress else "from"
        peer = f"{self.peer} ({self.peer_label})" if self.peer_label else self.peer
        return f"{fmt_proto_ports(pr, ports)} {prep} {peer}"

    def ref(self) -> str:
        d = f' "{self.description}"' if self.description else ""
        return f"{self.group_id} {self.rule_id} {self}{d}"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str            # error | warn | info
    code: str
    left: str = ""
    right: str = ""          # right group ids, comma-separated
    direction: str = ""
    rule_id: str = ""        # left rule
    rule: str = ""
    description: str = ""
    uncovered: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


def fmt_remainder(rem: dict[str, list[Box]], egress: bool) -> list[str]:
    prep = "to" if egress else "from"
    by_pp = defaultdict(list)
    for space, boxes in rem.items():
        for pr, ports, addr in boxes:
            by_pp[(pr, ports)].extend(fmt_addrs(space, addr))
    return [f"{fmt_proto_ports(pr, ports)} {prep} {', '.join(addrs)}"
            for (pr, ports), addrs in sorted(by_pp.items())]


def compare_rules(rules: list[SgRule], others: list[SgRule], left: SG, rights: list[SG],
                  direction: str) -> list[Finding]:
    """Check each left rule's access against the combined access of the right groups' rules (`others`)."""
    out = []
    right_ids = ", ".join(g.group_id for g in rights)
    for r in rules:
        base = dict(left=left.group_id, right=right_ids, direction=direction, rule_id=r.rule_id, rule=str(r),
                    description=r.description)
        same = [o for o in others if o.key() == r.key()]
        if same:
            out.append(Finding("info", "IDENTICAL", related=[o.ref() for o in same], **base))
            continue
        overlapping: dict[str, SgRule] = {}
        rem: dict[str, list[Box]] = defaultdict(list)
        for space, box in r.boxes:
            hits = []
            for o in others:
                for osp, ob in o.boxes:
                    if osp == space and intersects(box, ob):
                        hits.append(ob)
                        overlapping[o.rule_id] = o
            rem[space].extend(remainder(box, hits))
        rem = {sp: merge(bs) for sp, bs in rem.items() if bs}
        related = [o.ref() for o in overlapping.values()]
        if not overlapping:
            note = "; prefix list unresolved, compared by id only" if r.peer_kind == "pl" and \
                r.boxes[0][0].startswith("pl:") else ""
            out.append(Finding("error", "MISSING", uncovered=fmt_remainder(rem, r.egress),
                               detail=f"nothing in {right_ids} grants any of this{note}", **base))
        elif not rem:
            out.append(Finding("info", "COVERED", related=related,
                               detail=f"fully granted by different rule(s) in {right_ids}", **base))
        else:
            out.append(Finding("error", "PARTIAL", uncovered=fmt_remainder(rem, r.egress), related=related,
                               detail=f"only partly granted by {right_ids}", **base))
    return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.code != "MISSING"))


def diff_groups(groups: list[SG], rules: dict[str, list[SgRule]]) -> tuple[list[Finding], list[dict]]:
    left, rights = groups[0], groups[1:]
    findings = []
    row = {"left": left.group_id, "right": ", ".join(g.group_id for g in rights)}
    for egress, direction in ((False, "ingress"), (True, "egress")):
        a = [r for r in rules[left.group_id] if r.egress == egress]
        b = [r for g in rights for r in rules[g.group_id] if r.egress == egress]
        fs = compare_rules(a, b, left, rights, direction)
        gaps = sum(f.code in ("MISSING", "PARTIAL") for f in fs)
        row[direction] = (f"{gaps} gap(s)" if gaps
                          else "covered" if any(f.code == "COVERED" for f in fs) else "identical")
        findings.extend(fs)
    return findings, [row]


# --------------------------------------------------------------------------- #
# AWS
# --------------------------------------------------------------------------- #
def parse_targets(specs: list[str], default_region: str | None) -> tuple[list[tuple[str, str]], str | None]:
    """-> [(region, group_id)], account from ARNs (None if only IDs)."""
    targets, accounts = [], set()
    for spec in (s.strip() for x in specs for s in x.split(",") if s.strip()):
        m = ARN_RE.match(spec)
        if m:
            region, account, gid = m.groups()
            accounts.add(account)
            targets.append((region, gid))
        elif ID_RE.match(spec):
            if not default_region:
                raise ValueError(f"{spec}: bare group id needs --region (or AWS_REGION / profile region)")
            targets.append((default_region, spec))
        else:
            raise ValueError(f"not a security group ARN or id: {spec!r}")
    if len(accounts) > 1:
        raise ValueError(f"security groups must be in one account; ARNs name {', '.join(sorted(accounts))}")
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]
    if len(targets) < 2:
        raise ValueError("need at least two distinct security groups")
    return targets, (accounts.pop() if accounts else None)


def fetch_prefix_lists(ec2, ids: set[str]) -> tuple[dict[str, list[str] | None], dict[str, str], list[str]]:
    entries: dict[str, list[str] | None] = {}
    names: dict[str, str] = {}
    errors = []
    if not ids:
        return entries, names, errors
    try:
        for page in ec2.get_paginator("describe_managed_prefix_lists").paginate(PrefixListIds=sorted(ids)):
            for pl in _g(page, "PrefixLists", []):
                names[pl["PrefixListId"]] = pl.get("PrefixListName", "")
    except ClientError as e:
        log.debug("describe_managed_prefix_lists: %s", e)
    for pid in sorted(ids):
        try:
            cidrs = []
            for page in ec2.get_paginator("get_managed_prefix_list_entries").paginate(PrefixListId=pid):
                cidrs.extend(e["Cidr"] for e in _g(page, "Entries", []))
            entries[pid] = cidrs
        except ClientError as e:
            entries[pid] = None
            errors.append(f"{pid}: {e.response.get('Error', {}).get('Code', e)}")
    return entries, names, errors


def load(session_factory, targets: list[tuple[str, str]]):
    groups: dict[str, SG] = {}
    rules: dict[str, list[SgRule]] = {}
    findings: list[Finding] = []
    by_region = defaultdict(list)
    for region, gid in targets:
        by_region[region].append(gid)
    for region, ids in by_region.items():
        ec2 = get_client("ec2", session_factory(region))
        try:
            resp = ec2.describe_security_groups(GroupIds=ids)
        except ClientError as e:
            raise ValueError(f"{region}: {e.response.get('Error', {}).get('Message', e)}") from e
        for g in resp["SecurityGroups"]:
            groups[g["GroupId"]] = SG(g["GroupId"], g.get("GroupName", ""), g.get("VpcId", ""),
                                      g.get("OwnerId", ""), region)
            rules[g["GroupId"]] = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": ids}]):
            for r in _g(page, "SecurityGroupRules", []):
                rules[r["GroupId"]].append(SgRule.from_api(r))
        pl_ids = {r.peer for gid in ids for r in rules[gid] if r.peer_kind == "pl"}
        entries, names, errors = fetch_prefix_lists(ec2, pl_ids)
        for err in errors:
            findings.append(Finding("warn", "PREFIX_LIST_UNRESOLVED", detail=f"{region} {err}; compared by id only"))
        for gid in ids:
            for r in rules[gid]:
                if r.peer_kind == "pl":
                    n = entries.get(r.peer)
                    r.peer_label = ", ".join(x for x in (names.get(r.peer, ""),
                                                         f"{len(n)} entries" if n is not None else "unresolved") if x)
                r.expand(entries)
    ordered = [groups[gid] for _, gid in targets]
    for g in ordered:
        rules[g.group_id].sort(key=lambda r: (r.egress, r.key()[1], r.peer))
    return ordered, rules, findings


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(groups: list[SG], rules, findings: list[Finding], summary: list[dict], show_covered: bool) -> None:
    print()
    for i, g in enumerate(groups):
        print(f"{'left ' if i == 0 else 'right'}  {g}  rules: "
              f"{sum(not r.egress for r in rules[g.group_id])} in / {sum(r.egress for r in rules[g.group_id])} out")
    for f in (f for f in findings if not f.left):
        print(f"[{f.severity.upper():<5}] {f.code} {f.detail}")
    for row in summary:
        print(f"\n=== access in {row['left']} absent from {row['right']}   "
              f"ingress: {row['ingress']}   egress: {row['egress']}")
        shown = [f for f in findings if (f.left, f.right) == (row["left"], row["right"])
                 and (show_covered or f.severity != "info")]
        cur = None
        for f in shown:
            if f.direction != cur:
                cur = f.direction
                print(f"\n  {f.direction}:")
            desc = f'  "{f.description}"' if f.description else ""
            print(f"    [{f.severity.upper():<5}] {f.code:<9} {f.rule_id} {f.rule}{desc}")
            if f.detail:
                print(f"            {f.detail}")
            for u in f.uncovered[:MAX_CIDRS_SHOWN]:
                head, sep, addrs = u.rpartition(" from " if " from " in u else " to ")
                addrs = addrs.split(", ")
                more = f", ... {len(addrs) - MAX_CIDRS_SHOWN} more" if len(addrs) > MAX_CIDRS_SHOWN else ""
                print(f"            uncovered: {head}{sep}{', '.join(addrs[:MAX_CIDRS_SHOWN])}{more}")
            if len(f.uncovered) > MAX_CIDRS_SHOWN:
                print(f"            uncovered: ... {len(f.uncovered) - MAX_CIDRS_SHOWN} more (see JSON/CSV)")
            for x in f.related:
                print(f"            {'matches' if f.code == 'IDENTICAL' else 'overlaps'}: {x}")
        if not shown:
            print(f"  (no gaps: {row['right']} grant(s) everything {row['left']} grants)")
    hidden = sum(f.code in ("COVERED", "IDENTICAL") for f in findings)
    if hidden and not show_covered:
        print(f"\n({hidden} left rules fully granted by the right group(s) hidden; --show-covered to list)")


HTML_CSS = """
:root { --bg:#fff; --fg:#1d2329; --muted:#5b6670; --line:#d9dee3; --card:#f6f8fa;
  --error:#b42318; --error-bg:#fde8e7; --warn:#9a6700; --warn-bg:#fff4d6;
  --info:#305d9c; --info-bg:#e6effa; --ok:#1a7f37; --ok-bg:#dcf5e3; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1418; --fg:#e3e8ec; --muted:#97a3ad; --line:#2c353d;
  --card:#161d23; --error:#ff8a80; --error-bg:#3d1714; --warn:#f2c14e; --warn-bg:#3a2e0e;
  --info:#8ab4f8; --info-bg:#14243b; --ok:#6fdc8c; --ok-bg:#12321e; } }
body { background:var(--bg); color:var(--fg); font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",
  Roboto,sans-serif; margin:0 auto; padding:24px 16px; max-width:1400px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:18px; margin:32px 0 8px; }
h3 { font-size:15px; margin:20px 0 6px; } .muted { color:var(--muted); }
code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }
table { border-collapse:collapse; width:100%; margin:6px 0 12px; }
th, td { text-align:left; vertical-align:top; padding:6px 8px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
td ul { margin:0; padding-left:16px; } .wrap { overflow-x:auto; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 16px; margin:12px 0; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; }
.error { color:var(--error); background:var(--error-bg); } .warn { color:var(--warn); background:var(--warn-bg); }
.info { color:var(--info); background:var(--info-bg); } .ok { color:var(--ok); background:var(--ok-bg); }
.stats span { margin-right:14px; } details > summary { cursor:pointer; color:var(--muted); margin:6px 0; }
"""

def verdict_class(v: str) -> str:
    return "error" if "gap" in v else "ok"


def render_html(payload: dict, generated: str) -> str:
    e = html.escape

    def ul(items):
        return "<ul>" + "".join(f"<li class='mono'>{e(x)}</li>" for x in items) + "</ul>" if items else ""

    def badge(text, cls):
        return f"<span class='badge {cls}'>{e(text)}</span>"

    def finding_rows(fs):
        return "".join(
            f"<tr><td>{badge(f['severity'], f['severity'])}</td><td class='mono'>{e(f['code'])}</td>"
            f"<td class='mono'>{e(f['rule_id'])}<br>{e(f['rule'])}</td><td>{e(f['description'])}</td>"
            f"<td>{ul(f['uncovered'])}</td><td>{ul(f['related'])}</td><td>{e(f['detail'])}</td></tr>"
            for f in fs)

    head = ("<tr><th>Severity</th><th>Code</th><th>Left rule</th><th>Description</th><th>Absent from right</th>"
            "<th>Overlapping right rules</th><th>Detail</th></tr>")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
           f"<title>Security group diff</title><style>{HTML_CSS}</style></head><body>",
           f"<h1>Security group diff</h1><div class='muted'>Account {e(payload['account'])} &middot; "
           f"generated {e(generated)} &middot; access granted by the left group that the right group(s) combined do not grant "
           f"&middot; descriptions shown for reference, not compared</div>"]

    counts = payload["stats"]
    out.append("<div class='card stats'>" + "".join(
        f"<span><b>{e(k)}</b> {v}</span>" for k, v in sorted(counts.items())) + "</div>")

    out.append("<h2>Groups</h2><div class='wrap'><table><tr><th>Role</th><th>Group</th><th>Name</th><th>VPC</th>"
               "<th>Region</th><th>Ingress rules</th><th>Egress rules</th></tr>")
    for i, g in enumerate(payload["groups"]):
        rs = payload["rules"][g["group_id"]]
        out.append(f"<tr><td>{'left' if i == 0 else 'right'}</td><td class='mono'>{e(g['group_id'])}</td>"
                   f"<td>{e(g['name'])}</td><td class='mono'>{e(g['vpc_id'])}</td><td>{e(g['region'])}</td>"
                   f"<td>{sum(not r['egress'] for r in rs)}</td><td>{sum(r['egress'] for r in rs)}</td></tr>")
    out.append("</table></div>")

    general = [f for f in payload["findings"] if not f["left"]]
    if general:
        out.append("<div class='card'>" + "".join(
            f"<div>{badge(f['severity'], f['severity'])} <span class='mono'>{e(f['code'])}</span> "
            f"{e(f['detail'])}</div>" for f in general) + "</div>")

    for row in payload["summary"]:
        pair = (row["left"], row["right"])
        out.append(f"<h2>Access in <span class='mono'>{e(pair[0])}</span> absent from "
                   f"<span class='mono'>{e(pair[1])}</span></h2>"
                   f"<div>ingress {badge(row['ingress'], verdict_class(row['ingress']))} &nbsp; "
                   f"egress {badge(row['egress'], verdict_class(row['egress']))}</div>")
        fs = [f for f in payload["findings"] if (f["left"], f["right"]) == pair]
        for direction in ("ingress", "egress"):
            sel = [f for f in fs if f["direction"] == direction]
            gaps = [f for f in sel if f["severity"] != "info"]
            ok = [f for f in sel if f["severity"] == "info"]
            out.append(f"<h3>{direction}</h3>")
            if gaps:
                out.append(f"<div class='wrap'><table>{head}{finding_rows(gaps)}</table></div>")
            else:
                out.append("<div class='muted'>No gaps.</div>")
            if ok:
                out.append(f"<details><summary>{len(ok)} left rule(s) fully granted by the right group(s)</summary>"
                           f"<div class='wrap'><table>{head}{finding_rows(ok)}</table></div></details>")

    out.append("<h2>All rules</h2>")
    for g in payload["groups"]:
        rs = payload["rules"][g["group_id"]]
        out.append(f"<details><summary><span class='mono'>{e(g['group_id'])}</span> {e(g['name'])} "
                   f"({len(rs)} rules)</summary><div class='wrap'><table><tr><th>Direction</th><th>Rule ID</th>"
                   "<th>Rule</th><th>Description</th></tr>" + "".join(
                       f"<tr><td>{'egress' if r['egress'] else 'ingress'}</td><td class='mono'>{e(r['rule_id'])}"
                       f"</td><td class='mono'>{e(r['rule'])}</td><td>{e(r['description'])}</td></tr>" for r in rs)
                   + "</table></div></details>")
    out.append("</body></html>")
    return "\n".join(out)


def write_outputs(payload: dict, findings: list[Finding], json_path, csv_path, html_path=None) -> None:
    for path in (json_path, csv_path, html_path):
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Wrote JSON to %s", json_path)
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            w.writeheader()
            for f in findings:
                w.writerow({**asdict(f), "uncovered": " | ".join(f.uncovered), "related": " | ".join(f.related)})
        log.info("Wrote %d rows to %s", len(findings), csv_path)
    if html_path:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(payload, dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        log.info("Wrote HTML to %s", html_path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(
        description="Find access granted by the left security group that the right group(s), combined, do not grant "
                    "(prefix lists expanded, overlapping CIDRs resolved).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-admin sg-0123456789abcdef0 sg-0fedcba9876543210
  %(prog)s --profile prod-admin arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \\
           arn:aws:ec2:us-west-2:111122223333:security-group/sg-0fedcba9876543210
""")
    p.add_argument("groups", nargs="+", metavar="SG",
                   help="Security group ARNs or ids (comma-separated also accepted): LEFT RIGHT [RIGHT ...]; "
                        "left access is checked against the right groups' combined access")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE") or None, help="AWS profile (default AWS_PROFILE)")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or None,
                   help="Region for bare group ids (default AWS_REGION, then the profile's region)")
    p.add_argument("--show-covered", action="store_true",
                   help="Also list left rules the right group fully grants (COVERED, IDENTICAL)")
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

    try:
        base_session = boto3.Session(profile_name=args.profile)
        targets, account = parse_targets(args.groups, args.region or base_session.region_name)
        caller = get_client("sts", boto3.Session(profile_name=args.profile,
                                                 region_name=targets[0][0])).get_caller_identity()["Account"]
        if account and caller != account:
            raise ValueError(f"profile {args.profile or '(default)'} is account {caller}; groups are in {account}")
        groups, rules, findings = load(lambda r: boto3.Session(profile_name=args.profile, region_name=r), targets)
        owners = {g.owner for g in groups}
        if len(owners) > 1:
            raise ValueError(f"security groups must be in one account; owners: {', '.join(sorted(owners))}")
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", e)
        return 2

    diffs, summary = diff_groups(groups, rules)
    findings.extend(diffs)
    if len({g.vpc_id for g in groups}) > 1:
        findings.insert(0, Finding("info", "DIFFERENT_VPCS",
                                   detail="groups are in different VPCs; group references may not be comparable"))
    by_code = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    payload = {"account": caller, "groups": [asdict(g) for g in groups], "summary": summary,
               "stats": dict(by_code),
               "rules": {g.group_id: [{**{k: v for k, v in asdict(r).items() if k != "boxes"}, "rule": str(r)}
                                      for r in rules[g.group_id]] for g in groups},
               "findings": [asdict(f) for f in findings]}

    paths = {}
    if not args.no_save:
        now = dt.datetime.now()
        slug = "_".join(g.group_id for g in groups)[:80]
        stem = Path(args.out_dir) / now.strftime("%Y-%m-%d") / f"{now.strftime('%H%M%S')}_sgdiff_{slug}"
        paths = {"json": f"{stem}.json", "csv": f"{stem}.csv", "html": f"{stem}.html"}
    json_path = args.json_out or paths.get("json")
    csv_path = args.csv_out or paths.get("csv")
    html_path = args.html_out or paths.get("html")
    write_outputs(payload, findings, json_path, csv_path, html_path)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_report(groups, rules, findings, summary, args.show_covered)
        saved = [x for x in (html_path, csv_path, json_path) if x]
        if saved:
            print("\nSaved:\n" + "\n".join(f"  {x}" for x in saved))

    return 1 if any(f.severity in ("error", "warn") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
