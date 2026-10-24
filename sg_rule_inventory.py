#!/usr/bin/env python3
"""
Security group rule inventory, with a traffic tester in the HTML report.

Intent: answer "what do these security groups allow, together?" for a set
of groups - typically the groups attached to one network interface, or a
group set that is about to be attached - and let reviewers try "would this
flow be allowed, and what if this rule or group were removed?" from the
report alone. Security groups only allow, and every group attached to an
interface adds to its access, so the collection's access is the union of
all their rules. For reporting only: read-only, no changes are made in AWS.

What it does:

  1. Takes any number of targets, in one or more accounts (several accounts
     via ARNs): security group ids / ARNs; network interface ids / ARNs (an
     interface stands for its groups); EC2 instance ids / ARNs (each of its
     interfaces); Lambda function ARNs (the groups in its VPC configuration;
     a function outside a VPC has none and is skipped with a warning).
  2. Reads every rule (describe_security_group_rules) and expands prefix
     lists to their current CIDRs.
  3. Reports:
       * every rule, per group (filter and sort by group, direction,
         protocol, peer ...), with whether the same access is also granted
         by other rules in the collection (no / partly / fully) - fully means
         the rule could be removed without changing the collection's access
       * the combined access of the collection per direction: merged CIDRs per
         protocol/port, and which groups grant each piece
       * with two or more interfaces, only what differs between them: groups
         attached to some but not all, and the exact access (protocol / ports x
         addresses) allowed on some but not others, with the rules responsible.
         Each interface's access is compared exactly, so the same access
         written differently is not a difference
  4. The HTML report embeds the rule data and an access tester (JavaScript,
     runs in the browser, no AWS access): enter DIRECTION ADDRESS PROTOCOL
     [PORT] tests and see ALLOWED / PARTIAL / DENIED, the rules that grant
     it, and the switched-off rules that would. Without PORT, or for a
     partial result, the allowed and not-allowed ports / addresses are listed.
     Groups and individual rules can be switched off to see their effect.
     Tests with identical outcomes share a row. Results can be compared
     with a baseline test, one column per compared test: verdict, ports
     allowed for both / only one, and the rules involved, ignoring addresses. A scenario (tests, switched-off
     rules, name, notes) can be downloaded as a copy of the report that opens
     on it, or exported / imported as JSON, to show others that a path is open:
     on opening, the copy re-runs the tests, compares them with the exported
     results, checks the rule data against its SHA-256 (also printed by the
     run that made the report), and lists anything that was switched off.

Tester syntax (one test per line):

    ingress 10.1.2.3 tcp 443        traffic from 10.1.2.3 to tcp port 443
    egress 0.0.0.0/0 udp 53         traffic to anywhere on udp 53
    both 10.0.0.0/8 tcp 8000-8100   both directions, a CIDR and a port range
    in sg-0123456789abcdef0 tcp 5432    from members of a referenced group
    out pl-0123456789abcdef0 tcp 443    to a prefix list's CIDRs
    in 2001:db8::/64 icmpv6 128     ICMPv6 type 128 (PORT = TYPE[/CODE] for ICMP)
    in any all                      all traffic from anywhere (IPv4 and IPv6)

Ingress ADDRESS is the traffic's source, egress ADDRESS its destination; PORT
is the destination port. A missing PORT tests every port and lists which
ports / ranges are allowed and which are not. Group references
are matched by group id only (the report cannot know the members' addresses).

Profiles: each account is read with its own profile. --profile is used for
its own account; every other account named by an ARN uses its local profile
(found by account id; profiles ending in -priv or -cpar are never used;
--account-profile forces one). Bare ids belong to the --profile account, else
to the single ARN account, else (no ARNs) to AWS_PROFILE or the default
credentials; next to ARNs from several accounts they are refused as
ambiguous. Every profile is verified with sts:GetCallerIdentity first.

Configuration (.env, all optional; CLI flags override):

    # Profile for bare ids when --profile not given and no ARN names an account
    AWS_PROFILE=
    # Region for bare ids when --region not given (ARNs carry their own)
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports: text on screen, plus auto-saved HTML (interactive: rules by group,
combined access, access tester), CSV (rules) and JSON under
reports/sg_rule_inventory/YYYY-MM-DD/.

Usage:

    ./sg_rule_inventory.py --region us-east-1 sg-0123456789abcdef0 sg-0fedcba9876543210
    ./sg_rule_inventory.py arn:aws:ec2:us-east-1:111122223333:network-interface/eni-0123456789abcdef0

Exit codes: 0 ok, 1 the interfaces differ or a referenced prefix list could not be
read, 2 fatal error.

Read-only. Only Describe / Get calls are made (EC2, Lambda GetFunctionConfiguration, STS).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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
from lib.boxes import PROTO_NAMES, Box, fmt_addrs, fmt_proto_ports, intersects, merge, remainder  # noqa: E402
from lib.output import (add_output_args, print_saved, report_paths, setup_logging, write_csv,  # noqa: E402
                        write_json, write_text)
from lib.security_groups import (SG, SgRule, load_groups, parse_account_targets,  # noqa: E402
                                 resolve_account_profiles, resolve_workloads, split_specs, spec_accounts)

log = logging.getLogger("sg_rule_inventory")
TOOL = "sg_rule_inventory"
MAX_CIDRS_SHOWN = 8


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def fix_self_refs(rules: dict[str, list[SgRule]]) -> None:
    """Give self-references the owning group's id as address space, so a test against
    sg-X matches group X's own self-reference rules (the rule still reads 'self')."""
    for gid, rs in rules.items():
        for r in rs:
            if r.peer == "self":
                r.boxes = [(f"sg:{gid}", b) for _, b in r.boxes]


def union(boxes: list[tuple[str, Box]]) -> dict[str, list[Box]]:
    """Union of boxes per address space, as disjoint merged boxes."""
    acc: dict[str, list[Box]] = defaultdict(list)
    for space, b in boxes:
        acc[space].extend(remainder(b, acc[space]))
    return {sp: merge(bs) for sp, bs in acc.items()}


def also_granted(rule: SgRule, others: list[SgRule]) -> tuple[str, list[SgRule]]:
    """('no' | 'partly' | 'fully', overlapping rules): how much of `rule`'s access other rules
    in the collection grant too. 'fully' = removing the rule changes nothing."""
    hits: dict[tuple, SgRule] = {}
    left = []
    for space, box in rule.boxes:
        cover = []
        for o in others:
            for osp, ob in o.boxes:
                if osp == space and intersects(box, ob):
                    cover.append(ob)
                    hits[(o.group_id, o.rule_id)] = o
        left.extend(remainder(box, cover))
    return ("fully" if not left else "partly" if hits else "no"), list(hits.values())


@dataclass
class RuleRow:
    """One rule as reported (CSV row, rules table row)."""
    group_id: str
    group_name: str
    account: str
    direction: str
    rule_id: str
    protocol: str
    access: str
    peer: str
    peer_kind: str
    peer_label: str
    description: str
    rule: str
    also_granted: str
    overlaps: list[str] = field(default_factory=list)


CSV_COLUMNS = list(RuleRow.__dataclass_fields__)


def proto_label(r: SgRule) -> str:
    """Protocol name for filtering: tcp, udp, icmp, icmpv6, all, or the protocol number."""
    p = str(r.proto).lower()
    if p in ("-1", "all"):
        return "all"
    return PROTO_NAMES.get(int(p), p) if p.isdigit() else p


def rule_rows(groups: list[SG], rules: dict[str, list[SgRule]]) -> list[RuleRow]:
    """Every rule of every group, with how much of it the rest of the collection also grants."""
    names = {g.group_id: g.name for g in groups}
    every = [r for g in groups for r in rules[g.group_id]]
    out = []
    for g in groups:
        for r in rules[g.group_id]:
            others = [o for o in every if o.egress == r.egress and o is not r]
            level, hits = also_granted(r, others)
            out.append(RuleRow(g.group_id, g.name, g.owner, r.direction, r.rule_id, proto_label(r), r.access(), r.peer,
                               r.peer_kind, r.peer_label, r.description, str(r), level,
                               [f"{o.group_id} ({names.get(o.group_id, '')}) {o.rule_id} {o}" for o in hits]))
    return out


def combined_access(groups: list[SG], rules: dict[str, list[SgRule]]) -> list[dict]:
    """The collection's access per direction: one row per protocol/port with the merged
    addresses and the groups / rules that grant some of it."""
    out = []
    every = [r for g in groups for r in rules[g.group_id]]
    for egress, direction in ((False, "ingress"), (True, "egress")):
        rs = [r for r in every if r.egress == egress]
        merged = union([b for r in rs for b in r.boxes])
        by_pp: dict[tuple, list[tuple[str, Box]]] = defaultdict(list)
        for space, boxes in merged.items():
            for b in boxes:
                by_pp[(b[0], b[1])].append((space, b))
        for (pr, ports), items in sorted(by_pp.items()):
            contrib = [r for r in rs if any(sp == s2 and intersects(b, b2) for sp, b in r.boxes for s2, b2 in items)]
            addrs = [a for sp, b in sorted(items, key=lambda x: (x[0], x[1][2])) for a in fmt_addrs(sp, b[2])]
            out.append({"direction": direction, "access": fmt_proto_ports(pr, ports),
                        "addresses": addrs, "address_count": len(addrs),
                        "granted_by": sorted({r.group_id for r in contrib}),
                        "rules": [f"{r.group_id} {r.rule_id}" for r in contrib]})
    return out


# --------------------------------------------------------------------------- #
# Interface differences
# --------------------------------------------------------------------------- #
def partition(access: dict[str, dict[str, list[Box]]]) -> list[tuple[str, Box, frozenset]]:
    """Split the union of several access sets into disjoint pieces, each tagged with the set of
    owners (interfaces) that allow it. access = {owner: {space: disjoint boxes}}."""
    regions: list[tuple[str, Box, frozenset]] = []
    for owner, spaces in access.items():
        new = []
        for sp, b, who in regions:
            hits = [x for x in spaces.get(sp, []) if intersects(b, x)]
            outside = remainder(b, hits)
            new += [(sp, p, who | {owner}) for p in remainder(b, outside)] + [(sp, p, who) for p in outside]
        for sp, boxes in spaces.items():
            seen = [b for s2, b, _ in regions if s2 == sp]
            new += [(sp, p, frozenset([owner])) for x in boxes for p in remainder(x, seen)]
        regions = new
    return regions


def interface_deltas(interfaces: list[dict], rules: dict[str, list[SgRule]]) -> dict:
    """What differs between the interfaces given (two or more): groups attached to some but not
    all, and access (protocol / ports x addresses) allowed on some but not all, with the rules
    responsible. Each interface's access is the union of its groups' rules, compared exactly,
    so the same access written differently is not a difference."""
    enis = [n["id"] for n in interfaces]
    out = {"interfaces": enis, "groups": [], "access": []}
    if len(enis) < 2:
        return out
    every = set(enis)
    on = {n["id"]: set(n["groups"]) for n in interfaces}
    for gid in sorted(set().union(*on.values())):
        has = [e for e in enis if gid in on[e]]
        if len(has) < len(enis):
            out["groups"].append({"group_id": gid, "attached_to": has, "missing_on": [e for e in enis if e not in has]})
    for egress, direction in ((False, "ingress"), (True, "egress")):
        access = {e: union([b for g in on[e] for r in rules.get(g, []) if r.egress == egress for b in r.boxes])
                  for e in enis}
        by_owner: dict[frozenset, dict[str, list[Box]]] = defaultdict(lambda: defaultdict(list))
        for sp, b, who in partition(access):
            if who != every:
                by_owner[who][sp].append(b)
        prep = "to" if egress else "from"
        for who, spaces in by_owner.items():
            by_pp: dict[tuple, list[tuple[str, Box]]] = defaultdict(list)
            for sp, boxes in spaces.items():
                for b in merge(boxes):
                    by_pp[(b[0], b[1])].append((sp, b))
            for (pr, ports), items in sorted(by_pp.items()):
                resp = [r for g in sorted({g for e in who for g in on[e]}) for r in rules.get(g, [])
                        if r.egress == egress and any(sp == s2 and intersects(b, b2) for sp, b in r.boxes for s2, b2 in items)]
                addrs = [a for sp, b in sorted(items, key=lambda x: (x[0], x[1][2])) for a in fmt_addrs(sp, b[2])]
                out["access"].append({
                    "direction": direction, "access": fmt_proto_ports(pr, ports), "addresses": addrs,
                    "allowed_on": [e for e in enis if e in who], "missing_on": [e for e in enis if e not in who],
                    "rules": [f"{r.group_id} {r.rule_id} {r}" for r in resp], "prep": prep})
    out["access"].sort(key=lambda d: (d["direction"] != "ingress", d["access"], d["allowed_on"]))
    return out


# --------------------------------------------------------------------------- #
# HTML access tester data
# --------------------------------------------------------------------------- #
def known_prefix_lists(rules: dict[str, list[SgRule]]) -> dict[str, list[str]]:
    """{pl id: CIDRs} for the prefix lists the rules reference and whose entries were read."""
    out = {}
    for rs in rules.values():
        for r in rs:
            if r.peer_kind == "pl" and r.boxes and r.boxes[0][0] in ("ipv4", "ipv6"):
                out[r.peer] = sorted({c for sp, b in r.boxes for c in fmt_addrs(sp, b[2])})
    return out


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def via_text(payload: dict) -> str:
    """How the account(s) were read, e.g. 'profile acct-ro (local profile for account 1111...)',
    or one 'account via profile' per account."""
    def one(p, src):
        """'profile x (how chosen)' or 'default credentials'."""
        return f"profile {p} ({src})" if p else "default credentials"
    if len(payload["accounts"]) == 1:
        a = payload["accounts"][0]
        return one(a["profile"], a["profile_source"])
    return "; ".join(f"{a['account']} via {one(a['profile'], a['profile_source'])}" for a in payload["accounts"])


def cut(addrs: list[str]) -> str:
    """Comma-joined addresses, cut at MAX_CIDRS_SHOWN."""
    more = f", ... {len(addrs) - MAX_CIDRS_SHOWN} more" if len(addrs) > MAX_CIDRS_SHOWN else ""
    return ", ".join(addrs[:MAX_CIDRS_SHOWN]) + more


def print_report(payload: dict, rows: list[RuleRow], combined: list[dict], show_rules: bool = False) -> None:
    """Text report. By default a summary only: account, interfaces, one line per group, and
    counts of combined access entries and interface differences. Anything listing rules or
    access (per-group rules, combined access, interface access differences and the rules behind
    them) only with show_rules; the saved HTML / CSV / JSON always hold everything."""
    if len(payload["accounts"]) > 1:
        print(f"\nAccounts: {via_text(payload)}")
    else:
        print(f"\nAccount {payload['account']} via {via_text(payload)}")
    print(f"Rule data SHA-256 {payload['rule_data_sha256']} (shown in the HTML report and in exported scenarios)")
    for w in payload["warnings"]:
        print(f"[WARN ] PREFIX_LIST_UNRESOLVED {w}; matched by id only")
    for w in payload["target_warnings"]:
        print(f"[WARN ] {w}")
    for n in payload["interfaces"]:
        label = "lambda" if n["kind"] == "lambda" else "interface"
        acct = f"{n['account']}, " if len(payload["accounts"]) > 1 else ""
        print(f"{label} {n['id']} ({n['attachment'] or '-'}, {acct}{n['vpc_id']}, {n['region']}) "
              f"-> {', '.join(n['groups']) or '(no groups)'}")
    for g in payload["groups"]:
        rs = [r for r in rows if r.group_id == g["group_id"]]
        acct = f"{g['owner']}, " if len(payload["accounts"]) > 1 else ""
        line = (f"{g['group_id']} ({g['name']}, {acct}{g['vpc_id']}, {g['region']})  "
                f"{sum(r.direction == 'ingress' for r in rs)} in / {sum(r.direction == 'egress' for r in rs)} out"
                + (f"  via {', '.join(g['via'])}" if g["via"] else ""))
        if not show_rules:
            print(f"group {line}")
            continue
        print(f"\n=== {line}")
        cur = None
        for r in rs:
            if r.direction != cur:
                cur = r.direction
                print(f"  {cur}:")
            desc = f'  "{r.description}"' if r.description else ""
            also = f"  [also granted: {r.also_granted}]" if r.also_granted != "no" else ""
            print(f"    {r.rule_id:<22} {r.rule}{desc}{also}")
        if not rs:
            print("  (no rules)")
    d = payload["interface_deltas"]
    count = lambda xs, direction: sum(x["direction"] == direction for x in xs)
    if not show_rules:
        print(f"\nRules: {len(rows)}; combined access: {count(combined, 'ingress')} ingress / "
              f"{count(combined, 'egress')} egress protocol/port entries")
        if len(d["interfaces"]) >= 2:
            if not d["groups"] and not d["access"]:
                print(f"Interfaces / functions: no differences; all {len(d['interfaces'])} allow exactly the same access")
            else:
                print(f"Interfaces / functions: {len(d['groups'])} group attachment difference(s), {len(d['access'])} access "
                      f"difference(s) ({count(d['access'], 'ingress')} ingress / {count(d['access'], 'egress')} egress)")
                for e in d["interfaces"]:
                    lacks = sum(e in a["missing_on"] for a in d["access"])
                    if lacks:
                        print(f"  {e}: lacks access in {lacks} difference(s)")
        print("(--show-rules lists the rules, combined access and interface differences; the HTML / CSV / JSON "
              "reports always include them)")
        return
    print(f"\n=== combined access of {len(payload['groups'])} group(s)")
    for direction in ("ingress", "egress"):
        sel = [c for c in combined if c["direction"] == direction]
        print(f"  {direction}:" + ("" if sel else " none"))
        prep = "to" if direction == "egress" else "from"
        for c in sel:
            print(f"    {c['access']} {prep} {cut(c['addresses'])}   [{', '.join(c['granted_by'])}]")
    if len(d["interfaces"]) < 2:
        return
    print(f"\n=== differences between {len(d['interfaces'])} interfaces / functions")
    if not d["groups"] and not d["access"]:
        print("  none: every interface allows exactly the same access")
    for g in d["groups"]:
        print(f"  group {g['group_id']} attached to {', '.join(g['attached_to'])}; not to {', '.join(g['missing_on'])}")
    for a in d["access"]:
        print(f"  [{a['direction']}] {a['access']} {a['prep']} {cut(a['addresses'])}")
        print(f"      allowed on {', '.join(a['allowed_on'])}; not on {', '.join(a['missing_on'])}")
        for r in a["rules"]:
            print(f"      rule: {r}")


TESTER_HTML = """
<style>
/* this report uses the full window; the comparison table always fits it, long values wrap in their cells */
body{max-width:none}
table.cmp{table-layout:fixed;width:100%}table.cmp th,table.cmp td{white-space:normal;overflow-wrap:anywhere}
</style>
<section id="tester"><h2>Access tester</h2>
<div data-t="evidence"></div>
<div class="muted">Checks flows against the combined rules switched on below, using the rule data in this file
(prefix lists as of the report time). Runs in the browser only; nothing is sent anywhere. Ingress address = source, egress address = destination, port = destination
port; ICMP port = TYPE[/CODE]; no port = every port, and the result lists the allowed and not-allowed ports. One test per line:
<code>DIRECTION ADDRESS PROTOCOL [PORT]</code>, e.g. <code>ingress 10.1.2.3 tcp 443</code>,
<code>egress 0.0.0.0/0 udp 53</code>, <code>both sg-0123... tcp 5432</code>, <code>in any all</code>.</div>
<div class="controls">
<label>Direction<select data-t="dir"><option>ingress</option><option>egress</option><option>both</option></select></label>
<label>Address<input type="search" data-t="addr" placeholder="10.1.2.3, 10.0.0.0/8, any, sg-..., pl-..."></label>
<label>Protocol<input type="search" data-t="proto" list="tester-protos" value="tcp"></label>
<label>Port<input type="search" data-t="port" placeholder="443, 8000-8100, 8/0"></label>
<button data-t="add">Add test</button><button data-t="clear">Clear tests</button>
</div>
<datalist id="tester-protos"><option>tcp</option><option>udp</option><option>icmp</option><option>icmpv6</option>
<option>all</option></datalist>
<div class="controls"><label style="flex:1 1 100%">Tests<textarea data-t="lines" rows="5"
style="font:12.5px ui-monospace,Menlo,Consolas,monospace;width:100%;box-sizing:border-box;color:var(--fg);
background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px"></textarea></label>
</div>
<details class="controls" style="display:block" data-t="tgl"><summary style="cursor:pointer">
Groups and rules used by the tester: <b data-t="oncount"></b>
<button data-t="allon">All on</button></summary>
<div class="muted" style="margin:6px 0">Untick a group or a rule to see the effect of removing it.</div>
<div data-t="toggles"></div></details>
<div class="controls">
<label>Scenario name<input type="search" data-t="sname" placeholder="e.g. web to db, legacy group removed"></label>
<label style="flex:1 1 320px">Notes<input type="search" data-t="snotes" style="max-width:none;width:100%"
placeholder="change ticket, purpose, assumptions"></label>
<button data-t="exphtml">Download scenario report</button><button data-t="expjson">Export scenario JSON</button>
<button data-t="impbtn">Import scenario</button><input type="file" data-t="impfile" accept=".json,.html,application/json,text/html" hidden>
</div>
<div class="cards" data-t="cards"></div>
<div class="wrap"><table data-t="out"></table></div>
<h3>Compare tests with a baseline</h3>
<div class="muted">Differences between a baseline test and each compared test, other than their addresses: verdict,
the protocols / ports allowed (compared on the protocol / ports both cover), and the rules involved. Cells that
differ from the baseline are highlighted.</div>
<div class="controls"><label>Baseline<select data-t="cbase" style="max-width:420px"></select></label>
<button data-t="cmphtml">Download comparison</button><button data-t="cmpcsv">Download comparison CSV</button>
<div style="flex:1 1 100%"><span class="muted" style="font-size:11px">Compare with:</span>
<button data-t="cwall">All</button> <button data-t="cwnone">None</button>
<div data-t="cwith" style="display:flex;flex-wrap:wrap;gap:2px 14px;margin-top:4px"></div></div></div>
<table class="cmp" data-t="cmp"></table>
</section>
"""

TESTER_JS = r"""
(() => {
const T = JSON.parse(document.getElementById("extra-data").textContent);
const sec = document.getElementById("tester");
const $ = k => sec.querySelector(`[data-t="${k}"]`);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const PN = {tcp: 6, udp: 17, icmp: 1, icmpv6: 58}, NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"};
const DIRS = {in: ["ingress"], ingress: ["ingress"], out: ["egress"], egress: ["egress"], both: ["ingress", "egress"]};
const ALLP = [0n, 255n], ALLO = [0n, 65535n];
const rules = T.rules.map(r => ({...r, bx: r.boxes.map(([s, p0, p1, o0, o1, a0, a1]) =>
  ({s, b: [[BigInt(p0), BigInt(p1)], [BigInt(o0), BigInt(o1)], [BigInt(a0), BigInt(a1)]]}))}));

// --- box arithmetic (mirrors lib/boxes.py) ---
const inter = (a, b) => a.every((x, i) => x[0] <= b[i][1] && b[i][0] <= x[1]);
function sub(a, b) {
  if (!inter(a, b)) return [a];
  const out = [], cur = a.map(x => [...x]);
  for (let d = 0; d < 3; d++) {
    let [lo, hi] = cur[d]; const [blo, bhi] = b[d];
    if (lo < blo) { const c = cur.map(x => [...x]); c[d] = [lo, blo - 1n]; out.push(c); lo = blo; }
    if (hi > bhi) { const c = cur.map(x => [...x]); c[d] = [bhi + 1n, hi]; out.push(c); hi = bhi; }
    cur[d] = [lo, hi];
  }
  return out;
}

// --- addresses ---
function v4(s) {
  const p = s.split(".");
  if (p.length !== 4 || p.some(x => !/^\d{1,3}$/.test(x) || +x > 255)) return null;
  return p.reduce((a, x) => a * 256n + BigInt(+x), 0n);
}
function v6(s) {
  if (s.includes(".")) {
    const i = s.lastIndexOf(":"), t = v4(s.slice(i + 1));
    if (t === null) return null;
    s = s.slice(0, i + 1) + (t >> 16n).toString(16) + ":" + (t & 0xffffn).toString(16);
  }
  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const hd = dbl[0] ? dbl[0].split(":") : [], tl = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const fill = dbl.length === 2 ? 8 - hd.length - tl.length : 0;
  if (dbl.length === 2 ? fill < 1 : hd.length !== 8) return null;
  const parts = [...hd, ...Array(fill).fill("0"), ...tl];
  if (parts.some(x => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
  return parts.reduce((a, x) => a * 65536n + BigInt(parseInt(x, 16)), 0n);
}
function net(s) {
  const [ip, len, extra] = s.split("/");
  if (extra !== undefined) return null;
  let space = "ipv4", bits = 32, n = v4(ip);
  if (n === null) { space = "ipv6"; bits = 128; n = v6(ip); }
  if (n === null) return null;
  const l = len === undefined ? bits : (/^\d+$/.test(len) && +len <= bits ? +len : null);
  if (l === null) return null;
  const host = (1n << BigInt(bits - l)) - 1n, lo = n & ~host;
  return {space, lo, hi: lo + host};
}
function addresses(a) {
  if (a.toLowerCase() === "any") return [net("0.0.0.0/0"), net("::/0")];
  if (/^sg-[0-9a-f]+$/.test(a)) return [{space: "sg:" + a, lo: 0n, hi: 0n}];
  if (/^pl-[0-9a-f]+$/.test(a)) return T.prefix_lists[a] ? T.prefix_lists[a].map(net) : [{space: "pl:" + a, lo: 0n, hi: 0n}];
  const n = net(a);
  if (!n) throw `bad address "${a}" (IP, CIDR, any, sg-..., pl-...)`;
  return [n];
}
function fmtIp(n, bits) {
  if (bits === 32) return [24n, 16n, 8n, 0n].map(s => (n >> s) & 255n).join(".");
  const g = []; for (let i = 7; i >= 0; i--) g.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  let best = [-1, 0];
  for (let i = 0; i < 8;) { if (g[i] !== "0") { i++; continue; } let j = i; while (j < 8 && g[j] === "0") j++;
    if (j - i > best[1]) best = [i, j - i]; i = j; }
  if (best[1] < 2) return g.join(":");
  return g.slice(0, best[0]).join(":") + "::" + g.slice(best[0] + best[1]).join(":");
}
function cidrs(space, lo, hi) {
  if (space !== "ipv4" && space !== "ipv6") return [space.split(":")[1]];
  const bits = space === "ipv4" ? 32 : 128, out = [];
  while (lo <= hi) {
    let s = 0n;
    while (s < BigInt(bits) && (lo & ((1n << (s + 1n)) - 1n)) === 0n && lo + (1n << (s + 1n)) - 1n <= hi) s++;
    out.push(fmtIp(lo, bits) + "/" + (bits - Number(s)));
    lo += 1n << s;
  }
  return out;
}

// --- protocol / ports (mirrors sg_rule_inventory.test_proto_ports and lib.boxes.fmt_proto_ports) ---
function protoPorts(proto, port) {
  const p = proto.toLowerCase();
  if (["all", "any", "-1"].includes(p)) return [ALLP, ALLO];
  const n = p in PN ? PN[p] : (/^\d+$/.test(p) && +p <= 255 ? +p : null);
  if (n === null) throw `unknown protocol "${proto}"`;
  const P = [BigInt(n), BigInt(n)];
  if (!port || port === "any" || port === "all") return [P, ALLO];
  if (n === 6 || n === 17) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(port), a = m && +m[1], b = m && (m[2] !== undefined ? +m[2] : a);
    if (!m || b < a || b > 65535) throw `bad port "${port}"`;
    return [P, [BigInt(a), BigInt(b)]];
  }
  if (n === 1 || n === 58) {
    const m = /^(\d+)(?:[/:](\d+))?$/.exec(port);
    if (!m || +m[1] > 255 || (m[2] !== undefined && +m[2] > 255)) throw `bad ICMP type/code "${port}"`;
    const base = BigInt(+m[1] * 256);
    return [P, m[2] === undefined ? [base, base + 255n] : [base + BigInt(+m[2]), base + BigInt(+m[2])]];
  }
  return [P, ALLO];
}
function fmtPP(pr, o) {
  if (pr[0] === 0n && pr[1] === 255n) return "all traffic";
  if (pr[0] !== pr[1]) return `protocols ${pr[0]}-${pr[1]}` + (o[0] === 0n && o[1] === 65535n ? "" : ` ports ${o[0]}-${o[1]}`);
  const p = Number(pr[0]), name = NAMES[p] || `proto ${p}`;
  if (o[0] === 0n && o[1] === 65535n) return NAMES[p] ? `${name} all` : name;
  if (p === 1 || p === 58) {
    const [lo, hi] = o, tc = v => `${v / 256n}/${v % 256n}`;
    if (lo % 256n === 0n && hi === lo + 255n) return `${name} type ${lo / 256n}`;
    if (lo === hi) return `${name} type ${lo / 256n} code ${lo % 256n}`;
    if (lo % 256n === 0n && hi % 256n === 255n) return `${name} types ${lo / 256n}-${hi / 256n}`;
    return `${name} type/code ${tc(lo)}-${tc(hi)}`;
  }
  return o[0] === o[1] ? `${name} ${o[0]}` : `${name} ${o[0]}-${o[1]}`;
}

// --- evaluation ---
const big = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
// Coalesce boxes that differ in one dimension only and touch there (mirrors lib.boxes.merge).
function merge3(boxes) {
  let bs = boxes, changed = true;
  while (changed) {
    changed = false;
    for (let d = 0; d < 3; d++) {
      const groups = new Map();
      bs.forEach(b => { const k = b.filter((_, i) => i !== d).map(x => x.join("-")).join("|");
        (groups.get(k) || groups.set(k, []).get(k)).push(b); });
      const out = [];
      for (const g of groups.values()) {
        g.sort((x, y) => big(x[d][0], y[d][0]));
        let cur = g[0];
        for (const b of g.slice(1)) {
          if (b[d][0] <= cur[d][1] + 1n) {
            changed = true;
            if (b[d][1] > cur[d][1]) { cur = cur.map(x => [...x]); cur[d][1] = b[d][1]; }
          } else { out.push(cur); cur = b; }
        }
        out.push(cur);
      }
      bs = out;
    }
  }
  return bs;
}
// Protocol / port intervals [[pr, ports]] as text, ports listed per protocol: "tcp 22, 443; udp 53".
function ppText(pps) {
  pps = [...pps].sort((x, y) => big(x[0][0], y[0][0]) || big(x[1][0], y[1][0]));
  const protos = new Map();
  pps.forEach(([pr, o]) => {
    const t = fmtPP(pr, o), m = /^(tcp|udp|icmp|icmpv6) (.*)$/.exec(t);
    if (m) (protos.get(m[1]) || protos.set(m[1], []).get(m[1])).push(m[2]); else protos.set(t, null);
  });
  return [...protos].map(([n, ps]) => ps ? `${n} ${ps.join(", ")}` : n).join("; ");
}
// Pieces [[space, box]] as text, ports listed per protocol for each address set:
// "tcp 22, 443, 8000-8100; udp 53 from 10.1.2.3/32".
function describe(pieces, prep) {
  const bySpace = new Map();
  pieces.forEach(([s, b]) => (bySpace.get(s) || bySpace.set(s, []).get(s)).push(b));
  const byAddr = new Map();
  for (const [s, bs] of bySpace) for (const b of merge3(bs)) {
    const k = `${s}|${b[2][0]}|${b[2][1]}`;
    (byAddr.get(k) || byAddr.set(k, {s, iv: b[2], pp: []}).get(k)).pp.push([b[0], b[1]]);
  }
  const byText = new Map();
  for (const e of byAddr.values()) {
    const text = ppText(e.pp);
    (byText.get(text) || byText.set(text, []).get(text)).push(...cidrs(e.s, e.iv[0], e.iv[1]));
  }
  return [...byText].map(([t, a]) => `${t} ${prep} ${a.join(", ")}`);
}
function runLine(line, on) {
  const parts = line.trim().split(/\s+/);
  if (![3, 4].includes(parts.length) || !DIRS[parts[0].toLowerCase()])
    return [{test: line, direction: "", verdict: "INVALID", by: [], off: [], ok: [], rem: [], okN: [], remN: [],
             detail: "expected: DIRECTION(ingress|egress|both) ADDRESS PROTOCOL [PORT]"}];
  let pp, addrs;
  try { pp = protoPorts(parts[2], parts[3]); addrs = addresses(parts[1]); }
  catch (e) { return [{test: line, direction: "", verdict: "INVALID", by: [], off: [], ok: [], rem: [], okN: [], remN: [],
                       detail: String(e)}]; }
  const noPort = parts.length === 3;
  return DIRS[parts[0].toLowerCase()].map(dir => {
    const rs = rules.filter(r => r.dir === dir), hits = new Map(), offHits = new Map(), rem = [], ok = [], matched = [];
    for (const a of addrs) {
      const box = [pp[0], pp[1], [a.lo, a.hi]], cover = [];
      for (const r of rs) for (const x of r.bx) {
        if (x.s !== a.space || !inter(box, x.b)) continue;
        if (on.has(r.key)) { cover.push(x.b); hits.set(r.key, r); } else offHits.set(r.key, r);
        matched.push({t: ruleText(r), on: on.has(r.key), b: [x.b[0], x.b[1]].map((iv, i) => [iv[0] > box[i][0] ? iv[0] : box[i][0], iv[1] < box[i][1] ? iv[1] : box[i][1]])});
      }
      let pieces = [box];
      for (const c of cover) { pieces = pieces.flatMap(p => sub(p, c)); if (!pieces.length) break; }
      pieces.forEach(p => rem.push([a.space, p]));
      // granted part = test box minus what is left (kept disjoint)
      let granted = [box];
      for (const p of pieces) { granted = granted.flatMap(g => sub(g, p)); if (!granted.length) break; }
      granted.forEach(g => ok.push([a.space, g]));
    }
    const verdict = !rem.length ? "ALLOWED" : hits.size ? "PARTIAL" : "DENIED";
    const prep = dir === "egress" ? "to" : "from", show = noPort || verdict === "PARTIAL";
    const okT = show ? describe(ok, prep) : [], remT = show ? describe(rem, prep) : [];
    // the test's own address written as "(tested address)", so tests that differ only by address group together
    const own = new Set(addrs.flatMap(a => cidrs(a.space, a.lo, a.hi)));
    const norm = xs => xs.map(x => { const i = x.lastIndexOf(` ${prep} `), as = x.slice(i + prep.length + 2).split(", ");
      return i >= 0 && as.length === own.size && as.every(a => own.has(a)) ? `${x.slice(0, i)} ${prep} (tested address)` : x; });
    return {test: line, direction: dir, verdict, detail: "", by: [...hits.values()].map(ruleText),
            off: [...offHits.values()].map(ruleText), ok: okT, rem: remT, okN: norm(okT), remN: norm(remT),
            pp, okB: ok, remB: rem, matched};
  });
}
const ruleText = r => `${r.g} ${r.id} ${r.text}` + (r.desc ? ` "${r.desc}"` : "");

// --- comparing two results, ignoring their addresses ---
const NOADDR = [0n, 0n];
const minus = (xs, ys) => xs.flatMap(x => { let p = [x];
  for (const y of ys) { p = p.flatMap(q => sub(q, y)); if (!p.length) break; } return p; });
const isect = (a, b) => inter(a, b) ? a.map((x, i) => [x[0] > b[i][0] ? x[0] : b[i][0], x[1] < b[i][1] ? x[1] : b[i][1]]) : null;
const isectAll = (xs, ys) => xs.flatMap(x => ys.map(y => isect(x, y)).filter(Boolean));
const disjoint = xs => xs.reduce((acc, x) => acc.concat(minus([x], acc)), []);
const ppOf = bs => bs.length ? ppText(merge3(bs).map(b => [b[0], b[1]])) : "";
// Protocol / ports allowed for every tested address (all), and for only some of them (partial).
function coverage(r) {
  const tested = [r.pp[0], r.pp[1], NOADDR];
  const all = minus([tested], r.remB.map(([, b]) => [b[0], b[1], NOADDR]));
  return {tested, all, partial: minus(disjoint(r.okB.map(([, b]) => [b[0], b[1], NOADDR])), all)};
}
// Test B against baseline A, on the protocol / ports both cover (C).
function pairStats(A, B) {
  const a = coverage(A), b = coverage(B), C = isect(a.tested, b.tested), st = {C};
  if (C) {
    const ca = isectAll(a.all, [C]), cb = isectAll(b.all, [C]);
    Object.assign(st, {both: isectAll(ca, cb), missing: minus(ca, cb), extra: minus(cb, ca),
      pa: isectAll(a.partial, [C]), pb: isectAll(b.partial, [C]), ncA: minus([a.tested], [C]), ncB: minus([b.tested], [C])});
  }
  // rules matching the compared protocol / ports only
  const within = (R, on) => C ? [...new Set(R.matched.filter(m => m.on === on && isect([...m.b, NOADDR], C)).map(m => m.t))] : [];
  const split = on => { const la = within(A, on), lb = within(B, on), sa = new Set(la), sb = new Set(lb);
    return {both: la.filter(x => sb.has(x)), base: la.filter(x => !sb.has(x)), here: lb.filter(x => !sa.has(x))}; };
  st.by = split(true); st.off = split(false);
  return st;
}
// Comparison table model: a baseline column and one column per compared test. JSON-safe, so exported
// comparisons can be checked by recomputing it.
function comparisonTable(A, Bs) {
  const S = Bs.map(B => pairStats(A, B)), rows = [], counts = Bs.map(() => 0);
  const row = (what, base, cells, always = true) => {
    const has = v => Array.isArray(v) ? v.length > 0 : !!v;
    if (!always && !has(base) && !cells.some(c => has(c.v))) return;
    cells.forEach((c, i) => { if (c.diff) counts[i]++; });
    rows.push({what, base, cells: cells.map(c => c.v), diff: cells.map(c => !!c.diff)});
  };
  const pp = xs => ppOf(xs || []) || "nothing", na = "none in common";
  row("Direction", A.direction, Bs.map(B => ({v: B.direction, diff: B.direction !== A.direction})));
  row("Verdict", A.verdict, Bs.map(B => ({v: B.verdict, diff: B.verdict !== A.verdict})));
  row("Protocol / ports compared", ppOf([coverage(A).tested]), S.map(s => ({v: s.C ? ppOf([s.C]) : na})));
  row("Not compared (tested by one only)", "", S.map(s => ({v: !s.C ? "" : [s.ncA.length ? `baseline only: ${pp(s.ncA)}` : "",
    s.ncB.length ? `this test only: ${pp(s.ncB)}` : ""].filter(Boolean).join("; ")})), false);
  row("Allowed for both", "", S.map(s => ({v: s.C ? pp(s.both) : na})));
  row("Allowed for baseline, not here", "", S.map(s => ({v: s.C ? pp(s.missing) : na, diff: s.C && s.missing.length > 0})));
  row("Allowed here, not for baseline", "", S.map(s => ({v: s.C ? pp(s.extra) : na, diff: s.C && s.extra.length > 0})));
  row("Allowed for part of the tested addresses", "", S.map(s => ({v: !s.C || (!s.pa.length && !s.pb.length) ? ""
    : `baseline: ${pp(s.pa)}; this test: ${pp(s.pb)}`, diff: s.C && ppOf(s.pa) !== ppOf(s.pb)})), false);
  row("Granted by", A.by, S.map(s => ({v: s.by.both})), false);
  row("Granted only for baseline", "", S.map(s => ({v: s.by.base, diff: s.by.base.length > 0})), false);
  row("Granted only here", "", S.map(s => ({v: s.by.here, diff: s.by.here.length > 0})), false);
  row("Switched-off rules matching both", A.off, S.map(s => ({v: s.off.both})), false);
  row("Switched-off rules matching only baseline", "", S.map(s => ({v: s.off.base, diff: s.off.base.length > 0})), false);
  row("Switched-off rules matching only here", "", S.map(s => ({v: s.off.here, diff: s.off.here.length > 0})), false);
  return {baseline: {test: A.test, direction: A.direction},
          against: Bs.map((B, i) => ({test: B.test, direction: B.direction, differences: counts[i]})), rows};
}
// The table as HTML (used in the report and in the exported comparison page).
function comparisonTableHtml(m) {
  const cell = v => Array.isArray(v) ? v.map(esc).join("<br>") : esc(v);
  const show = (what, v) => what === "Verdict" && BADGE[v] ? `<span class="badge ${BADGE[v]}">${v}</span>` : cell(v);
  const hl = ' style="background:var(--warn-bg)"';
  // fixed layout: the label column gets a set width, the baseline and each compared test share the rest
  return `<colgroup><col style="width:12em">${"<col>".repeat(m.against.length + 1)}</colgroup>` +
    `<tr><th></th><th>Baseline: ${esc(m.baseline.test)}</th>` +
    m.against.map(b => `<th>${esc(b.test)}</th>`).join("") + `</tr>` +
    `<tr><td></td><td></td>` + m.against.map(b => `<td>${b.differences
      ? `<span class="badge warn">${b.differences} difference(s)</span>` : `<span class="badge ok">same outcome</span>`}</td>`).join("") +
    `</tr>` + m.rows.map(r => `<tr><td class="nw"${r.diff.some(Boolean) ? ' style="font-weight:600"' : ""}>${esc(r.what)}` +
      `${r.diff.some(Boolean) ? " &#9679;" : ""}</td><td>${show(r.what, r.base)}</td>` +
      r.cells.map((c, i) => `<td${r.diff[i] ? hl : ""}>${show(r.what, c)}</td>`).join("") + `</tr>`).join("");
}
let cmpBase = "", cmpWith = null;           // cmpWith null = every other test
const resKey = r => `${r.direction}|${r.test}`;
function pickComparison(valid, base, withKeys) {
  const A = valid.find(r => resKey(r) === base);
  if (!A) return null;
  const Bs = (withKeys === null || withKeys === undefined ? valid.map(resKey).filter(k => k !== base) : withKeys)
    .map(k => valid.find(r => resKey(r) === k)).filter(B => B && B !== A);
  return Bs.length ? comparisonTable(A, Bs) : null;
}
function renderCompare(res) {
  const valid = res.filter(r => r.verdict !== "INVALID"), keys = valid.map(resKey);
  if (!keys.includes(cmpBase)) cmpBase = keys[0] || "";
  $("cbase").innerHTML = valid.map(r => `<option value="${esc(resKey(r))}">${esc(r.test)} (${esc(r.direction)})</option>`).join("");
  $("cbase").value = cmpBase;
  const sel = new Set(cmpWith === null ? keys : cmpWith);
  $("cwith").innerHTML = valid.filter(r => resKey(r) !== cmpBase).map(r => `<label class="check"><input type="checkbox"
    data-cw="${esc(resKey(r))}"${sel.has(resKey(r)) ? " checked" : ""}> ${esc(r.test)} (${esc(r.direction)})</label>`).join("");
  const m = valid.length < 2 ? null : pickComparison(valid, cmpBase, cmpWith);
  $("cmp").innerHTML = m ? comparisonTableHtml(m) : `<tr><td class="muted">${valid.length < 2
    ? "Add at least two valid tests to compare." : "Tick at least one test to compare with the baseline."}</td></tr>`;
}

// --- UI: tests, group / rule toggles, URL fragment state ---
const BADGE = {ALLOWED: "ok", PARTIAL: "warn", DENIED: "error", INVALID: "info"};
rules.forEach(r => r.key = r.g + "|" + r.id);
$("toggles").innerHTML = T.groups.map(g => {
  const rs = rules.filter(r => r.g === g.id);
  return `<div style="margin:6px 0"><label class="check"><input type="checkbox" data-g="${esc(g.id)}" checked>
    <b>${esc(g.id)}</b> ${esc(g.name)} <span class="muted">(${rs.length} rules)</span></label>
    <div style="padding-left:24px">` + (rs.map(r => `<label class="check" style="font:12.5px ui-monospace,Menlo,Consolas,monospace">
    <input type="checkbox" data-r="${esc(r.key)}" checked> ${esc(r.dir)} ${esc(r.id)} ${esc(r.text)}` +
    (r.desc ? ` <span class="muted">"${esc(r.desc)}"</span>` : "") + `</label>`).join("") || `<span class="muted">no rules</span>`) +
    `</div></div>`;
}).join("");
const boxes = sel => [...sec.querySelectorAll(sel)];
const H = new URLSearchParams(location.hash.slice(1));
const rid = c => c.dataset.r.split("|")[1];
$("lines").placeholder = "ingress 10.1.2.3 tcp 443\negress 0.0.0.0/0 udp 53";
const offGroups = () => boxes("input[data-g]").filter(c => !c.checked).map(c => c.dataset.g);
const offRules = () => boxes("input[data-r]").filter(c => !c.checked).map(rid);
function setState(sc) {
  $("sname").value = sc.name || ""; $("snotes").value = sc.notes || ""; $("lines").value = sc.tests || "";
  // compare: {base, with} (with null = every other test); older scenarios: [A, B]
  const c = sc.compare || {};
  [cmpBase, cmpWith] = Array.isArray(c) ? [c[0] || "", c[1] ? [c[1]] : null] : [c.base || "", c.with ?? null];
  const g = new Set(sc.groups_off || []), r = new Set(sc.rules_off || []);
  boxes("input[data-g]").forEach(c => c.checked = !g.has(c.dataset.g));
  boxes("input[data-r]").forEach(c => c.checked = !r.has(rid(c)));
}
function active() {
  const g = new Set(boxes("input[data-g]:checked").map(c => c.dataset.g));
  boxes("input[data-r]").forEach(c => c.disabled = !g.has(c.dataset.r.split("|")[0]));
  return new Set(boxes("input[data-r]:checked").filter(c => !c.disabled).map(c => c.dataset.r));
}
function save() {
  const p = new URLSearchParams(location.hash.slice(1)), set = (k, v) => v ? p.set(k, v) : p.delete(k);
  set("tests", $("lines").value);
  set("tests.goff", offGroups().join(","));
  set("tests.roff", offRules().join(","));
  set("tests.name", $("sname").value);
  set("tests.notes", $("snotes").value);
  set("tests.cbase", cmpBase);
  set("tests.cwith", cmpWith === null ? "" : JSON.stringify(cmpWith));
  history.replaceState(null, "", "#" + p.toString());
}
// Results of a scenario evaluated on its own on/off state (independent of the checkboxes).
function rawResults(sc) {
  const g = new Set(sc.groups_off || []), r = new Set(sc.rules_off || []);
  const on = new Set(rules.filter(x => !g.has(x.g) && !r.has(x.id)).map(x => x.key));
  return (sc.tests || "").split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#")).flatMap(l => runLine(l, on));
}
function evaluate(sc) {
  return rawResults(sc).map(({test, direction, verdict, ok, rem, by, detail}) =>
    ({test, direction, verdict, allowed: ok, not_allowed: rem, granted_by: by, detail}));
}
// The comparison of a scenario's selected pair (sc.compare = [key A, key B]), or null.
function comparisonOf(sc) {
  const c = sc.compare || {}, valid = rawResults(sc).filter(r => r.verdict !== "INVALID");
  const [base, withKeys] = Array.isArray(c) ? [c[0], c[1] ? [c[1]] : null] : [c.base, c.with ?? null];
  return pickComparison(valid, base, withKeys);
}
function run() {
  save();
  const on = active();
  $("oncount").textContent = `${on.size} of ${rules.length} rules on` +
    (on.size < rules.length ? ` (${boxes("input[data-g]:checked").length} of ${T.groups.length} groups)` : "");
  const lines = $("lines").value.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  const res = lines.flatMap(l => runLine(l, on));
  const n = v => res.filter(r => r.verdict === v).length;
  const rows = new Map();
  // grouped by outcome only: which rules grant it may differ between the tests of a row
  res.forEach(r => { const k = JSON.stringify([r.direction, r.verdict, r.detail, r.okN, r.remN]);
    (rows.get(k) || rows.set(k, []).get(k)).push(r); });
  $("cards").innerHTML = [[res.length, "results"], [rows.size, "distinct results"], [n("ALLOWED"), "allowed"], [n("PARTIAL"), "partial"],
    [n("DENIED"), "denied"], [n("INVALID"), "invalid"], [on.size, "rules on"]]
    .map(([v, l]) => `<div class="card"><b>${v}</b><span>${l}</span></div>`).join("");
  const ul = xs => xs.length ? xs.map(esc).join("<br>") : "";
  // Rules matching every test of a row are listed plainly; others name the tests they match.
  const attributed = (g, key) => {
    const per = new Map();
    g.forEach(x => x[key].forEach(t => (per.get(t) || per.set(t, []).get(t)).push(x.test)));
    return [...per].map(([t, ts]) => ts.length === g.length ? esc(t)
      : `${esc(t)} <span class="muted">(for ${ts.map(esc).join(", ")})</span>`).join("<br>");
  };
  // tests with identical outcomes share a row; a single test keeps its literal addresses
  $("out").innerHTML = res.length ? `<tr><th>Tests</th><th>Direction</th><th>Verdict</th><th>Allowed</th>` +
    `<th>Not allowed</th><th>Granted by</th><th>Switched-off rules that match</th></tr>` + [...rows.values()].map(g => {
    const r = g[0], one = g.length === 1;
    return `<tr><td class="nw">${ul(g.map(x => x.test))}</td><td>${esc(r.direction)}</td>` +
      `<td><span class="badge ${BADGE[r.verdict]}">${r.verdict}</span>${one ? "" : ` <span class="muted">&times;${g.length}</span>`}</td>` +
      `<td>${ul(one ? r.ok : r.okN)}</td><td>${r.detail ? esc(r.detail) : ul(one ? r.rem : r.remN)}</td>` +
      `<td>${attributed(g, "by")}</td><td>${attributed(g, "off")}</td></tr>`; }).join("") : "";
  renderCompare(res);
  save();
}
// --- scenarios: export for others, import, evidence check ---
const dataText = document.getElementById("extra-data").textContent;
const fingerprint = (async () => {
  if (!(window.crypto && crypto.subtle)) return null;
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(dataText));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("");
})();
const SCOPE = "Security groups only: network ACLs, route tables, firewalls and the far end's security groups " +
  "are not evaluated. Rules and prefix lists as of the report time.";
async function current() {
  const st = {tests: $("lines").value, groups_off: offGroups(), rules_off: offRules()};
  return {format: "sg_rule_inventory.scenario/1", name: $("sname").value.trim(), notes: $("snotes").value.trim(),
          ...st, compare: {base: cmpBase, with: cmpWith}, exported: new Date().toISOString(),
          report: {account: T.report.account, generated: T.report.generated, groups: T.groups.map(g => g.id),
                   rule_data_sha256: await fingerprint},
          results: evaluate(st), comparison: comparisonOf({...st, compare: {base: cmpBase, with: cmpWith}})};
}
// A copy of this page that opens on scenario `sc` (focus "compare" scrolls to the comparison).
function exportHtml(sc, file) {
  const doc = document.documentElement.cloneNode(true);
  doc.querySelector("#app").innerHTML = "";
  doc.querySelectorAll("#scenario").forEach(x => x.remove());
  const tag = document.createElement("script");
  tag.id = "scenario"; tag.type = "application/json";
  tag.textContent = JSON.stringify(sc).replace(/<\//g, "<\\/");
  doc.querySelector("#extra-data").after(tag);
  doc.querySelector("title").textContent = `${sc.focus === "compare" ? "Comparison" : "Scenario"}` +
    `${sc.name ? ": " + sc.name : ""} - ${document.title}`;
  download(file, "<!doctype html>\n" + doc.outerHTML, "text/html");
}
const slug = s => (s || "scenario").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60);
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], {type}));
  a.download = name; a.click();
}
async function evidence(sc, how) {
  const fp = await fingerprint, ids = new Set(rules.map(r => r.id)), gids = new Set(T.groups.map(g => g.id));
  const unknown = [...(sc.groups_off || []).filter(g => !gids.has(g)), ...(sc.rules_off || []).filter(r => !ids.has(r))];
  const exp = (sc.report || {}).rule_data_sha256;
  const now = JSON.stringify(evaluate(sc)), then = JSON.stringify(sc.results || []);
  const B = (cls, t) => `<span class="badge ${cls}">${esc(t)}</span>`;
  const checks = [
    !fp ? B("warn", "rule data not checked (browser has no crypto.subtle)")
      : exp === fp ? B("ok", "same rule data as when exported") : B("error", "rule data differs from when exported"),
    now === then ? B("ok", `results reproduced: ${(sc.results || []).length} result(s) identical`)
      : B("error", "results differ from the exported results"),
    unknown.length ? B("error", `${unknown.length} switched-off group(s)/rule(s) not in this report: ${unknown.join(", ")}`) : "",
    sc.comparison ? (JSON.stringify(comparisonOf(sc)) === JSON.stringify(sc.comparison)
      ? B("ok", "comparison reproduced") : B("error", "comparison differs from the exported comparison")) : "",
  ].filter(Boolean).join(" ");
  const cm = sc.comparison, nd = cm ? cm.against.filter(b => b.differences).length : 0;
  const cmpText = cm ? `Comparison: baseline ${cm.baseline.test} (${cm.baseline.direction}) against ` +
    `${cm.against.length} test(s); when exported ${nd} differed from the baseline and ` +
    `${cm.against.length - nd} had the same outcome.` : "";
  const offG = sc.groups_off || [], offR = sc.rules_off || [];
  const offText = !offG.length && !offR.length ? "nothing: every rule of every group is on"
    : [...offG.map(g => `group ${g}`), ...offR.map(r => { const x = rules.find(y => y.id === r);
        return x ? `${x.g} ${x.id} ${x.text}` : r; })].join("; ");
  const res = sc.results || [], cnt = v => res.filter(r => r.verdict === v).length;
  $("evidence").innerHTML = `<div class="card" style="margin:8px 0;padding:12px 16px">
    <div><strong style="font-size:16px">Scenario${sc.name ? ": " + esc(sc.name) : ""}</strong> <span class="muted">(${esc(how)})</span></div>
    ${sc.notes ? `<div>${esc(sc.notes)}</div>` : ""}
    <div class="muted">Exported ${esc(sc.exported || "?")} from the report for account ${esc((sc.report || {}).account || "?")}
      generated ${esc((sc.report || {}).generated || "?")}. Rule data SHA-256 ${esc(fp || "n/a")}.</div>
    <div style="margin:6px 0">Exported results: ${cnt("ALLOWED")} allowed, ${cnt("PARTIAL")} partial,
      ${cnt("DENIED")} denied, ${cnt("INVALID")} invalid.</div>
    ${cmpText ? `<div style="margin:6px 0">${esc(cmpText)}</div>` : ""}
    <div style="margin:6px 0">${checks}</div>
    <div><strong>Switched off:</strong> ${esc(offText)}</div>
    <div class="muted" style="margin-top:6px">${esc(SCOPE)}</div></div>`;
}
$("exphtml").addEventListener("click", async () => {
  const sc = await current();
  exportHtml(sc, `sg_scenario_${slug(sc.name)}.html`);
});
// The comparison alone: a small static page (no rule data) carrying a compact scenario of just the
// compared tests, which "Import scenario" in the full report re-runs to check it.
async function comparisonScenario() {
  const full = await current();
  if (!full.comparison) return null;
  const c = full.comparison, key = x => `${x.direction}|${x.test}`;
  const tests = [...new Set([c.baseline, ...c.against].map(x => x.test))].join("\n");
  const st = {tests, groups_off: full.groups_off, rules_off: full.rules_off,
              compare: {base: key(c.baseline), with: c.against.map(key)}};
  return {...full, ...st, focus: "compare", results: evaluate(st), comparison: comparisonOf(st),
          name: full.name || (c.against.length === 1 ? `${c.baseline.test} vs ${c.against[0].test}`
                                                     : `${c.baseline.test} vs ${c.against.length} tests`)};
}
function comparisonPage(sc) {
  const c = sc.comparison, r = sc.report || {}, nd = c.against.filter(b => b.differences).length;
  const offG = sc.groups_off || [], offR = sc.rules_off || [];
  const off = !offG.length && !offR.length ? "nothing: every rule of every group was on"
    : [...offG.map(g => `group ${g}`), ...offR.map(id => { const x = rules.find(y => y.id === id);
        return x ? `${x.g} ${x.id} ${x.text}` : id; })].join("; ");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc("Comparison: " + sc.name)}</title><style>
:root{--bg:#fff;--fg:#1d2329;--muted:#5b6670;--line:#d9dee3;--card:#f6f8fa;--error:#b42318;--error-bg:#fde8e7;
--warn:#9a6700;--warn-bg:#fff4d6;--info:#305d9c;--info-bg:#e6effa;--ok:#1a7f37;--ok-bg:#dcf5e3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1418;--fg:#e3e8ec;--muted:#97a3ad;--line:#2c353d;--card:#161d23;
--error:#ff8a80;--error-bg:#3d1714;--warn:#f2c14e;--warn-bg:#3a2e0e;--info:#8ab4f8;--info-bg:#14243b;--ok:#6fdc8c;--ok-bg:#12321e}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 6px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:12px 0}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{text-align:left;vertical-align:top;padding:6px 8px;
border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:12px}td{font:12.5px ui-monospace,Menlo,Consolas,monospace}
table.cmp{table-layout:fixed;width:100%}table.cmp th,table.cmp td{white-space:normal;overflow-wrap:anywhere}.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;
font-weight:600;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.error{color:var(--error);background:var(--error-bg)}.warn{color:var(--warn);background:var(--warn-bg)}
.info{color:var(--info);background:var(--info-bg)}.ok{color:var(--ok);background:var(--ok-bg)}
</style></head><body>
<h1>Security group test comparison${sc.name ? ": " + esc(sc.name) : ""}</h1>
${sc.notes ? `<div>${esc(sc.notes)}</div>` : ""}
<div class="muted">Exported ${esc(sc.exported)} from the sg_rule_inventory report for account ${esc(r.account || "?")}
generated ${esc(r.generated || "?")}. Source rule data SHA-256 ${esc(r.rule_data_sha256 || "n/a")}.</div>
<div class="card"><div><b>Baseline:</b> ${esc(c.baseline.test)} (${esc(c.baseline.direction)}) &nbsp;
<b>Compared:</b> ${c.against.length} test(s): ${nd ? `<span class="badge warn">${nd} differ</span>` : ""}
${c.against.length - nd ? `<span class="badge ok">${c.against.length - nd} same outcome</span>` : ""}</div>
<div style="margin-top:6px"><b>Switched off:</b> ${esc(off)}</div></div>
<table class="cmp">${comparisonTableHtml(c)}</table>
<div class="muted">Addresses are ignored: the comparison covers verdict, the protocol / ports allowed (on the protocol /
ports both tests cover) and the rules involved. ${esc(SCOPE)}</div>
<div class="muted" style="margin-top:6px">To verify: open the full report with the same rule data SHA-256 and load this file
with "Import scenario"; it re-runs the tests and checks the comparison is reproduced.</div>
<script id="scenario" type="application/json">${JSON.stringify(sc).replace(/<\//g, "<\\/")}</script>
</body></html>`;
}
$("cmphtml").addEventListener("click", async () => {
  const sc = await comparisonScenario();
  if (sc) download(`sg_comparison_${slug(sc.name)}.html`, comparisonPage(sc), "text/html");
});
$("cmpcsv").addEventListener("click", async () => {
  const c = (await current()).comparison;
  if (!c) return;
  const q = v => { v = Array.isArray(v) ? v.join("; ") : String(v ?? ""); return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
  // one column per test; a cell that differs from the baseline is prefixed "[differs] "
  const lines = [["what", `baseline: ${c.baseline.test} (${c.baseline.direction})`,
                  ...c.against.map(b => `${b.test} (${b.direction})`)].map(q).join(",")]
    .concat([["differences", "", ...c.against.map(b => String(b.differences))].map(q).join(",")])
    .concat(c.rows.map(r => [r.what, r.base, ...r.cells.map((v, i) =>
      (r.diff[i] ? "[differs] " : "") + (Array.isArray(v) ? v.join("; ") : v))].map(q).join(",")));
  download(`sg_comparison_${slug(c.baseline.test)}.csv`, lines.join("\n"), "text/csv");
});
$("expjson").addEventListener("click", async () =>
  download(`sg_scenario_${slug($("sname").value)}.json`, JSON.stringify(await current(), null, 2), "application/json"));
$("impbtn").addEventListener("click", () => $("impfile").click());
$("impfile").addEventListener("change", async e => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    const text = await f.text();
    // a scenario JSON, or an exported page (comparison or scenario report) carrying one
    const m = /<script id="scenario" type="application\/json">([\s\S]*?)<\/script>/.exec(text);
    const sc = JSON.parse(m ? m[1] : text);
    if (sc.format !== "sg_rule_inventory.scenario/1") throw "not an sg_rule_inventory scenario file";
    setState(sc); run(); evidence(sc, `imported from ${f.name}`);
  } catch (err) { $("evidence").innerHTML = `<div class="card"><span class="badge error">import failed</span> ${esc(String(err))}</div>`; }
  e.target.value = "";
});
$("add").addEventListener("click", () => {
  const a = $("addr").value.trim();
  if (!a) return $("addr").focus();
  const line = [$("dir").value, a, $("proto").value.trim() || "tcp", $("port").value.trim()].filter(Boolean).join(" ");
  $("lines").value = ($("lines").value.trim() ? $("lines").value.replace(/\s*$/, "\n") : "") + line;
  run();
});
$("addr").addEventListener("keydown", e => { if (e.key === "Enter") $("add").click(); });
$("port").addEventListener("keydown", e => { if (e.key === "Enter") $("add").click(); });
$("clear").addEventListener("click", () => { $("lines").value = ""; run(); });
$("allon").addEventListener("click", e => { e.preventDefault(); boxes("input[data-g], input[data-r]").forEach(c => c.checked = true); run(); });
$("lines").addEventListener("input", run);
$("cbase").addEventListener("change", e => { cmpBase = e.target.value; run(); });
$("cwith").addEventListener("change", () => {
  const all = boxes("input[data-cw]"), on = all.filter(c => c.checked).map(c => c.dataset.cw);
  cmpWith = on.length === all.length ? null : on; run(); });
$("cwall").addEventListener("click", () => { cmpWith = null; run(); });
$("cwnone").addEventListener("click", () => { cmpWith = []; run(); });
sec.addEventListener("change", e => { if (e.target.dataset.g || e.target.dataset.r) run(); });
$("sname").addEventListener("input", save);
$("snotes").addEventListener("input", save);
// start from the URL fragment if it holds a view, else from a scenario embedded by "Download scenario report"
const embedded = document.getElementById("scenario");
const fromHash = ["tests", "tests.goff", "tests.roff", "tests.name", "tests.notes"].some(k => H.has(k));
if (fromHash) setState({name: H.get("tests.name"), notes: H.get("tests.notes"), tests: H.get("tests"),
  compare: H.has("tests.cbase") ? {base: H.get("tests.cbase"), with: H.get("tests.cwith") ? JSON.parse(H.get("tests.cwith")) : null}
    : [H.get("tests.ca") || "", H.get("tests.cb") || ""],
  groups_off: (H.get("tests.goff") || "").split(",").filter(Boolean), rules_off: (H.get("tests.roff") || "").split(",").filter(Boolean)});
let shared = null;
if (embedded) {
  try { shared = JSON.parse(embedded.textContent); } catch (err) { shared = null; }
  if (shared && !fromHash) setState(shared);
}
run();
if (shared) evidence(shared, fromHash ? "embedded in this file; the view below comes from the URL" : "embedded in this file")
  .then(() => { if (shared.focus === "compare" && !fromHash) $("evidence").scrollIntoView(); });
})();
"""


def tester_data(payload: dict, groups: list[SG], rules: dict[str, list[SgRule]],
                prefix_lists: dict[str, list[str]]) -> tuple[str, str]:
    """The HTML tester's data as embedded JSON text, and its SHA-256.

    The data holds the report identity, groups, rules with their boxes (addresses as decimal
    strings, IPv6 needs BigInt) and prefix list entries. The hash is taken over the exact
    embedded text, so the page can recompute it and an exported scenario can be tied back to
    this run (the text and JSON reports print the same value). It is a consistency check,
    not a signature.
    """
    data = {"report": {"account": payload["account"], "generated": payload["generated"]},
            "groups": [{"id": g.group_id, "name": g.name} for g in groups],
            "prefix_lists": prefix_lists,
            "rules": [{"g": g.group_id, "id": r.rule_id, "dir": r.direction, "text": str(r), "desc": r.description,
                       "boxes": [[sp, b[0][0], b[0][1], b[1][0], b[1][1], str(b[2][0]), str(b[2][1])]
                                 for sp, b in r.boxes]}
                      for g in groups for r in rules[g.group_id]]}
    text = json.dumps(data, default=str).replace("</", "<\\/")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_html(payload: dict, rows: list[RuleRow], combined: list[dict], tester_text: str) -> str:
    """Interactive HTML: access tester, groups, rules (filter/sort by group), combined access."""
    gs = payload["groups"]
    group_rows = [{**g, "ingress": sum(r.group_id == g["group_id"] and r.direction == "ingress" for r in rows),
                   "egress": sum(r.group_id == g["group_id"] and r.direction == "egress" for r in rows)} for g in gs]
    tables = [
        {"id": "g", "title": "Groups", "row_label": "groups",
         "columns": [["group_id", "Group"], ["name", "Name"], ["owner", "Account"], ["vpc_id", "VPC"], ["region", "Region"],
                     ["via", "Via interface"], ["ingress", "Ingress rules"], ["egress", "Egress rules"],
                     ["description", "Description"]],
         "rows": group_rows, "filters": ["owner", "vpc_id", "region", "via"], "wrap": ["description"],
         "uniq": [["owner", "accounts"], ["vpc_id", "VPCs"], ["region", "regions"]], "sort": [["group_id", 1]]},
        {"id": "r", "title": "Rules", "row_label": "rules",
         "note": "Every rule of every group. 'Also granted' = how much of the rule's access other rules in this "
                 "collection grant too (fully = removing it changes nothing). Descriptions are for reference.",
         "columns": [["group_id", "Group"], ["group_name", "Group name"], ["account", "Account"], ["direction", "Direction"],
                     ["rule_id", "Rule ID"], ["protocol", "Protocol"], ["access", "Ports"], ["peer", "Peer"],
                     ["peer_kind", "Peer type"], ["peer_label", "Prefix list"], ["description", "Description"],
                     ["also_granted", "Also granted"], ["overlaps", "Overlapping rules"]],
         "rows": [asdict(r) for r in rows],
         "filters": ["group_id", "group_name", "account", "direction", "protocol", "access", "peer", "peer_kind",
                     "also_granted"],
         "wrap": ["description", "overlaps"],
         "badges": {"also_granted": {"fully": "warn", "partly": "info"}},
         "order": {"direction": ["ingress", "egress"], "also_granted": ["no", "partly", "fully"]},
         "uniq": [["group_id", "groups"], ["peer", "peers"], ["access", "protocol/ports"]],
         "by": {"key": "group_id", "label": "By group", "badge": None},
         "sort": [["group_id", 1], ["direction", 1], ["access", 1]]},
        {"id": "c", "title": "Combined access", "row_label": "protocol/port entries",
         "note": "Union of all rules of all groups, per direction: what an interface with every group attached "
                 "would allow. Addresses are merged CIDRs; sg-/pl- entries are group references and unreadable "
                 "prefix lists.",
         "columns": [["direction", "Direction"], ["access", "Protocol/ports"], ["address_count", "Addresses"],
                     ["addresses", "CIDRs / references"], ["granted_by", "Granted by"], ["rules", "Rules"]],
         "rows": combined, "filters": ["direction", "access", "granted_by"], "wrap": ["addresses", "rules"],
         "order": {"direction": ["ingress", "egress"]},
         "uniq": [["access", "protocol/ports"], ["granted_by", "groups"]],
         "sort": [["direction", 1], ["access", 1]]},
    ]
    d = payload["interface_deltas"]
    if len(d["interfaces"]) >= 2:
        tables.insert(0, {
            "id": "d", "title": "Interface differences", "row_label": "differences",
            "note": f"Access allowed on some of the {len(d['interfaces'])} interfaces / functions but not on others. Each one's "
                    "access is the union of its groups' rules, compared exactly (the same access written differently "
                    "is not a difference). Rules = the rules on the allowing interfaces that grant it. "
                    + ("No differences: every interface allows exactly the same access." if not d["access"] else ""),
            "columns": [["direction", "Direction"], ["access", "Protocol/ports"], ["addresses", "CIDRs / references"],
                        ["allowed_on", "Allowed on"], ["missing_on", "Not allowed on"], ["rules", "Rules"]],
            "rows": d["access"], "filters": ["direction", "access", "allowed_on", "missing_on"],
            "wrap": ["addresses", "rules", "allowed_on", "missing_on"], "order": {"direction": ["ingress", "egress"]},
            "uniq": [["access", "protocol/ports"], ["missing_on", "interfaces / functions missing access"]],
            "by": {"key": "missing_on", "label": "By interface / function missing access", "badge": None},
            "sort": [["direction", 1], ["access", 1]]})
        if d["groups"]:
            tables.insert(0, {
                "id": "ga", "title": "Group attachment differences", "row_label": "groups",
                "note": "Groups attached to some of the interfaces / functions but not all.",
                "columns": [["group_id", "Group"], ["attached_to", "Attached to"], ["missing_on", "Not attached to"]],
                "rows": d["groups"], "filters": ["missing_on"], "wrap": ["attached_to", "missing_on"],
                "sort": [["group_id", 1]]})
    if payload["interfaces"]:
        tables.insert(0, {"id": "i", "title": "Interfaces and functions", "row_label": "interfaces / functions",
                          "columns": [["id", "Interface / function"], ["kind", "Type"], ["account", "Account"],
                                      ["attachment", "Attached to"], ["vpc_id", "VPC"],
                                      ["region", "Region"], ["groups", "Groups"], ["description", "Description"]],
                          "rows": payload["interfaces"], "wrap": ["description", "attachment"], "filters": ["kind", "account"],
                          "sort": [["id", 1]]})
    who = (f"Accounts: {via_text(payload)}" if len(payload["accounts"]) > 1
           else f"Account {payload['account']} via {via_text(payload)}")
    meta = [f"{who} · generated {payload['generated']} · "
            "read-only report", f"Rule data SHA-256 {payload['rule_data_sha256']}"]
    meta += [f"Warning: prefix list {w}; matched by id only" for w in payload["warnings"]]
    meta += [f"Warning: {w}" for w in payload["target_warnings"]]
    cards = [(len(gs), "groups"), (len(payload["interfaces"]), "interfaces / functions"),
             (sum(r.direction == "ingress" for r in rows), "ingress rules"),
             (sum(r.direction == "egress" for r in rows), "egress rules"),
             (sum(r.also_granted == "fully" for r in rows), "fully overlapped rules"),
             (len({g["vpc_id"] for g in gs}), "VPCs"), (len(payload["accounts"]), "accounts")]
    if len(d["interfaces"]) >= 2:
        cards.append((len(d["access"]), "interface access differences"))
    return html_report.render("Security group rule inventory", meta=meta, cards=cards, tables=tables,
                              extra_html=TESTER_HTML, extra_script=TESTER_JS,
                              extra_data=tester_text)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 ok, 1 interfaces differ or a prefix list could not be read, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Report every rule of a set of security groups (or the groups on network interfaces, EC2 "
                    "instances or Lambda functions, in one or more accounts), "
                    "and their combined access, with an interactive traffic tester in the HTML report. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --region us-east-1 sg-0123456789abcdef0 sg-0fedcba9876543210
  %(prog)s arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0
  %(prog)s --profile prod-ro --region us-east-1 eni-0123456789abcdef0 sg-0aaaabbbbccccdddd

Traffic tests are run in the HTML report (no AWS access needed once it is saved).
""")
    p.add_argument("targets", nargs="+", metavar="TARGET",
                   help="Security group, network interface or EC2 instance ids / ARNs, or Lambda function ARNs "
                        "(comma-separated also accepted). An interface stands for its groups; an instance for each "
                        "of its interfaces; a function for the groups in its VPC configuration")
    p.add_argument("--profile", default=None,
                   help="AWS profile, used for its own account (and for bare ids). Other accounts named by "
                        "ARNs use their local profiles (never -priv/-cpar); with no ARNs, default AWS_PROFILE")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or None,
                   help="Region for bare ids (default AWS_REGION, then the profile's region)")
    p.add_argument("--show-rules", action="store_true",
                   help="Text report: list every rule per group, the combined access, and each interface "
                        "difference with its rules (default: summary and counts only). The HTML / CSV / JSON "
                        "reports always include everything")
    add_profile_args(p)
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        arn_accounts = spec_accounts(args.targets)
        bare_ids = any(not t.startswith("arn:") for t in split_specs(args.targets))
        profiles, bare_account = resolve_account_profiles(args, arn_accounts, bare_ids)
        default_region = args.region or (boto3.Session(profile_name=profiles[bare_account][0]).region_name
                                         if bare_account else None)
        targets = parse_account_targets(args.targets, default_region)
        for account, (profile, source) in sorted(profiles.items()):
            log.info("Account %s via %s (%s)", account, profile or "default credentials", source)

        # read each account with its own profile; groups / interfaces keep argument order
        groups, rules, warnings, interfaces, target_warnings = [], {}, [], [], []
        for account in dict.fromkeys(a or bare_account for a, _, _ in targets):
            profile = profiles[account][0]

            def session(region, profile=profile):
                """boto3 session for this account's profile in `region`."""
                return boto3.Session(profile_name=profile, region_name=region)
            mine = [(r, rid) for a, r, rid in targets if (a or bare_account) == account]
            group_targets, entries, tw = resolve_workloads(session, mine)
            interfaces += [{**e, "account": account} for e in entries]
            target_warnings += tw
            if group_targets:
                gs, rs, ws = load_groups(session, group_targets)
                groups += [g for g in gs if g.group_id not in rules]
                rules.update(rs)
                warnings += ws
        for w in target_warnings:
            log.warning("%s", w)
        if not groups:
            raise ValueError("no security groups: the targets given have none attached")
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", e)
        return 2

    fix_self_refs(rules)
    pls = known_prefix_lists(rules)
    rows = rule_rows(groups, rules)
    combined = combined_access(groups, rules)
    via = defaultdict(list)
    for n in interfaces:
        for gid in n["groups"]:
            via[gid].append(n["id"])
    accounts = sorted({g.owner for g in groups})
    used = {a: profiles[a] for a in accounts if a in profiles}
    payload = {"account": ", ".join(accounts),
               "accounts": [{"account": a, "profile": p, "profile_source": src} for a, (p, src) in used.items()],
               "profile": next(iter(used.values()))[0] if len(used) == 1 else None,
               "profile_source": next(iter(used.values()))[1] if len(used) == 1 else "",
               "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "interfaces": interfaces, "warnings": warnings, "target_warnings": target_warnings,
               "groups": [{**asdict(g), "via": via.get(g.group_id, [])} for g in groups],
               "rules": [asdict(r) for r in rows], "combined_access": combined,
               "interface_deltas": interface_deltas(interfaces, rules)}
    tester_text, payload["rule_data_sha256"] = tester_data(payload, groups, rules, pls)

    slug = groups[0].group_id if len(groups) == 1 else f"{groups[0].group_id}_and_{len(groups) - 1}_more"
    workloads = [rid for _, _, rid in targets if not rid.startswith("sg-")]
    if workloads and len(workloads) == len(targets):
        slug = workloads[0].replace("lambda:", "") if len(workloads) == 1 else f"{len(workloads)}_targets"
    paths = report_paths(args, TOOL, f"sgrules_{slug}")
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(r) for r in rows], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(payload, rows, combined, tester_text))

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(payload, rows, combined, args.show_rules)
        print_saved(paths)
    deltas = payload["interface_deltas"]
    return 1 if warnings or target_warnings or deltas["groups"] or deltas["access"] else 0


if __name__ == "__main__":
    sys.exit(main())
