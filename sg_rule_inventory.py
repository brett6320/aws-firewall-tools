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

  1. Takes any number of security group ids / ARNs and network interface
     ids / ARNs (an interface stands for the groups attached to it), all in
     one account.
  2. Reads every rule (describe_security_group_rules) and expands prefix
     lists to their current CIDRs.
  3. Reports:
       * every rule, per group (filter and sort by group, direction,
         protocol, peer ...), with whether the same access is also granted
         by other rules in the collection (no / partly / fully) - fully means
         the rule could be removed without changing the collection's access
       * the combined access of the collection per direction: merged CIDRs per
         protocol/port, and which groups grant each piece
  4. The HTML report embeds the rule data and an access tester (JavaScript,
     runs in the browser, no AWS access): enter DIRECTION ADDRESS PROTOCOL
     [PORT] tests and see ALLOWED / PARTIAL (with the part not granted) /
     DENIED, the rules that grant it, and the switched-off rules that would.
     Groups and individual rules can be switched off to see their effect.

Tester syntax (one test per line):

    ingress 10.1.2.3 tcp 443        traffic from 10.1.2.3 to tcp port 443
    egress 0.0.0.0/0 udp 53         traffic to anywhere on udp 53
    both 10.0.0.0/8 tcp 8000-8100   both directions, a CIDR and a port range
    in sg-0123456789abcdef0 tcp 5432    from members of a referenced group
    out pl-0123456789abcdef0 tcp 443    to a prefix list's CIDRs
    in 2001:db8::/64 icmpv6 128     ICMPv6 type 128 (PORT = TYPE[/CODE] for ICMP)
    in any all                      all traffic from anywhere (IPv4 and IPv6)

Ingress ADDRESS is the traffic's source, egress ADDRESS its destination; PORT
is the destination port. A missing PORT means every port. Group references
are matched by group id only (the report cannot know the members' addresses).

Profile: --profile if given. Otherwise the account in the ARNs selects the
local profile for that account (found by account id; profiles ending in -priv
or -cpar are never used; --account-profile forces one). With bare ids only,
AWS_PROFILE or the default credentials. The profile's account is verified
with sts:GetCallerIdentity before anything is read.

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

Exit codes: 0 ok, 1 a referenced prefix list could not be read, 2 fatal error.

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
from lib.boxes import PROTO_NAMES, Box, fmt_addrs, fmt_proto_ports, intersects, merge, remainder  # noqa: E402
from lib.output import (add_output_args, print_saved, report_paths, setup_logging, write_csv,  # noqa: E402
                        write_json, write_text)
from lib.security_groups import (SG, SgRule, check_account, load_groups, parse_targets,  # noqa: E402
                                 resolve_enis, resolve_profile, spec_accounts)

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
            out.append(RuleRow(g.group_id, g.name, r.direction, r.rule_id, proto_label(r), r.access(), r.peer,
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
    """How the account was read, e.g. 'profile acct-ro (local profile for account 1111...)'."""
    if not payload["profile"]:
        return "default credentials"
    return f"profile {payload['profile']} ({payload['profile_source']})"


def cut(addrs: list[str]) -> str:
    """Comma-joined addresses, cut at MAX_CIDRS_SHOWN."""
    more = f", ... {len(addrs) - MAX_CIDRS_SHOWN} more" if len(addrs) > MAX_CIDRS_SHOWN else ""
    return ", ".join(addrs[:MAX_CIDRS_SHOWN]) + more


def print_report(payload: dict, rows: list[RuleRow], combined: list[dict]) -> None:
    """Text report: interfaces, rules per group, combined access."""
    print(f"\nAccount {payload['account']} via {via_text(payload)}")
    for w in payload["warnings"]:
        print(f"[WARN ] PREFIX_LIST_UNRESOLVED {w}; matched by id only")
    for n in payload["interfaces"]:
        print(f"interface {n['eni_id']} ({n['attachment'] or '-'}, {n['vpc_id']}, {n['region']}) "
              f"-> {', '.join(n['groups']) or '(no groups)'}")
    for g in payload["groups"]:
        rs = [r for r in rows if r.group_id == g["group_id"]]
        print(f"\n=== {g['group_id']} ({g['name']}, {g['vpc_id']}, {g['region']})  "
              f"{sum(r.direction == 'ingress' for r in rs)} in / {sum(r.direction == 'egress' for r in rs)} out"
              + (f"  via {', '.join(g['via'])}" if g["via"] else ""))
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
    print(f"\n=== combined access of {len(payload['groups'])} group(s)")
    for direction in ("ingress", "egress"):
        sel = [c for c in combined if c["direction"] == direction]
        print(f"  {direction}:" + ("" if sel else " none"))
        prep = "to" if direction == "egress" else "from"
        for c in sel:
            print(f"    {c['access']} {prep} {cut(c['addresses'])}   [{', '.join(c['granted_by'])}]")


TESTER_HTML = """
<section id="tester"><h2>Access tester</h2>
<div class="muted">Checks flows against the combined rules switched on below, using the rule data in this file
(prefix lists as of the report time). Runs in the browser only; nothing is sent anywhere. Ingress address = source, egress address = destination, port = destination
port; ICMP port = TYPE[/CODE]; no port = every port. One test per line:
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
<details class="controls" style="display:block" data-t="tgl" open><summary style="cursor:pointer">
Groups and rules used by the tester: <b data-t="oncount"></b>
<button data-t="allon">All on</button></summary>
<div class="muted" style="margin:6px 0">Untick a group or a rule to see the effect of removing it.</div>
<div data-t="toggles"></div></details>
<div class="cards" data-t="cards"></div>
<div class="wrap"><table data-t="out"></table></div>
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
function runLine(line, on) {
  const parts = line.trim().split(/\s+/);
  if (![3, 4].includes(parts.length) || !DIRS[parts[0].toLowerCase()])
    return [{test: line, direction: "", verdict: "INVALID", by: [], off: [], rem: [],
             detail: "expected: DIRECTION(ingress|egress|both) ADDRESS PROTOCOL [PORT]"}];
  let pp, addrs;
  try { pp = protoPorts(parts[2], parts[3]); addrs = addresses(parts[1]); }
  catch (e) { return [{test: line, direction: "", verdict: "INVALID", by: [], off: [], rem: [], detail: String(e)}]; }
  return DIRS[parts[0].toLowerCase()].map(dir => {
    const rs = rules.filter(r => r.dir === dir), hits = new Map(), offHits = new Map(), rem = [];
    for (const a of addrs) {
      const box = [pp[0], pp[1], [a.lo, a.hi]], cover = [];
      for (const r of rs) for (const x of r.bx) {
        if (x.s !== a.space || !inter(box, x.b)) continue;
        if (on.has(r.key)) { cover.push(x.b); hits.set(r.key, r); } else offHits.set(r.key, r);
      }
      let pieces = [box];
      for (const c of cover) { pieces = pieces.flatMap(p => sub(p, c)); if (!pieces.length) break; }
      pieces.forEach(p => rem.push([a.space, p]));
    }
    const verdict = !rem.length ? "ALLOWED" : hits.size ? "PARTIAL" : "DENIED";
    const prep = dir === "egress" ? "to" : "from", byPP = new Map();
    if (verdict === "PARTIAL") {
      const groups = new Map();
      rem.forEach(([s, b]) => { const k = `${b[0]}|${b[1]}|${s}`; (groups.get(k) || groups.set(k, {s, b, r: []}).get(k)).r.push(b[2]); });
      for (const {s, b, r} of groups.values()) {
        r.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
        const m = [];
        r.forEach(iv => { const l = m[m.length - 1]; if (l && iv[0] <= l[1] + 1n) { if (iv[1] > l[1]) l[1] = iv[1]; } else m.push([...iv]); });
        const k = fmtPP(b[0], b[1]);
        byPP.set(k, (byPP.get(k) || []).concat(m.flatMap(iv => cidrs(s, iv[0], iv[1]))));
      }
    }
    return {test: line, direction: dir, verdict, detail: "", by: [...hits.values()].map(ruleText),
            off: [...offHits.values()].map(ruleText), rem: [...byPP].map(([k, a]) => `${k} ${prep} ${a.join(", ")}`)};
  });
}
const ruleText = r => `${r.g} ${r.id} ${r.text}` + (r.desc ? ` "${r.desc}"` : "");

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
$("lines").value = H.get("tests") || "";
$("lines").placeholder = "ingress 10.1.2.3 tcp 443\negress 0.0.0.0/0 udp 53";
const offG = new Set((H.get("tests.goff") || "").split(",")), offR = new Set((H.get("tests.roff") || "").split(","));
boxes("input[data-g]").forEach(c => c.checked = !offG.has(c.dataset.g));
boxes("input[data-r]").forEach(c => c.checked = !offR.has(c.dataset.r.split("|")[1]));
function active() {
  const g = new Set(boxes("input[data-g]:checked").map(c => c.dataset.g));
  boxes("input[data-r]").forEach(c => c.disabled = !g.has(c.dataset.r.split("|")[0]));
  return new Set(boxes("input[data-r]:checked").filter(c => !c.disabled).map(c => c.dataset.r));
}
function save() {
  const p = new URLSearchParams(location.hash.slice(1)), set = (k, v) => v ? p.set(k, v) : p.delete(k);
  set("tests", $("lines").value);
  set("tests.goff", boxes("input[data-g]").filter(c => !c.checked).map(c => c.dataset.g).join(","));
  set("tests.roff", boxes("input[data-r]").filter(c => !c.checked).map(c => c.dataset.r.split("|")[1]).join(","));
  history.replaceState(null, "", "#" + p.toString());
}
function run() {
  save();
  const on = active();
  $("oncount").textContent = `${on.size} of ${rules.length} rules on` +
    (on.size < rules.length ? ` (${boxes("input[data-g]:checked").length} of ${T.groups.length} groups)` : "");
  const lines = $("lines").value.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  const res = lines.flatMap(l => runLine(l, on));
  const n = v => res.filter(r => r.verdict === v).length;
  $("cards").innerHTML = [[res.length, "results"], [n("ALLOWED"), "allowed"], [n("PARTIAL"), "partial"],
    [n("DENIED"), "denied"], [n("INVALID"), "invalid"], [on.size, "rules on"]]
    .map(([v, l]) => `<div class="card"><b>${v}</b><span>${l}</span></div>`).join("");
  const ul = xs => xs.length ? xs.map(esc).join("<br>") : "";
  $("out").innerHTML = res.length ? `<tr><th>Test</th><th>Direction</th><th>Verdict</th><th>Granted by</th>` +
    `<th>Not granted</th><th>Switched-off rules that match</th></tr>` + res.map(r =>
    `<tr><td class="nw">${esc(r.test)}</td><td>${esc(r.direction)}</td>` +
    `<td><span class="badge ${BADGE[r.verdict]}">${r.verdict}</span></td><td>${ul(r.by)}</td>` +
    `<td>${r.detail ? esc(r.detail) : ul(r.rem)}</td><td>${ul(r.off)}</td></tr>`).join("") : "";
}
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
sec.addEventListener("change", e => { if (e.target.dataset.g || e.target.dataset.r) run(); });
run();
})();
"""


def tester_data(groups: list[SG], rules: dict[str, list[SgRule]], prefix_lists: dict[str, list[str]]) -> dict:
    """Groups, rules with their boxes (addresses as decimal strings, IPv6 needs BigInt) and
    prefix list entries for the HTML tester."""
    return {"groups": [{"id": g.group_id, "name": g.name} for g in groups],
            "prefix_lists": prefix_lists,
            "rules": [{"g": g.group_id, "id": r.rule_id, "dir": r.direction, "text": str(r), "desc": r.description,
                       "boxes": [[sp, b[0][0], b[0][1], b[1][0], b[1][1], str(b[2][0]), str(b[2][1])]
                                 for sp, b in r.boxes]}
                      for g in groups for r in rules[g.group_id]]}


def render_html(payload: dict, rows: list[RuleRow], combined: list[dict], groups: list[SG],
                rules: dict[str, list[SgRule]], prefix_lists: dict[str, list[str]]) -> str:
    """Interactive HTML: access tester, groups, rules (filter/sort by group), combined access."""
    gs = payload["groups"]
    group_rows = [{**g, "ingress": sum(r.group_id == g["group_id"] and r.direction == "ingress" for r in rows),
                   "egress": sum(r.group_id == g["group_id"] and r.direction == "egress" for r in rows)} for g in gs]
    tables = [
        {"id": "g", "title": "Groups", "row_label": "groups",
         "columns": [["group_id", "Group"], ["name", "Name"], ["vpc_id", "VPC"], ["region", "Region"],
                     ["via", "Via interface"], ["ingress", "Ingress rules"], ["egress", "Egress rules"],
                     ["description", "Description"]],
         "rows": group_rows, "filters": ["vpc_id", "region", "via"], "wrap": ["description"],
         "uniq": [["vpc_id", "VPCs"], ["region", "regions"]], "sort": [["group_id", 1]]},
        {"id": "r", "title": "Rules", "row_label": "rules",
         "note": "Every rule of every group. 'Also granted' = how much of the rule's access other rules in this "
                 "collection grant too (fully = removing it changes nothing). Descriptions are for reference.",
         "columns": [["group_id", "Group"], ["group_name", "Group name"], ["direction", "Direction"],
                     ["rule_id", "Rule ID"], ["protocol", "Protocol"], ["access", "Ports"], ["peer", "Peer"],
                     ["peer_kind", "Peer type"], ["peer_label", "Prefix list"], ["description", "Description"],
                     ["also_granted", "Also granted"], ["overlaps", "Overlapping rules"]],
         "rows": [asdict(r) for r in rows],
         "filters": ["group_id", "group_name", "direction", "protocol", "access", "peer", "peer_kind", "also_granted"],
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
    if payload["interfaces"]:
        tables.insert(0, {"id": "i", "title": "Interfaces", "row_label": "interfaces",
                          "columns": [["eni_id", "Interface"], ["attachment", "Attached to"], ["vpc_id", "VPC"],
                                      ["region", "Region"], ["groups", "Groups"], ["description", "Description"]],
                          "rows": payload["interfaces"], "wrap": ["description"], "sort": [["eni_id", 1]]})
    meta = [f"Account {payload['account']} via {via_text(payload)} · generated {payload['generated']} · "
            "read-only report"]
    meta += [f"Warning: prefix list {w}; matched by id only" for w in payload["warnings"]]
    cards = [(len(gs), "groups"), (len(payload["interfaces"]), "interfaces"),
             (sum(r.direction == "ingress" for r in rows), "ingress rules"),
             (sum(r.direction == "egress" for r in rows), "egress rules"),
             (sum(r.also_granted == "fully" for r in rows), "fully overlapped rules"),
             (len({g["vpc_id"] for g in gs}), "VPCs")]
    return html_report.render("Security group rule inventory", meta=meta, cards=cards, tables=tables,
                              extra_html=TESTER_HTML, extra_script=TESTER_JS,
                              extra_data=tester_data(groups, rules, prefix_lists))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 ok, 1 a prefix list could not be read, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Report every rule of a set of security groups (or the groups on network interfaces), "
                    "and their combined access, with an interactive traffic tester in the HTML report. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --region us-east-1 sg-0123456789abcdef0 sg-0fedcba9876543210
  %(prog)s arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0
  %(prog)s --profile prod-ro --region us-east-1 eni-0123456789abcdef0 sg-0aaaabbbbccccdddd

Traffic tests are run in the HTML report (no AWS access needed once it is saved).
""")
    p.add_argument("targets", nargs="+", metavar="SG_OR_ENI",
                   help="Security group or network interface ids / ARNs (comma-separated also accepted); "
                        "an interface stands for its attached groups")
    p.add_argument("--profile", default=None,
                   help="AWS profile. Default: the local profile for the account in the ARNs "
                        "(never -priv/-cpar), else AWS_PROFILE")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or None,
                   help="Region for bare ids (default AWS_REGION, then the profile's region)")
    add_profile_args(p)
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        accounts = spec_accounts(args.targets)
        if len(accounts) > 1:
            raise ValueError(f"all targets must be in one account; ARNs name {', '.join(sorted(accounts))}")
        account = next(iter(accounts), None)
        profile, source = resolve_profile(args, account)
        default_region = args.region or boto3.Session(profile_name=profile).region_name
        targets, _ = parse_targets(args.targets, default_region, min_groups=1, allow_enis=True)
        caller = check_account(profile, targets[0][0], account)
        log.info("Account %s via %s (%s)", caller, profile or "default credentials", source)

        def session(region):
            """boto3 session for the chosen profile in `region`."""
            return boto3.Session(profile_name=profile, region_name=region)
        group_targets, interfaces = resolve_enis(session, targets)
        if not group_targets:
            raise ValueError("no security groups: the interfaces given have none attached")
        groups, rules, warnings = load_groups(session, group_targets)
        owners = {g.owner for g in groups}
        if len(owners) > 1:
            raise ValueError(f"security groups must be in one account; owners: {', '.join(sorted(owners))}")
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
            via[gid].append(n["eni_id"])
    payload = {"account": caller, "profile": profile, "profile_source": source,
               "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "interfaces": interfaces, "warnings": warnings,
               "groups": [{**asdict(g), "via": via.get(g.group_id, [])} for g in groups],
               "rules": [asdict(r) for r in rows], "combined_access": combined}

    slug = groups[0].group_id if len(groups) == 1 else f"{groups[0].group_id}_and_{len(groups) - 1}_more"
    if interfaces and len(interfaces) == len(targets):
        slug = interfaces[0]["eni_id"] if len(interfaces) == 1 else f"{len(interfaces)}_interfaces"
    paths = report_paths(args, TOOL, f"sgrules_{slug}")
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(r) for r in rows], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(payload, rows, combined, groups, rules, pls))

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(payload, rows, combined)
        print_saved(paths)
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
