#!/usr/bin/env python3
"""
Security group access gap check.

Intent: before replacing or consolidating security groups (moving workloads
from a legacy group to new ones, or checking that a standard group covers a
bespoke one), confirm that nothing the old group allowed is lost. Rules are
compared by the access they actually grant, so differences in how rules are
written (prefix lists vs. CIDRs, split or merged ranges) are not reported as
gaps, while real missing access is reported down to the exact CIDRs and ports.

Finds access granted by a "left" security group that the "right" security
group(s) do not grant. Groups are given as ARNs or group IDs, in one or more
accounts (several accounts via ARNs); the first is the left group and every
further group is a right group. With several right groups, left access is checked against their
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

Accounts: each account is read with its own profile. --profile is used for
its own account; every other account named by an ARN uses its local profile
(found by account id; profiles ending in -priv or -cpar are never used;
--account-profile forces one). Bare ids belong to the --profile account, else
to the single ARN account, else (no ARNs) to AWS_PROFILE or the default
credentials; next to ARNs from several accounts they are refused as
ambiguous. Every profile is verified with sts:GetCallerIdentity first.

Security group references are matched by group ID (a self-reference in the
left group matches a self-reference in any right group). Prefix lists that
cannot be read are compared by ID only and reported. Descriptions are shown
for reference only.

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Region for bare group IDs when --region not given (ARNs carry their own)
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports: text on screen, plus auto-saved HTML, CSV and JSON under
reports/sg_access_gap/YYYY-MM-DD/.

Usage:

    ./sg_access_gap.py --profile prod-admin LEFT_SG RIGHT_SG [RIGHT_SG ...]
    ./sg_access_gap.py LEFT_SG_ARN RIGHT_SG_ARN_IN_ANOTHER_ACCOUNT

Exit codes: 0 no gaps, 1 gaps or warnings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib.accounts import add_profile_args, check_profile_args  # noqa: E402
from lib.aws_common import get_client  # noqa: E402,F401  (also loads .env, sets up logging)
from lib.boxes import Box, fmt_addrs, fmt_proto_ports, intersects, merge, remainder  # noqa: E402
from lib.security_groups import (SG, SgRule, load_groups, parse_account_targets,  # noqa: E402
                                 resolve_account_profiles, split_specs, spec_accounts)

log = logging.getLogger("sg_access_gap")

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}
MAX_CIDRS_SHOWN = 8


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """Result for one left rule (or a run-level warning), as shown in every report format."""
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
    """Render uncovered boxes as text lines, one per protocol/port combination, CIDRs merged."""
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
    """Check the left group's rules against the combined right groups, per direction.

    Returns the findings and a one-row summary with a verdict per direction
    ('N gap(s)', 'covered' or 'identical').
    """
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
def load(session_factory, targets: list[tuple[str, str]]):
    """Groups in argument order, rules by group, and PREFIX_LIST_UNRESOLVED warnings
    (see lib.security_groups.load_groups)."""
    groups, rules, warnings = load_groups(session_factory, targets)
    return groups, rules, [Finding("warn", "PREFIX_LIST_UNRESOLVED", detail=f"{w}; compared by id only")
                           for w in warnings]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(groups: list[SG], rules, findings: list[Finding], summary: list[dict], show_covered: bool,
                 accounts: list[dict] | None = None) -> None:
    """Print the text report: accounts, groups, warnings, then per direction each gap with its
    absent access and the overlapping right rules (covered rules only with `show_covered`).
    """
    print()
    for a in accounts or []:
        print(f"account {a['account']} via {('profile ' + a['profile']) if a['profile'] else 'default credentials'} "
              f"({a['profile_source']})")
    multi = len({g.owner for g in groups}) > 1
    for i, g in enumerate(groups):
        print(f"{'left ' if i == 0 else 'right'}  {g}{'  account ' + g.owner if multi else ''}  rules: "
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
    """Badge colour for a direction verdict."""
    return "error" if "gap" in v else "ok"


def render_html(payload: dict, generated: str) -> str:
    """Build the static HTML report: groups, verdicts, gap tables per direction, and every
    group's full rule list.
    """
    e = html.escape

    def ul(items):
        """HTML bullet list, or nothing when empty."""
        return "<ul>" + "".join(f"<li class='mono'>{e(x)}</li>" for x in items) + "</ul>" if items else ""

    def badge(text, cls):
        """HTML badge span."""
        return f"<span class='badge {cls}'>{e(text)}</span>"

    def finding_rows(fs):
        """HTML table rows for a list of findings."""
        return "".join(
            f"<tr><td>{badge(f['severity'], f['severity'])}</td><td class='mono'>{e(f['code'])}</td>"
            f"<td class='mono'>{e(f['rule_id'])}<br>{e(f['rule'])}</td><td>{e(f['description'])}</td>"
            f"<td>{ul(f['uncovered'])}</td><td>{ul(f['related'])}</td><td>{e(f['detail'])}</td></tr>"
            for f in fs)

    head = ("<tr><th>Severity</th><th>Code</th><th>Left rule</th><th>Description</th><th>Absent from right</th>"
            "<th>Overlapping right rules</th><th>Detail</th></tr>")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
           f"<title>Security group access gap</title><style>{HTML_CSS}</style></head><body>",
           f"<h1>Security group access gap</h1><div class='muted'>Account {e(payload['account'])} &middot; "
           f"generated {e(generated)} &middot; access granted by the left group that the right group(s) combined do not grant "
           f"&middot; descriptions shown for reference, not compared</div>"]

    counts = payload["stats"]
    out.append("<div class='card stats'>" + "".join(
        f"<span><b>{e(k)}</b> {v}</span>" for k, v in sorted(counts.items())) + "</div>")

    out.append("<h2>Groups</h2><div class='wrap'><table><tr><th>Role</th><th>Group</th><th>Name</th><th>Account</th><th>VPC</th>"
               "<th>Region</th><th>Ingress rules</th><th>Egress rules</th></tr>")
    for i, g in enumerate(payload["groups"]):
        rs = payload["rules"][g["group_id"]]
        out.append(f"<tr><td>{'left' if i == 0 else 'right'}</td><td class='mono'>{e(g['group_id'])}</td>"
                   f"<td>{e(g['name'])}</td><td class='mono'>{e(g['owner'])}</td><td class='mono'>{e(g['vpc_id'])}</td>"
                   f"<td>{e(g['region'])}</td>"
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
    """Write the JSON, CSV and HTML reports to whichever paths are set."""
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
    """Command-line entry point. Returns 0 no gaps, 1 gaps or warnings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Find access granted by the left security group that the right group(s), combined, do not grant "
                    "(prefix lists expanded, overlapping CIDRs resolved).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-admin sg-0123456789abcdef0 sg-0fedcba9876543210
  %(prog)s --profile prod-admin arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \\
           arn:aws:ec2:us-west-2:111122223333:security-group/sg-0fedcba9876543210
  %(prog)s arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \\
           arn:aws:ec2:us-east-1:444455556666:security-group/sg-0fedcba9876543210
""")
    p.add_argument("groups", nargs="+", metavar="SG",
                   help="Security group ARNs or ids (comma-separated also accepted): LEFT RIGHT [RIGHT ...]; "
                        "left access is checked against the right groups' combined access. ARNs may name "
                        "different accounts")
    p.add_argument("--profile", default=None,
                   help="AWS profile, used for its own account (and for bare ids). Other accounts named by "
                        "ARNs use their local profiles (never -priv/-cpar); with no ARNs, default AWS_PROFILE")
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
    add_profile_args(p)
    args = p.parse_args()
    check_profile_args(p, args)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        arn_accounts = spec_accounts(args.groups)
        bare_ids = any(not t.startswith("arn:") for t in split_specs(args.groups))
        profiles, bare_account = resolve_account_profiles(args, arn_accounts, bare_ids)
        default_region = args.region or (boto3.Session(profile_name=profiles[bare_account][0]).region_name
                                         if bare_account else None)
        targets = [(a or bare_account, r, gid) for a, r, gid in
                   parse_account_targets(args.groups, default_region, allow_workloads=False)]
        if len(targets) < 2:
            raise ValueError("need at least two distinct security groups")
        for account, (profile, source) in sorted(profiles.items()):
            log.info("Account %s via %s (%s)", account, profile or "default credentials", source)
        # each account read with its own profile; groups keep argument order (first = left)
        by_id, rules, findings = {}, {}, []
        for account in dict.fromkeys(a for a, _, _ in targets):
            profile = profiles[account][0]
            gs, rs, fs = load(lambda r, profile=profile: boto3.Session(profile_name=profile, region_name=r),
                              [(r, gid) for a, r, gid in targets if a == account])
            by_id.update({g.group_id: g for g in gs})
            rules.update(rs)
            findings += fs
        groups = [by_id[gid] for _, _, gid in targets]
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
    if len({g.owner for g in groups}) > 1:
        findings.insert(0, Finding("info", "DIFFERENT_ACCOUNTS",
                                   detail=f"groups are in {len({g.owner for g in groups})} accounts; group references "
                                          "are matched by group id"))
    used = sorted({g.owner for g in groups})
    accounts = [{"account": a, "profile": profiles[a][0], "profile_source": profiles[a][1]} for a in used if a in profiles]
    by_code = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    payload = {"account": ", ".join(used), "accounts": accounts, "groups": [asdict(g) for g in groups], "summary": summary,
               "stats": dict(by_code),
               "rules": {g.group_id: [{**{k: v for k, v in asdict(r).items() if k != "boxes"}, "rule": str(r)}
                                      for r in rules[g.group_id]] for g in groups},
               "findings": [asdict(f) for f in findings]}

    paths = {}
    if not args.no_save:
        now = dt.datetime.now()
        slug = "_".join(g.group_id for g in groups)[:80]
        stem = Path(args.out_dir) / "sg_access_gap" / now.strftime("%Y-%m-%d") / f"{now.strftime('%H%M%S')}_sggap_{slug}"
        paths = {"json": f"{stem}.json", "csv": f"{stem}.csv", "html": f"{stem}.html"}
    json_path = args.json_out or paths.get("json")
    csv_path = args.csv_out or paths.get("csv")
    html_path = args.html_out or paths.get("html")
    write_outputs(payload, findings, json_path, csv_path, html_path)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_report(groups, rules, findings, summary, args.show_covered, accounts)
        saved = [x for x in (html_path, csv_path, json_path) if x]
        if saved:
            print("\nSaved:\n" + "\n".join(f"  {x}" for x in saved))

    return 1 if any(f.severity in ("error", "warn") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
