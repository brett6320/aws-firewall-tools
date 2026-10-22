#!/usr/bin/env python3
"""
AWS Firewall Manager (FMS) policy snapshots and diffs.

Intent: keep a reviewable history of Firewall Manager policies and spot
unintended changes, either between two points in time or between regions
that are meant to carry the same policies. FMS keeps no change history of
its own, so a policy edited by hand, or changed in one region but not
another, is otherwise easy to miss.

What it does (three subcommands):

  snapshot         Save every FMS policy, one JSON file per policy, in a
                   timestamped folder:
                   <snapshot-dir>/<YYYY-MM-DD_HHMMSS>/<region>/<name>__<id>.json
                   Each file has the `aws fms get-policy` shape
                   ({"Policy": ..., "PolicyArn": ...}, plus "TagList"), so it
                   can be passed straight to fmm_nacl_audit.py --policy-file.
                   index.json lists every policy saved.
  diff OLD NEW     Compare two snapshots (or a snapshot and `live`). Policies
                   are matched by region and policy id and reported as added,
                   removed, or changed field by field.
  compare-regions  Compare the policies of each region with a baseline region,
                   matched by policy name (or a tag value). Region names
                   inside values (e.g. ARNs) are ignored.

Before diffing, PolicyUpdateToken is dropped and ManagedServiceData (a JSON
string) is parsed, so changes inside it show with their full path, e.g.
SecurityServicePolicyData.ManagedServiceData.securityGroups[0].id.

Usage:

    ./fmm_policy_snapshot.py snapshot --region us-east-1,ca-central-1
    ./fmm_policy_snapshot.py diff previous latest
    ./fmm_policy_snapshot.py diff latest live
    ./fmm_policy_snapshot.py compare-regions --region us-east-1,ca-central-1

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Firewall Manager administrator (security) account id; its local profile
    # is found by account id. --profile overrides, AWS_PROFILE is the fallback.
    FMM_ADMIN_ACCOUNT=
    # Where snapshots are saved (<dir>/<YYYY-MM-DD_HHMMSS>/<region>/...)
    FMM_SNAPSHOT_DIR=./snapshots
    # Base directory for diff reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports (diff and compare-regions): text on screen, plus auto-saved HTML
(interactive: filter, sort, unique counts), CSV and JSON under
reports/fmm_policy_snapshot/YYYY-MM-DD/.

Exit codes: 0 no differences (snapshot: saved), 1 differences found,
2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.accounts import add_profile_args, caller_account, check_profile_args, resolve_admin_profile  # noqa: E402
from lib.aws_common import err_text, _g, get_client, get_session, list_policies, resolve_regions  # noqa: E402
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, print_saved, report_paths,  # noqa: E402
                        setup_logging, slugify, write_csv, write_json, write_text)

log = logging.getLogger("fmm_policy_snapshot")

TOOL = "fmm_policy_snapshot"
DROP_KEYS = {"PolicyUpdateToken"}                    # change on every save; never meaningful
REGION_IGNORE_KEYS = {"PolicyId", "PolicyArn"}       # differ per region by definition
COSMETIC_PATHS = {"PolicyName", "PolicyDescription"}  # reported as info, not warn
ABSENT = "(absent)"
MAX_VALUE = 200
SNAPSHOT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
@dataclass
class Record:
    """One saved or live policy: the get-policy document plus where it came from."""
    region: str
    policy: dict          # the Policy object
    arn: str = ""
    tags: dict | None = None
    file: str = ""

    @property
    def policy_id(self) -> str:
        """FMS policy id."""
        return self.policy.get("PolicyId", "")

    @property
    def name(self) -> str:
        """FMS policy name."""
        return self.policy.get("PolicyName", "")


@dataclass
class Finding:
    """One difference between two policy sets (or a policy missing from one side)."""
    severity: str        # warn | info
    code: str            # POLICY_ADDED | POLICY_REMOVED | POLICY_CHANGED | MISSING_IN_REGION | DIFFERS
    region: str
    policy_name: str
    policy_id: str
    other: str           # the other snapshot label or region
    path: str = ""
    old: str = ""
    new: str = ""
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


# --------------------------------------------------------------------------- #
# Fetching live policies
# --------------------------------------------------------------------------- #


def fetch_live(profile: str | None, regions: list[str], policy_filter: str | None = None,
               types: set[str] | None = None, with_tags: bool = True) -> list[Record]:
    """Read every matching FMS policy in the given regions.

    Fails closed: any list/get failure raises, so a snapshot or diff is never built from
    a partial set of policies. Tag lookups are best effort (tags are only used for
    --match-tag and stored for reference).
    """
    out: list[Record] = []
    for region in regions:
        fms = get_client("fms", get_session(profile, region))
        try:
            summaries = list(list_policies(fms))
        except (ClientError, BotoCoreError) as e:
            raise RuntimeError(f"{region}: list_policies failed: {err_text(e)}") from e
        log.info("Region %s: %d policies", region, len(summaries))
        for s in summaries:
            if policy_filter and policy_filter not in (s["PolicyId"], s["PolicyName"]):
                continue
            if types and s.get("SecurityServiceType") not in types:
                continue
            try:
                resp = fms.get_policy(PolicyId=s["PolicyId"])
            except (ClientError, BotoCoreError) as e:
                raise RuntimeError(f"{region}: get_policy {s['PolicyId']} failed: {err_text(e)}") from e
            arn = resp.get("PolicyArn") or s.get("PolicyArn", "")
            tags = None
            if with_tags and arn:
                try:
                    tags = {t["Key"]: t.get("Value", "")
                            for t in _g(fms.list_tags_for_resource(ResourceArn=arn), "TagList", [])}
                except (ClientError, BotoCoreError) as e:
                    log.warning("%s: list_tags_for_resource failed: %s", arn, err_text(e))
            out.append(Record(region=region, policy=resp["Policy"], arn=arn, tags=tags))
    return out


# --------------------------------------------------------------------------- #
# Snapshots on disk
# --------------------------------------------------------------------------- #
def save_snapshot(records: list[Record], snapshot_dir: str, admin_account: str, regions: list[str],
                  now: dt.datetime | None = None) -> Path:
    """Write one get-policy-shaped JSON file per policy plus index.json; return the folder."""
    now = now or dt.datetime.now()
    root = Path(snapshot_dir) / now.strftime("%Y-%m-%d_%H%M%S")
    if root.exists():
        raise ValueError(f"{root} already exists")
    index = {"taken_at": now.isoformat(timespec="seconds"), "admin_account": admin_account,
             "regions": regions, "policies": []}
    for r in records:
        rel = Path(r.region) / f"{slugify(r.name, 80)}__{r.policy_id}.json"
        doc = {"Policy": r.policy, "PolicyArn": r.arn}
        if r.tags is not None:
            doc["TagList"] = [{"Key": k, "Value": v} for k, v in sorted(r.tags.items())]
        write_json(root / rel, doc)
        index["policies"].append({"region": r.region, "id": r.policy_id, "name": r.name,
                                  "type": _g(r.policy, "SecurityServicePolicyData", {}).get("Type", ""),
                                  "arn": r.arn, "file": str(rel)})
    write_json(root / "index.json", index)
    return root


def list_snapshots(snapshot_dir: str) -> list[Path]:
    """Snapshot folders under snapshot_dir, oldest first."""
    base = Path(snapshot_dir)
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if p.is_dir() and SNAPSHOT_RE.match(p.name))


def resolve_snapshot(ref: str, snapshot_dir: str) -> Path:
    """Turn 'latest', 'previous', a snapshot folder name, or a path into a snapshot folder."""
    snaps = list_snapshots(snapshot_dir)
    if ref in ("latest", "previous"):
        need = 1 if ref == "latest" else 2
        if len(snaps) < need:
            raise ValueError(f"'{ref}' needs at least {need} snapshot(s) in {snapshot_dir}, found {len(snaps)}")
        return snaps[-need]
    p = Path(ref)
    if not p.is_dir() and (Path(snapshot_dir) / ref).is_dir():
        p = Path(snapshot_dir) / ref
    if not p.is_dir():
        raise ValueError(f"snapshot not found: {ref}")
    return p


def load_snapshot(path: Path) -> list[Record]:
    """Read every policy file of a snapshot folder (<region>/<file>.json)."""
    out: list[Record] = []
    for f in sorted(path.glob("*/*.json")):
        with open(f, encoding="utf-8") as fh:
            doc = json.load(fh)
        if "Policy" not in doc:
            log.warning("%s: no Policy object, skipped", f)
            continue
        tags = {t["Key"]: t.get("Value", "") for t in doc["TagList"]} if "TagList" in doc else None
        out.append(Record(region=f.parent.name, policy=doc["Policy"], arn=doc.get("PolicyArn", ""),
                          tags=tags, file=str(f)))
    if not out:
        raise ValueError(f"no policy files in snapshot {path}")
    return out


def _region_args(args) -> list[str]:
    """Regions named with --region (repeatable / comma-separated), in order."""
    out: list[str] = []
    for item in args.region or []:
        out += [r.strip() for r in item.split(",") if r.strip() and r.strip() not in out]
    return out


def _policy_type(r: Record) -> str:
    """SecurityServicePolicyData.Type of a record's policy."""
    return _g(r.policy, "SecurityServicePolicyData", {}).get("Type", "")


def load_source(ref: str, args) -> tuple[str, list[Record], list[str]]:
    """(label, records, regions) for 'live' or a snapshot reference.

    Live: the regions read (from --region / --all-regions / AWS_REGION). Snapshot: the
    regions it holds, narrowed to --region when given. --policy / --type filter both.
    """
    types = set(args.type or [])
    if ref == "live":
        profile = resolve_admin_profile(args)
        regions = resolve_regions(profile, args.region, args.all_regions)
        return "live", fetch_live(profile, regions, args.policy, types or None), regions
    path = resolve_snapshot(ref, args.snapshot_dir)
    recs = load_snapshot(path)
    wanted = _region_args(args)
    if wanted:
        recs = [r for r in recs if r.region in wanted]
    if args.policy:
        recs = [r for r in recs if args.policy in (r.policy_id, r.name)]
    if types:
        recs = [r for r in recs if _policy_type(r) in types]
    index = path / "index.json"
    held = json.loads(index.read_text(encoding="utf-8")).get("regions") if index.exists() else None
    regions = wanted or held or sorted({p.name for p in path.iterdir() if p.is_dir()})
    return path.name, recs, list(regions)


# --------------------------------------------------------------------------- #
# Normalisation and diffing
# --------------------------------------------------------------------------- #
def normalise(policy: dict, region: str | None = None, drop: set[str] = frozenset()) -> dict:
    """Copy of a Policy ready for diffing.

    Drops PolicyUpdateToken (and `drop` keys), parses ManagedServiceData into a dict, and,
    when `region` is given, replaces that region name inside every string with '{region}'.
    """
    p = copy.deepcopy(policy)
    for k in DROP_KEYS | set(drop):
        p.pop(k, None)
    ssp = p.get("SecurityServicePolicyData")
    if isinstance(ssp, dict) and isinstance(ssp.get("ManagedServiceData"), str):
        try:
            ssp["ManagedServiceData"] = json.loads(ssp["ManagedServiceData"])
        except json.JSONDecodeError:
            pass   # keep the raw string; it still diffs as a value
    if region:
        p = _replace_region(p, region)
    return p


def _replace_region(v, region: str):
    """Recursively replace `region` with '{region}' in string values."""
    if isinstance(v, dict):
        return {k: _replace_region(x, region) for k, x in v.items()}
    if isinstance(v, list):
        return [_replace_region(x, region) for x in v]
    if isinstance(v, str):
        return v.replace(region, "{region}")
    return v


def render_value(v) -> str:
    """Compact one-line rendering of a value for reports (truncated)."""
    if v is ABSENT:
        return ABSENT
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)
    return s if len(s) <= MAX_VALUE else s[:MAX_VALUE - 3] + "..."


def _is_scalar(v) -> bool:
    """True for values that are not dicts or lists."""
    return not isinstance(v, (dict, list))


def diff_values(a, b, path: str = "") -> list[tuple[str, object, object]]:
    """Field-level differences between two JSON values as (dotted path, old, new).

    Dicts are compared key by key and lists of objects index by index. Lists of plain
    values (account ids, resource types, ...) are compared as sets, since their order
    carries no meaning: old holds the removed items, new the added ones.
    """
    out: list[tuple[str, object, object]] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            p = f"{path}.{k}" if path else str(k)
            if k not in a:
                out.append((p, ABSENT, b[k]))
            elif k not in b:
                out.append((p, a[k], ABSENT))
            else:
                out += diff_values(a[k], b[k], p)
    elif isinstance(a, list) and isinstance(b, list):
        if all(_is_scalar(x) for x in a + b):
            removed = sorted((x for x in a if x not in b), key=str)
            added = sorted((x for x in b if x not in a), key=str)
            if removed or added:
                out.append((path, removed or ABSENT, added or ABSENT))
        else:
            for i in range(max(len(a), len(b))):
                p = f"{path}[{i}]"
                if i >= len(a):
                    out.append((p, ABSENT, b[i]))
                elif i >= len(b):
                    out.append((p, a[i], ABSENT))
                else:
                    out += diff_values(a[i], b[i], p)
    elif a != b:
        out.append((path, a, b))
    return out


def _change_findings(code: str, rec: Record, other: str, diffs, region: str | None = None) -> list[Finding]:
    """Findings for each changed path of one policy (cosmetic paths as info)."""
    return [Finding(severity="info" if path in COSMETIC_PATHS else "warn", code=code,
                    region=region or rec.region, policy_name=rec.name, policy_id=rec.policy_id, other=other,
                    path=path, old=render_value(old), new=render_value(new))
            for path, old, new in diffs]


def diff_snapshots(old: list[Record], new: list[Record], old_label: str, new_label: str) -> list[Finding]:
    """Compare two policy sets matched by (region, policy id): added, removed and changed policies."""
    a = {(r.region, r.policy_id): r for r in old}
    b = {(r.region, r.policy_id): r for r in new}
    out: list[Finding] = []
    for key in sorted(set(a) | set(b)):
        if key not in a:
            r = b[key]
            out.append(Finding("warn", "POLICY_ADDED", r.region, r.name, r.policy_id, old_label,
                               detail=f"in {new_label}, not in {old_label}"))
        elif key not in b:
            r = a[key]
            out.append(Finding("warn", "POLICY_REMOVED", r.region, r.name, r.policy_id, new_label,
                               detail=f"in {old_label}, not in {new_label}"))
        else:
            diffs = diff_values(normalise(a[key].policy), normalise(b[key].policy))
            out += _change_findings("POLICY_CHANGED", b[key], f"{old_label} -> {new_label}", diffs)
    return out


def match_key(r: Record, tag: str | None) -> str | None:
    """Cross-region matching key: the policy name, or the value of tag `tag` (None if untagged)."""
    if not tag:
        return r.name
    return (r.tags or {}).get(tag)


def compare_regions(records: list[Record], baseline: str, regions: list[str], tag: str | None) -> list[Finding]:
    """Compare every region's policies with the baseline region's.

    Policies are matched by name (or tag value). Region names inside values and the
    policies' own ids/ARNs are ignored, so only real configuration differences remain.
    """
    out: list[Finding] = []
    by_region: dict[str, dict[str, Record]] = {rg: {} for rg in regions}
    for r in records:
        if r.region not in by_region:
            continue
        k = match_key(r, tag)
        if k is None:
            log.warning("%s %s: no %s tag; not compared", r.region, r.name, tag)
            continue
        if k in by_region[r.region]:
            log.warning("%s: several policies match %r; comparing the first (%s)", r.region, k,
                        by_region[r.region][k].policy_id)
            continue
        by_region[r.region][k] = r
    base = by_region[baseline]
    for region in regions:
        if region == baseline:
            continue
        here = by_region[region]
        for k in sorted(set(base) | set(here)):
            if k not in here:
                r = base[k]
                out.append(Finding("warn", "MISSING_IN_REGION", region, r.name, r.policy_id, baseline,
                                   detail=f"{baseline} has this policy; {region} does not"))
            elif k not in base:
                r = here[k]
                out.append(Finding("warn", "MISSING_IN_REGION", baseline, r.name, r.policy_id, region,
                                   detail=f"{region} has this policy; baseline {baseline} does not"))
            else:
                diffs = diff_values(normalise(base[k].policy, baseline, REGION_IGNORE_KEYS),
                                    normalise(here[k].policy, region, REGION_IGNORE_KEYS))
                out += _change_findings("DIFFERS", here[k], baseline, diffs, region)
    return out


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by policy, region, severity and path for reporting."""
    return sorted(findings, key=lambda f: (f.policy_name, f.region, SEVERITY_ORDER[f.severity], f.code, f.path))


def print_report(findings: list[Finding], title: str, compared: int) -> None:
    """Print the text report: a summary, then each policy's differences."""
    print(f"\n{title}\nPolicies compared: {compared}   Differences: {len(findings)}")
    if not findings:
        print("\nNo differences.")
        return
    cur = None
    for f in findings:
        hdr = (f.policy_name, f.policy_id, f.region)
        if hdr != cur:
            cur = hdr
            print(f"\n{f.region}  {f.policy_name} ({f.policy_id})")
        line = f"    [{f.severity.upper():<4}] {f.code}"
        if f.path:
            line += f"  {f.path}"
        print(line)
        if f.path:
            a, b = ("baseline", "region  ") if f.code == "DIFFERS" else ("old", "new")
            print(f"        {a}: {f.old}\n        {b}: {f.new}")
        if f.detail:
            print(f"        {f.detail}")


def render_html(findings: list[Finding], title: str, meta: list[str], compared: int) -> str:
    """Interactive HTML report of the differences."""
    sev = [f.severity for f in findings]
    cards = [(compared, "policies compared"), (len(findings), "differences"),
             (sev.count("warn"), "warn"), (sev.count("info"), "info")]
    table = {
        "id": "diffs", "title": "Differences", "row_label": "differences",
        "columns": [["severity", "Severity"], ["code", "Code"], ["region", "Region"],
                    ["policy_name", "Policy"], ["policy_id", "Policy id"], ["other", "Compared with"],
                    ["path", "Path"], ["old", "Old / baseline"], ["new", "New / region"], ["detail", "Detail"]],
        "rows": [asdict(f) for f in findings],
        "filters": ["severity", "code", "region", "policy_name"],
        "uniq": [["policy_name", "Policies"], ["region", "Regions"], ["path", "Paths"]],
        "wrap": ["path", "old", "new", "detail"],
        "badges": {"severity": SEVERITY_BADGES},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["policy_name", 1], ["region", 1], ["severity", 1]],
        "by": {"key": "policy_name", "label": "By policy", "badge": None},
    }
    return html_report.render(title, meta=meta, cards=cards, tables=[table])


def emit(args, findings: list[Finding], title: str, meta: list[str], compared: int, slug: str) -> int:
    """Write/print the reports for diff and compare-regions; return the exit code."""
    findings = sort_findings(findings)
    paths = report_paths(args, TOOL, slug)
    payload = {"title": title, "meta": meta, "compared": compared, "findings": [asdict(f) for f in findings]}
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(f) for f in findings], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(findings, title, meta, compared))
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_report(findings, title, compared)
        print_saved(paths)
    return 1 if findings else 0


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #
def cmd_snapshot(args) -> int:
    """Save every matching policy to a new timestamped snapshot folder."""
    profile = resolve_admin_profile(args)
    regions = resolve_regions(profile, args.region, args.all_regions)
    records = fetch_live(profile, regions, args.policy, set(args.type or []) or None)
    admin = caller_account(profile)
    root = save_snapshot(records, args.snapshot_dir, admin, regions)
    by_region = {rg: sum(r.region == rg for r in records) for rg in regions}
    print(f"\nSnapshot of {len(records)} policies (admin account {admin}) saved to {root}")
    for rg, n in by_region.items():
        print(f"  {rg}: {n}")
    return 0


def cmd_diff(args) -> int:
    """Compare two snapshots (or a snapshot and live).

    Only regions present on both sides are compared, so a snapshot holding more regions
    than were read live does not report the extra regions' policies as removed.
    """
    old_label, old, old_regions = load_source(args.old, args)
    new_label, new, new_regions = load_source(args.new, args)
    scope = set(old_regions) & set(new_regions)
    skipped = (set(old_regions) | set(new_regions)) - scope
    if skipped:
        log.warning("Regions only on one side, not compared: %s", ", ".join(sorted(skipped)))
    old = [r for r in old if r.region in scope]
    new = [r for r in new if r.region in scope]
    findings = diff_snapshots(old, new, old_label, new_label)
    compared = len({(r.region, r.policy_id) for r in old} | {(r.region, r.policy_id) for r in new})
    title = f"FMS policy diff: {old_label} -> {new_label}"
    meta = [f"Old: {old_label}", f"New: {new_label}", f"Regions: {', '.join(sorted(scope)) or '-'}"]
    return emit(args, findings, title, meta, compared, f"diff_{old_label}_vs_{new_label}")


def cmd_compare_regions(args) -> int:
    """Compare each region's policies with the baseline region's."""
    label, records, regions = load_source(args.source, args)
    baseline = args.baseline_region or (regions[0] if regions else None)
    if baseline and baseline not in regions:
        regions.insert(0, baseline)
    if not baseline or len(regions) < 2:
        raise ValueError("compare-regions needs at least two regions (--region a,b, or a snapshot holding two)")
    findings = compare_regions(records, baseline, regions, args.match_tag)
    compared = len({match_key(r, args.match_tag) for r in records if r.region in regions})
    title = f"FMS policies by region: baseline {baseline} vs {', '.join(r for r in regions if r != baseline)}"
    meta = [f"Source: {label}", f"Matched by: {'tag ' + args.match_tag if args.match_tag else 'policy name'}"]
    return emit(args, findings, title, meta, compared, f"regions_{label}_{baseline}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """The command-line parser with its three subcommands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="FMS administrator AWS profile; overrides --admin-account "
                                          "(default: profile for --admin-account, else AWS_PROFILE)")
    add_profile_args(common, admin=True)
    common.add_argument("--region", action="append",
                        help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    common.add_argument("--all-regions", action="store_true", help="Every enabled region that offers Firewall Manager")
    common.add_argument("--policy", help="Only this policy id or name")
    common.add_argument("--type", action="append", metavar="SECURITY_SERVICE_TYPE",
                        help="Only policies of this type, e.g. NETWORK_ACL_COMMON (repeatable)")
    common.add_argument("--snapshot-dir", default=os.getenv("FMM_SNAPSHOT_DIR", "./snapshots"),
                        help="Where snapshots live (default ./snapshots, env FMM_SNAPSHOT_DIR)")

    p = argparse.ArgumentParser(
        description="Save Firewall Manager policies as snapshots and diff them over time or across regions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s snapshot --region us-east-1,ca-central-1
  %(prog)s diff previous latest
  %(prog)s diff latest live --region us-east-1
  %(prog)s compare-regions --region us-east-1,ca-central-1
  %(prog)s compare-regions --source latest --baseline-region us-east-1
""")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("snapshot", parents=[common], help="Save every policy to a new snapshot folder")
    s.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    s.add_argument("-q", "--quiet", action="store_true", help="Warnings-only logging")

    d = sub.add_parser("diff", parents=[common], help="Compare two snapshots, or a snapshot and live")
    d.add_argument("old", help="Snapshot folder (path or name), 'latest', 'previous', or 'live'")
    d.add_argument("new", help="Snapshot folder (path or name), 'latest', 'previous', or 'live'")
    add_output_args(d)

    c = sub.add_parser("compare-regions", parents=[common], help="Compare policies across regions")
    c.add_argument("--source", default="live",
                   help="'live' (default), 'latest', 'previous', or a snapshot folder")
    c.add_argument("--baseline-region", help="Region the others are compared with (default: first region)")
    c.add_argument("--match-tag", metavar="KEY",
                   help="Match policies across regions by this tag's value instead of by name")
    add_output_args(c)
    return p


def main() -> int:
    """Command-line entry point. Returns 0 clean / saved, 1 differences, 2 fatal."""
    p = build_parser()
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)
    try:
        if args.command == "snapshot":
            return cmd_snapshot(args)
        if args.command == "diff":
            return cmd_diff(args)
        return cmd_compare_regions(args)
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
