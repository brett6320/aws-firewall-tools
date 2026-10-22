#!/usr/bin/env python3
"""
AWS Firewall Manager (FMS) compliance report.

Intent: show what Firewall Manager itself reports as non-compliant, per
policy, per member account and per resource, with the reason. This is the
ground truth to compare against this repo's own audits (fmm_nacl_audit.py,
fmm_rule_parity.py), and a work list for remediation.

What it does:

  1. Lists the Firewall Manager policies in one or more regions through the
     FMS administrator account (filter with --policy / --type).
  2. Records each policy's settings: type, remediation, resource types,
     whether unused FMS-managed resources are deleted, include/exclude maps.
  3. Reads each policy's compliance status per member account
     (fms:ListComplianceStatus): compliant or not, violator count,
     evaluation limit, last update, and issues (e.g. AWS Config or account
     access problems).
  4. For non-compliant accounts (all accounts with --details-all), reads the
     violating resources and the reason for each (fms:GetComplianceDetail).
  5. Optionally names accounts from AWS Organizations (--org-names).

Usage:

    ./fmm_compliance.py --region us-east-1
    ./fmm_compliance.py --all-regions --type NETWORK_ACL_COMMON --org-names
    ./fmm_compliance.py --policy prod-baseline-sg --account 111122223333

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports
    # Firewall Manager administrator (security) account id. Its local profile is
    # found by account id; --profile overrides, AWS_PROFILE is the fallback.
    FMM_ADMIN_ACCOUNT=

Reports: text on screen, plus auto-saved HTML (interactive: accounts,
violations and issues tables with filters, sort and unique counts), CSV
(violations and issues) and JSON under reports/fmm_compliance/YYYY-MM-DD/.

Exit codes: 0 everything compliant, 1 violations or warnings, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import datetime as dt
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
from lib.accounts import add_profile_args, check_profile_args, resolve_admin_profile  # noqa: E402
from lib.aws_common import err_text, _g, get_client, get_policy, get_session, list_policies, resolve_regions  # noqa: E402
from lib.output import (SEVERITY_BADGES, SEVERITY_ORDER, add_output_args, exit_code, print_saved,  # noqa: E402
                        report_paths, setup_logging, write_csv, write_json, write_text)

log = logging.getLogger("fmm_compliance")

TOOL = "fmm_compliance"
MAX_RESOURCES_SHOWN = 10


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class PolicyInfo:
    """Settings of one FMS policy that matter when reading its compliance."""
    region: str
    policy_id: str
    policy_name: str
    policy_type: str
    remediation_enabled: bool = False
    resource_types: list[str] = field(default_factory=list)
    delete_unused_managed: bool = False
    include_map: bool = False
    exclude_map: bool = False
    accounts: int = 0
    compliant: int = 0
    non_compliant: int = 0
    violators: int = 0


@dataclass
class AccountRow:
    """Compliance of one member account under one policy, as FMS reports it."""
    region: str
    policy_name: str
    policy_id: str
    policy_type: str
    account: str
    account_name: str = ""
    status: str = "UNKNOWN"         # COMPLIANT | NON_COMPLIANT | UNKNOWN
    violators: int = 0
    evaluation_limit_exceeded: bool = False
    last_updated: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A violating resource (VIOLATION) or a run-level problem (ISSUE, EVALUATION_LIMIT_EXCEEDED,
    NON_COMPLIANT_NO_DETAIL, FMS_ERROR)."""
    severity: str                   # error | warn | info
    code: str
    region: str
    policy_name: str = ""
    policy_id: str = ""
    policy_type: str = ""
    account: str = ""
    account_name: str = ""
    resource_type: str = ""
    resource_id: str = ""
    reason: str = ""
    metadata: str = ""
    detail: str = ""


CSV_COLUMNS = list(Finding.__dataclass_fields__)


def _ts(v) -> str:
    """Timestamp (datetime or string) as 'YYYY-MM-DD HH:MM:SS', or '' when absent."""
    if not v:
        return ""
    if isinstance(v, dt.datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def _metadata(md: dict | None) -> str:
    """Compact 'key=value; key=value' text for a violator's Metadata map."""
    return "; ".join(f"{k}={v}" for k, v in sorted((md or {}).items()))


# --------------------------------------------------------------------------- #
# FMS reads
# --------------------------------------------------------------------------- #
def org_account_names(profile: str | None) -> dict[str, str]:
    """{account id: name} from AWS Organizations, or {} (with a warning) when not permitted."""
    try:
        org = get_client("organizations", get_session(profile, "us-east-1"))
        names = {}
        for page in org.get_paginator("list_accounts").paginate():
            for a in _g(page, "Accounts", []):
                names[a["Id"]] = a.get("Name", "")
        log.info("Organizations: %d account names", len(names))
        return names
    except (ClientError, BotoCoreError) as e:
        log.warning("Organizations account names unavailable (%s); continuing without names", err_text(e))
        return {}


def policy_info(fms, region: str, summary: dict, findings: list[Finding]) -> PolicyInfo:
    """Build PolicyInfo from a ListPolicies summary, enriched with get_policy when it can be read."""
    info = PolicyInfo(region=region, policy_id=summary["PolicyId"], policy_name=summary.get("PolicyName", ""),
                      policy_type=summary.get("SecurityServiceType", ""),
                      remediation_enabled=bool(summary.get("RemediationEnabled")),
                      resource_types=[summary["ResourceType"]] if summary.get("ResourceType") else [],
                      delete_unused_managed=bool(summary.get("DeleteUnusedFMManagedResources")))
    try:
        pol = get_policy(fms, info.policy_id)
    except (ClientError, BotoCoreError) as e:
        findings.append(Finding("error", "FMS_ERROR", region, info.policy_name, info.policy_id, info.policy_type,
                                detail=f"get_policy: {err_text(e)} (settings from policy summary only)"))
        return info
    types = list(_g(pol, "ResourceTypeList", []))
    if pol.get("ResourceType") and pol["ResourceType"] not in types:
        types.insert(0, pol["ResourceType"])
    info.resource_types = types or info.resource_types
    info.remediation_enabled = bool(pol.get("RemediationEnabled", info.remediation_enabled))
    info.delete_unused_managed = bool(pol.get("DeleteUnusedFMManagedResources", info.delete_unused_managed))
    info.include_map = bool(_g(pol, "IncludeMap", {}))
    info.exclude_map = bool(_g(pol, "ExcludeMap", {}))
    return info


def account_status(entry: dict) -> tuple[str, int, bool]:
    """(status, violator count, evaluation limit exceeded) from one PolicyComplianceStatus entry.
    Any NON_COMPLIANT evaluation makes the account NON_COMPLIANT; no evaluations is UNKNOWN."""
    results = _g(entry, "EvaluationResults", [])
    statuses = {r.get("ComplianceStatus") for r in results}
    if "NON_COMPLIANT" in statuses:
        status = "NON_COMPLIANT"
    elif statuses == {"COMPLIANT"}:
        status = "COMPLIANT"
    else:
        status = "UNKNOWN"
    violators = sum(int(r.get("ViolatorCount") or 0) for r in results)
    limit = any(r.get("EvaluationLimitExceeded") for r in results)
    return status, violators, limit


def scan_policy(fms, info: PolicyInfo, accounts_filter: set[str], names: dict[str, str], details_all: bool,
                rows: list[AccountRow], findings: list[Finding]) -> None:
    """Read compliance status (and violation details) for every member account of one policy."""
    base = dict(region=info.region, policy_name=info.policy_name, policy_id=info.policy_id,
                policy_type=info.policy_type)
    try:
        entries = []
        for page in fms.get_paginator("list_compliance_status").paginate(PolicyId=info.policy_id):
            entries.extend(_g(page, "PolicyComplianceStatusList", []))
    except (ClientError, BotoCoreError) as e:
        findings.append(Finding("error", "FMS_ERROR", **base, detail=f"list_compliance_status: {err_text(e)}"))
        return
    for entry in sorted(entries, key=lambda x: x.get("MemberAccount", "")):
        account = entry.get("MemberAccount", "")
        if accounts_filter and account not in accounts_filter:
            continue
        status, violators, limit = account_status(entry)
        name = names.get(account, "")
        issues = {k: v for k, v in _g(entry, "IssueInfoMap", {}).items()}
        row = AccountRow(**base, account=account, account_name=name, status=status, violators=violators,
                         evaluation_limit_exceeded=limit, last_updated=_ts(entry.get("LastUpdated")))
        info.accounts += 1
        info.compliant += status == "COMPLIANT"
        info.non_compliant += status == "NON_COMPLIANT"
        acct = dict(base, account=account, account_name=name)
        found = 0
        if status == "NON_COMPLIANT" or details_all:
            try:
                detail = fms.get_compliance_detail(PolicyId=info.policy_id,
                                                   MemberAccount=account)["PolicyComplianceDetail"]
            except (ClientError, BotoCoreError) as e:
                findings.append(Finding("error", "FMS_ERROR", **acct, detail=f"get_compliance_detail: {err_text(e)}"))
                detail = None
            if detail is not None:
                for v in _g(detail, "Violators", []):
                    found += 1
                    findings.append(Finding("error", "VIOLATION", **acct, resource_type=v.get("ResourceType", ""),
                                            resource_id=v.get("ResourceId", ""),
                                            reason=v.get("ViolationReason", ""),
                                            metadata=_metadata(v.get("Metadata"))))
                limit = limit or bool(detail.get("EvaluationLimitExceeded"))
                issues.update(_g(detail, "IssueInfoMap", {}))
                if status == "NON_COMPLIANT" and found == 0:
                    expired = f"; detail expired at {_ts(detail.get('ExpiredAt'))}" if detail.get("ExpiredAt") else ""
                    findings.append(Finding("warn", "NON_COMPLIANT_NO_DETAIL", **acct,
                                            detail=f"FMS reports {violators} violator(s) but returned no "
                                                   f"violating resources{expired}"))
        row.evaluation_limit_exceeded = limit
        row.issues = [f"{k}: {v}" for k, v in sorted(issues.items())]
        if limit:
            findings.append(Finding("warn", "EVALUATION_LIMIT_EXCEEDED", **acct,
                                    detail="FMS evaluated only part of this account's resources; "
                                           "the violator list may be incomplete"))
        for service, message in sorted(issues.items()):
            findings.append(Finding("warn", "ISSUE", **acct, reason=service, detail=str(message)))
        info.violators += max(violators, found)
        rows.append(row)


def run(args, regions: list[str]) -> tuple[list[PolicyInfo], list[AccountRow], list[Finding], dict]:
    """Scan every matching policy in every region; return policies, account rows, findings and stats.

    Raises ValueError when policies could be listed in no region at all (fatal).
    """
    policies: list[PolicyInfo] = []
    rows: list[AccountRow] = []
    findings: list[Finding] = []
    accounts_filter = {a.strip() for item in args.account or [] for a in item.split(",") if a.strip()}
    types = {t.strip().upper() for item in args.type or [] for t in item.split(",") if t.strip()}
    names = org_account_names(args.profile) if args.org_names else {}
    listed = 0
    for region in regions:
        fms = get_client("fms", get_session(args.profile, region))
        try:
            summaries = list(list_policies(fms))
        except (ClientError, BotoCoreError) as e:
            findings.append(Finding("error", "FMS_ERROR", region, detail=f"list_policies: {err_text(e)}"))
            continue
        listed += 1
        for s in sorted(summaries, key=lambda x: x.get("PolicyName", "")):
            if args.policy and args.policy not in (s["PolicyId"], s.get("PolicyName")):
                continue
            if types and s.get("SecurityServiceType", "").upper() not in types:
                continue
            info = policy_info(fms, region, s, findings)
            log.info("Region %s policy %s (%s)", region, info.policy_name, info.policy_type)
            scan_policy(fms, info, accounts_filter, names, args.details_all, rows, findings)
            policies.append(info)
    if not listed:
        raise ValueError(f"could not list Firewall Manager policies in any region ({', '.join(regions)})")
    if args.policy and not policies:
        raise ValueError(f"policy {args.policy!r} not found in region(s) {', '.join(regions)}")
    findings.sort(key=lambda f: (f.region, f.policy_name, f.account, SEVERITY_ORDER[f.severity], f.code,
                                 f.reason, f.resource_type, f.resource_id))
    by_code: dict[str, int] = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    stats = {"regions": len(regions), "policies": len(policies),
             "account_rows": len(rows),
             "accounts": len({r.account for r in rows}),
             "non_compliant_accounts": len({r.account for r in rows if r.status == "NON_COMPLIANT"}),
             "violations": by_code.get("VIOLATION", 0),
             "by_code": dict(by_code)}
    return policies, rows, findings, stats


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(policies: list[PolicyInfo], rows: list[AccountRow], findings: list[Finding], stats: dict) -> None:
    """Print a summary per policy, then each non-compliant account's violations grouped by reason,
    then run-level issues."""
    print()
    print(f"Policies: {stats['policies']}   Accounts: {stats['accounts']}   "
          f"Non-compliant accounts: {stats['non_compliant_accounts']}   Violations: {stats['violations']}")
    viol = defaultdict(list)
    for f in findings:
        if f.code == "VIOLATION":
            viol[(f.region, f.policy_id, f.account)].append(f)
    for p in policies:
        print(f"\n{p.region}  {p.policy_name} ({p.policy_type})  remediation={'on' if p.remediation_enabled else 'off'}"
              f"  accounts: {p.compliant} compliant, {p.non_compliant} non-compliant"
              f"{f', {p.accounts - p.compliant - p.non_compliant} unknown' if p.accounts > p.compliant + p.non_compliant else ''}"
              f"  violators: {p.violators}")
        for r in rows:
            if (r.region, r.policy_id) != (p.region, p.policy_id) or r.status != "NON_COMPLIANT":
                continue
            name = f" ({r.account_name})" if r.account_name else ""
            print(f"    account {r.account}{name}: {r.violators} violator(s)")
            groups = defaultdict(list)
            for f in viol.get((r.region, r.policy_id, r.account), []):
                groups[f.reason].append(f)
            for reason, fs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                print(f"        {reason or '(no reason)'} ({len(fs)})")
                for f in fs[:MAX_RESOURCES_SHOWN]:
                    print(f"            {f.resource_type} {f.resource_id}")
                if len(fs) > MAX_RESOURCES_SHOWN:
                    print(f"            ... {len(fs) - MAX_RESOURCES_SHOWN} more (see CSV/JSON/HTML)")
    other = [f for f in findings if f.code != "VIOLATION"]
    if other:
        print("\nIssues:")
        for f in other:
            where = " ".join(x for x in (f.region, f.policy_name, f.account) if x)
            what = f"{f.reason}: {f.detail}" if f.reason else f.detail
            print(f"    [{f.severity.upper():<5}] {f.code:<26} {where}  {what}")
    if not policies:
        print("\nNo matching policies.")


def render_html(policies: list[PolicyInfo], rows: list[AccountRow], findings: list[Finding], stats: dict,
                regions: list[str]) -> str:
    """Interactive HTML: accounts table (compliant rows hidden by default), violations table and
    issues table, each with filters, sort and unique counts."""
    viol = [asdict(f) for f in findings if f.code == "VIOLATION"]
    issues = [asdict(f) for f in findings if f.code != "VIOLATION"]
    warn = sum(f.severity == "warn" for f in findings)
    errors = sum(f.code == "FMS_ERROR" for f in findings)
    cards = [(stats["policies"], "policies"), (stats["accounts"], "accounts"),
             (stats["non_compliant_accounts"], "non-compliant accounts"), (stats["violations"], "violations"),
             (warn, "warnings"), (errors, "FMS call errors")]
    meta = [f"Regions: {', '.join(regions)} · generated {dt.datetime.now():%Y-%m-%d %H:%M:%S}",
            "Compliance as reported by AWS Firewall Manager."]
    accounts = {
        "id": "accounts", "title": "Accounts", "row_label": "account rows",
        "note": "One row per policy and member account.",
        "columns": [["status", "Status"], ["policy_name", "Policy"], ["policy_type", "Type"], ["region", "Region"],
                    ["account", "Account"], ["account_name", "Name"], ["violators", "Violators"],
                    ["evaluation_limit_exceeded", "Eval limit"], ["last_updated", "Last updated"],
                    ["issues", "Issues"]],
        "rows": [{**asdict(r), "evaluation_limit_exceeded": "yes" if r.evaluation_limit_exceeded else ""}
                 for r in rows],
        "filters": ["status", "policy_name", "policy_type", "region", "account"],
        "uniq": [["account", "Accounts"], ["policy_name", "Policies"], ["region", "Regions"]],
        "wrap": ["issues"],
        "badges": {"status": {"NON_COMPLIANT": "error", "COMPLIANT": "ok", "UNKNOWN": "info"}},
        "order": {"status": ["NON_COMPLIANT", "UNKNOWN", "COMPLIANT"]},
        "sort": [["status", 1], ["policy_name", 1], ["account", 1]],
        "hide": {"key": "status", "values": ["COMPLIANT"], "label": "show compliant"},
        "by": {"key": "policy_name", "label": "By policy", "badge": None},
    }
    violations = {
        "id": "violations", "title": "Violations", "row_label": "violations",
        "note": "Resources FMS reports as violating a policy, with FMS's reason.",
        "columns": [["severity", "Severity"], ["code", "Code"], ["policy_name", "Policy"],
                    ["policy_type", "Type"], ["region", "Region"], ["account", "Account"],
                    ["account_name", "Name"], ["resource_type", "Resource type"], ["resource_id", "Resource"],
                    ["reason", "Reason"], ["metadata", "Metadata"]],
        "rows": viol,
        "filters": ["policy_name", "policy_type", "region", "account", "resource_type", "reason"],
        "uniq": [["account", "Accounts"], ["policy_name", "Policies"], ["resource_type", "Resource types"],
                 ["resource_id", "Resources"]],
        "wrap": ["metadata"],
        "badges": {"severity": SEVERITY_BADGES},
        "order": {"severity": list(SEVERITY_ORDER)},
        "sort": [["policy_name", 1], ["account", 1], ["reason", 1]],
        "by": {"key": "reason", "label": "By reason", "badge": None},
    }
    tables = [accounts, violations]
    if issues:
        tables.append({
            "id": "issues", "title": "Issues", "row_label": "issues",
            "note": "Problems that limit what FMS could evaluate, and calls that failed.",
            "columns": [["severity", "Severity"], ["code", "Code"], ["policy_name", "Policy"], ["region", "Region"],
                        ["account", "Account"], ["account_name", "Name"], ["reason", "Service"],
                        ["detail", "Detail"]],
            "rows": issues,
            "filters": ["severity", "code", "policy_name", "region", "account"],
            "uniq": [["account", "Accounts"], ["policy_name", "Policies"]],
            "wrap": ["detail"],
            "badges": {"severity": SEVERITY_BADGES},
            "order": {"severity": list(SEVERITY_ORDER)},
            "sort": [["severity", 1], ["code", 1]],
            "by": {"key": "code", "label": "By code", "badge": "severity"},
        })
    return html_report.render("FMS compliance report", meta=meta, cards=cards, tables=tables)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    """Command-line entry point. Returns 0 all compliant, 1 violations or warnings, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Report what AWS Firewall Manager itself flags as non-compliant: per policy, member "
                    "account and resource, with the reason.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --region us-east-1
  %(prog)s --all-regions --type NETWORK_ACL_COMMON --org-names
  %(prog)s --policy prod-baseline-sg --account 111122223333
""")
    p.add_argument("--profile", help="FMS administrator AWS profile; overrides --admin-account "
                                     "(default: profile for --admin-account, else AWS_PROFILE)")
    add_profile_args(p, admin=True)
    p.add_argument("--region", action="append",
                   help="Region(s): repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true", help="Every enabled region that offers Firewall Manager")
    p.add_argument("--policy", help="Only this policy (id or name)")
    p.add_argument("--type", action="append", metavar="TYPE",
                   help="Only policies of this SecurityServiceType (e.g. SECURITY_GROUPS_COMMON, "
                        "NETWORK_ACL_COMMON); repeatable / comma-separated")
    p.add_argument("--account", action="append", help="Only these member account(s); repeatable / comma-separated")
    p.add_argument("--details-all", action="store_true",
                   help="Read violation details for compliant accounts too (default: non-compliant only)")
    p.add_argument("--org-names", action="store_true",
                   help="Name accounts from AWS Organizations (organizations:ListAccounts); skipped if denied")
    add_output_args(p)
    args = p.parse_args()
    setup_logging(args)
    check_profile_args(p, args)

    try:
        args.profile = resolve_admin_profile(args)
        regions = resolve_regions(args.profile, args.region, args.all_regions)
        policies, rows, findings, stats = run(args, regions)
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2

    payload = {"stats": stats, "regions": regions,
               "policies": [asdict(x) for x in policies],
               "accounts": [asdict(r) for r in rows],
               "violations": [asdict(f) for f in findings if f.code == "VIOLATION"],
               "issues": [asdict(f) for f in findings if f.code != "VIOLATION"]}
    paths = report_paths(args, TOOL, "compliance_" + (args.policy or ",".join(sorted({t for t in args.type or []})) or "all"))
    if paths["json"]:
        write_json(paths["json"], payload)
    if paths["csv"]:
        write_csv(paths["csv"], [asdict(f) for f in findings], CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(policies, rows, findings, stats, regions))

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(policies, rows, findings, stats)
        print_saved(paths)
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
