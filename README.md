# fmm_parity — AWS Firewall Manager rule parity review

Walks every AWS Firewall Manager (FMS) policy in one or more regions, expands
the rules those policies carry, and reports every rule where any **A target**
(IP + protocol + port, or a managed prefix list) is present but the expected
**B target(s)** are missing alongside it. Read-only; no mutating API calls.

Rule sources inspected per policy type:

| FMS policy type | Rules read from |
|---|---|
| `SECURITY_GROUPS_COMMON`, `SECURITY_GROUPS_CONTENT_AUDIT` | Referenced security groups (`ec2:DescribeSecurityGroups`) — ingress + egress CIDR rules; managed prefix list references expanded to CIDRs |
| `NETWORK_FIREWALL` | Referenced stateless and stateful rule groups (`network-firewall:DescribeRuleGroup`) — 5-tuple rules and Suricata rule strings (header portion), with `$IPSET` / `$PORTSET` variables and `ReferenceSets` prefix-list IP set references resolved |
| `NETWORK_ACL_COMMON` | Inline `networkAclEntrySet.firstEntries` / `lastEntries` |
| WAF, WAFV2, Shield, DNS Firewall, third-party | Skipped (no IP+port rule semantics) |

## Usage

```bash
python fmm_parity.py --profile fms-admin --region ca-central-1,us-east-1 \
    -a 10.0.0.1 tcp 8080 -a 10.0.0.2 tcp 8080 \
    -b pl-0123abcd tcp 8080 -b pl-0456ef01 tcp 8080 --b-match all
```

`-a` and `-b` are repeatable. A rule is "A-present" when **any** `-a` target
matches it. B is satisfied when **any** `-b` target has a counterpart (default)
or **all** of them do (`--b-match all`). Targets are labelled `A1, A2, …` and
`B1, B2, …` in output.

Targets are `IP[/prefix] PROTO PORT` or `pl-xxxx PROTO PORT`:

- `IP`: a CIDR, **or** a managed prefix list ID / ARN (case-insensitive). A prefix
  list target matches rules that reference that prefix list (see `--pl-match`)
- `PROTO`: `tcp`, `udp`, `icmp`, `any`, or an IP protocol number
- `PORT`: single (`8080`), range (`8000-8100`), or `any`

Tokens may be space- or comma-separated, quoted as one string, and filler words
like `port` are ignored (`-a 10.0.0.1 tcp port 8080` works). Omitted `PROTO` /
`PORT` default to `any`.

Exit code is `1` when any gap is found, `0` otherwise (handy for CI).

### Options

| Flag | Description |
|---|---|
| `--target-a IP PROTO PORT` / `-a` | Target that must be present (repeatable, any may match) |
| `--target-b IP PROTO PORT` / `-b` | Target expected alongside A (repeatable) |
| `--b-match any\|all` | With several `-b`: parity needs any one (default) or all of them |
| `--pl-match ref\|cidrs-all\|cidrs-any` | Prefix-list target semantics: `ref` (default) = rule must reference the prefix list ID; `cidrs-all` / `cidrs-any` = expand the list and require rule CIDRs to cover all / any entry |
| `--profile NAME` | AWS profile (overrides `AWS_PROFILE`) |
| `--region REGION` | Region(s) to scan; repeatable and/or comma-separated. Default `AWS_REGION` or `us-east-1` |
| `--all-regions` | Scan every enabled region that offers Firewall Manager |
| `--policy ID_OR_NAME` | Restrict to one policy |
| `--scope container\|policy` | Where B must exist: same SG / rule group / NACL entry list (default) or anywhere in the same policy |
| `--show-all` | Also list every rule matching A or B, tagged `[AB]`, `[A-]`, `[-B]` |
| `--json` | JSON to stdout instead of text report |
| `--json-out PATH` | Write JSON report to file |
| `--out-dir DIR` | Base directory for auto-saved reports (default `./reports`, env `FMM_REPORT_DIR`) |
| `--no-save` | Skip auto-saving |
| `--report-out PATH` | Per-container compliance CSV path (overrides auto path) |
| `--all-containers` | Show rule groups and NACL lists in the on-screen compliance table (default: SGs only) |
| `--csv-out PATH` | Write CSV to file: one row per gap; with `--show-all`, every rule matching A or B |
| `-v` / `-q` | Debug / warnings-only logging |

### Examples

```bash
# Multi-region, named profile
python fmm_parity.py --profile fms-admin --region us-east-1 --region us-west-2 \
    -a 10.0.0.1 tcp 8080 -b 192.168.1.1 tcp 8080

# A is an IP, B is a managed prefix list: find rules allowing the IP with no
# sibling rule referencing the prefix list
python fmm_parity.py --profile fms-admin -a 10.0.0.1 tcp 8080 -b pl-0123456789abcdef0 tcp 8080

# Any protocol/port, loosen parity to policy level, JSON out
python fmm_parity.py --profile fms-admin -a 10.0.0.0/24 any any -b 192.168.1.0/24 any any \
    --scope policy --json > report.json

# Text report on screen, plus JSON + CSV files
python fmm_parity.py --profile fms-admin -a 10.0.0.1 tcp 8080 -b 192.168.1.1 tcp 8080 \
    --show-all --json-out report.json --csv-out report.csv

# One policy, show everything touching either target
python fmm_parity.py --profile fms-admin --policy prod-baseline-sg \
    -a 10.0.0.1 tcp 8080 -b 192.168.1.1 tcp 8080 --show-all
```

## How matching works

A rule *matches* a target when:

1. Protocol is compatible (rule `any` or equal to target's; target `any` matches all).
2. If the target has a port and the rule constrains ports, the port falls inside one of the rule's defined source or destination port ranges. Port-agnostic rules match any port.
3. Address match, by target kind:
   - **CIDR target**: contained in one of the rule's explicitly defined source or destination networks. A rule with no address constraints on either side matches as `any`.
   - **Prefix list target** (`--pl-match ref`, default): the rule references that prefix list ID, either as a security group `PrefixListIds` entry or as a Network Firewall `ReferenceSets` IP set variable. Wide CIDR rules such as `0.0.0.0/0` do **not** count.
   - **Prefix list target** (`cidrs-all` / `cidrs-any`): the list is expanded and the rule's CIDRs must cover all / any of its entries.

   The role (`src`, `dst`) is recorded.

A **gap** is reported when a rule matches any A target in some role, and the
same scope lacks same-*shape* rules (`kind`, direction, action, protocol)
matching the B target(s) in that role: any one B target by default, every B
target with `--b-match all`. A single wide rule (e.g. `0.0.0.0/0`) that
covers both targets counts as parity.

Managed prefix lists (customer- and AWS-managed) are expanded via
`ec2:GetManagedPrefixListEntries` and cached per list. Prefix lists are
regional, so a prefix-list target in `cidrs-*` mode is resolved in every
scanned region and the CIDRs unioned. A security group rule
referencing a prefix list becomes one rule carrying all of that list's CIDRs.
Unresolvable references (prefix lists the admin account cannot read, SG-to-SG
references, negated or unknown Suricata variables) are listed per finding but
not evaluated.

## Requirements

- Python 3.11+
- AWS credentials for the Firewall Manager administrator account

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env   # optional: AWS_PROFILE / AWS_REGION defaults
```

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework.
- **Windows**: System Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed.

## IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "fms:ListPolicies",
        "fms:GetPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "ec2:GetManagedPrefixListEntries",
        "network-firewall:DescribeRuleGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

## Saved reports

Every run saves three files by default, organised by date:

```
reports/
└── 2026-10-09/
    ├── 224850_10.160.67.203_32_tcp_8080_vs_pl-0cb0138_tcp_8080.compliance.csv
    ├── 224850_10.160.67.203_32_tcp_8080_vs_pl-0cb0138_tcp_8080.gaps.csv
    └── 224850_10.160.67.203_32_tcp_8080_vs_pl-0cb0138_tcp_8080.json
```

Filename = `HHMMSS_<targetA>_vs_<targetB>`. Change the base directory with
`--out-dir` or `FMM_REPORT_DIR`; override any single file with `--report-out`,
`--csv-out`, `--json-out`; disable with `--no-save`. Saved paths are printed at
the end of the text report. `reports/` is gitignored.

## Compliance report

After the gap list, a per-security-group table is printed (add
`--all-containers` for Network Firewall rule groups and NACL entry lists).
`--report-out report.csv` writes the same data; `containers[]` carries it in
JSON output.

| Status | Meaning |
|---|---|
| `NON_COMPLIANT` | At least one rule matches A with no B counterpart |
| `COMPLIANT` | A present, and every A rule has a B counterpart |
| `NOT_APPLICABLE` | A not present in this container |

Columns: `status, region, container_type, container, container_name, policies,
rules_total, rules_matching_a, rules_matching_b, a_targets_seen, b_targets_seen,
gaps, gap_rules`. A security
group referenced by several policies appears once, with all policy names.
Security groups with no rules at all emit no rows.

## Output

Text mode prints a summary line (rules inspected, A matches, B matches, gaps),
then each gap grouped by region / policy / container with the raw rule and the
reason. `--json` / `--json-out` emit `{targets_a[], targets_b[], b_mode, regions[], scope, stats, findings[], containers[]}`
and, with `--show-all`, `matching_rules[]`.

`--csv-out` columns: `gap, matches_a, a_targets, matches_b, b_targets, region,
policy_name, policy_id, policy_type, container, container_name, kind, direction,
action, proto, src_nets, dst_nets, src_ports, dst_ports, src_pls, dst_pls, raw,
reason, unresolved`. `a_targets`/`b_targets` list which labelled targets hit
and in which role, e.g. `A1:src;A2:src`. Multi-valued cells are
`;`-separated; `any` means unconstrained. `matches_a`/`matches_b` hold the
role(s) (`src`, `dst`, `any`) or blank for no match. Without `--show-all` only
`gap=True` rows are written.

---

# fmm_nacl_drift — live NACLs vs Firewall Manager NACL policy

Companion to `fmm_parity.py`. For each `NETWORK_ACL_COMMON` policy it asks FMS
which member accounts are in scope (`fms:ListComplianceStatus`), reads the live
network ACLs in each account through a **local AWS profile** for that account,
and reports:

- **First / last rule drift** — per direction, the lowest-numbered live entries
  must equal the policy's `firstEntries` and the highest-numbered (below the
  `*` default) must equal `lastEntries`, in order. Compared fields: action,
  protocol, CIDR, port range, ICMP type/code.
- **Duplicate rules** — the same action / protocol / CIDR / ports / ICMP at
  more than one rule number in a direction (`DUPLICATE_RULE`). Only the
  lowest-numbered copy is ever evaluated; the rest waste slots against the limit.
- **Default NACLs** — VPC default NACLs are never checked against the policy
  (even with `--nacl-scope all`). Every default NACL in each scanned account
  and region must hold only the `*` deny-all rules; anything else is
  `DEFAULT_NACL_NOT_DENY_ALL`. The finding's `subnets` shows any subnets still
  attached to it.
- **Rule-count limit** — NACLs with `>= --limit` rules in a direction
  (default 30, our raised quota; AWS default is 20), or within `--headroom` of it
  (default 3, so 27+ rules is flagged). FMS
  remediation temporarily adds rules, so headroom matters.

Read-only. No mutating API calls.

## Usage

```bash
# All NACL policies in a region, expected rules from the live FMS policy
python fmm_nacl_drift.py --profile fms-admin --region us-east-1

# Expected rules from a policy file; accounts still come from FMS
aws fms get-policy --policy-id <id> --profile fms-admin > prod-nacl.json
python fmm_nacl_drift.py --profile fms-admin --policy-file prod-nacl.json

# Also diff the file against the live policy and check NACLs against both
python fmm_nacl_drift.py --profile fms-admin --policy-file prod-nacl.json --compare-live

# Flag only NACLs at the limit (no headroom)
python fmm_nacl_drift.py --profile fms-admin --headroom 0
```

**Region.** FMS policies are regional; each policy's member accounts are
scanned only in that policy's region. A policy file's `PolicyArn` sets the
region (it wins over `--region`). Without one, the policy is looked up in every
`--region` given (or `--all-regions`); not found, or found in more than one, is
a fatal error. `--policy` that matches nothing in the scanned regions is also
fatal rather than a clean pass.

A policy file may be `aws fms get-policy` output, the bare `Policy` object, or
bare `ManagedServiceData`. The
policy is located in FMS by `--policy`, else the file's `PolicyId` /
`PolicyName`. Tag scope (`ResourceTags`) comes from the file when present,
else from the live policy.

## FMS administrator account

Set the security account where Firewall Manager lives in `.env`:

```bash
FMM_ADMIN_ACCOUNT=123456789012
```

(or `--admin-account`). Its profile is found by account id the same way as
member accounts below and verified with `sts:GetCallerIdentity`. Precedence:
`--profile` > `FMM_ADMIN_ACCOUNT` / `--admin-account` > `AWS_PROFILE`.

## Account → profile mapping

Profiles are read from the local AWS config (`AWS_CONFIG_FILE` honoured). A
profile's account is its `sso_account_id`, `aws_account_id`, or the account
in its `role_arn`. Profiles ending in `-priv` or `-cpar` are never used
(`--exclude-profile-suffix` to change). When several profiles match, the first
alphabetically is used with a warning; force one with
`--account-profile 123456789012=my-profile`. Each profile is verified with
`sts:GetCallerIdentity` before use; a mismatch is reported, not scanned.
Accounts with no profile are reported as `NO_PROFILE`.

## Options

| Flag | Description |
|---|---|
| `--admin-account ID` | FMS administrator (security) account; profile found by account id (env `FMM_ADMIN_ACCOUNT`) |
| `--profile NAME` | FMS administrator profile; overrides `--admin-account` |
| `--region` / `--all-regions` | As in `fmm_parity.py` |
| `--policy ID_OR_NAME` | Restrict to one policy (also locates a policy file's policy) |
| `--policy-file PATH` | Expected rules from this file instead of the live policy |
| `--compare-live` | With `--policy-file`: report file vs live policy diffs, check NACLs against both |
| `--account ID` | Restrict to account(s); repeatable / comma-separated |
| `--account-profile ACCT=PROFILE` | Force the profile for an account (repeatable) |
| `--exclude-profile-suffix LIST` | Profile suffixes never used (default `-priv,-cpar`) |
| `--nacl-scope subnets\|fmmanaged\|all` | Non-default NACLs on subnets in the policy's tag scope (default), tagged `FMManaged=true`, or all non-default NACLs |
| `--limit N` | Rules-per-direction limit (default 30, env `FMM_NACL_LIMIT`) |
| `--headroom N` | Also flag NACLs within N rules of the limit (default 3, env `FMM_NACL_HEADROOM`) |
| `--show-info` | Show info findings |
| `--json`, `--json-out`, `--csv-out`, `--out-dir`, `--no-save` | As in `fmm_parity.py`; auto-saves `reports/YYYY-MM-DD/HHMMSS_nacl_<policy>.{json,csv}` |

Exit code `1` on any error/warn finding, `2` on a fatal error, else `0`.

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `FIRST_MISSING` / `LAST_MISSING` | error | Too few entries in that direction to hold the block |
| `FIRST_MISMATCH` / `LAST_MISMATCH` | error | Entry in that position differs; field diffs listed |
| `FIRST_OUT_OF_ORDER` / `LAST_OUT_OF_ORDER` | error | Expected entry exists, but at another rule number |
| `AT_LIMIT` / `NEAR_LIMIT` | warn | Rule count at the limit / within headroom |
| `DEFAULT_NACL_NOT_DENY_ALL` | error | VPC default NACL has a rule other than `*` deny all |
| `DUPLICATE_RULE` | warn | Identical rule at several rule numbers in one direction; `actual` gives the rule and its numbers |
| `NOT_FMMANAGED` | warn | In-scope subnet's (non-default) NACL lacks `FMManaged=true` |
| `POLICY_DRIFT` | warn/info | Policy file differs from live policy (`--compare-live`) |
| `NO_PROFILE`, `PROFILE_ACCOUNT_MISMATCH`, `ACCOUNT_ERROR`, `FMS_ERROR` | error | Account or FMS could not be checked |
| `FIRST_RENUMBERED` / `LAST_RENUMBERED` | info | Correct and in order, but not at FMS initial numbers (1.. / ..32766) |
| `CUSTOM_OUTSIDE_RANGE` | info | Rule that matches no policy first/last rule (in any position) and is numbered outside the 5000–32000 custom range |

`baseline` on each finding is `file`, `live`, or `file-vs-live`.

## IAM permissions

FMS admin profile: `sts:GetCallerIdentity`, `fms:ListPolicies`, `fms:GetPolicy`,
`fms:ListComplianceStatus`, `ec2:DescribeRegions` (for `--all-regions`).
Member-account profiles: `sts:GetCallerIdentity`,
`ec2:DescribeNetworkAcls`, `ec2:DescribeSubnets`.
