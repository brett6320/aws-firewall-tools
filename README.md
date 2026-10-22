# aws-firewall-tools

Read-only review tools for AWS Firewall Manager (FMS) policies, network ACLs
and security groups. None of them make changes in AWS.

| Tool | Question it answers |
|---|---|
| [`fmm_rule_parity.py`](#fmm_rule_parity) | Which FMS policy rules allow target A without a matching rule for target B? |
| [`fmm_nacl_audit.py`](#fmm_nacl_audit) | Do the live NACLs in FMS member accounts carry the policy's first/last rules, and are any near the rule limit? |
| [`sg_access_gap.py`](#sg_access_gap) | What access does one security group grant that one or more others, combined, do not? |

**Contents:** [Getting started](#getting-started) ·
[Configuration](#configuration) · [Reports](#reports) ·
[fmm_rule_parity](#fmm_rule_parity) · [fmm_nacl_audit](#fmm_nacl_audit) ·
[sg_access_gap](#sg_access_gap) · [Repository layout](#repository-layout)

---

## Getting started

Requires Python 3.11+ and AWS credentials (local AWS profiles).

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # optional defaults, see Configuration
```

The tools are executable:

```bash
./fmm_rule_parity.py --help
./fmm_nacl_audit.py --help
./sg_access_gap.py --help
```

`python <tool>.py ...` works too. TLS uses the operating system's trust store
(`truststore`): Security.framework on macOS, the Certificate Store on Windows,
the system CA bundle on Linux (install `ca-certificates`).

## Configuration

Settings come from `.env` (see `.env.example`); command-line flags override them.

| Variable | Used by | Meaning |
|---|---|---|
| `AWS_PROFILE` | all | Default AWS profile (`--profile` overrides) |
| `AWS_REGION` | all | Default region (`--region` overrides) |
| `FMM_REPORT_DIR` | all | Base directory for saved reports (default `./reports`) |
| `FMM_ADMIN_ACCOUNT` | `fmm_nacl_audit` | FMS administrator (security) account id; its profile is found by account id |
| `FMM_NACL_LIMIT` | `fmm_nacl_audit` | NACL rules-per-direction limit (default 30) |
| `FMM_NACL_HEADROOM` | `fmm_nacl_audit` | Flag NACLs within this many rules of the limit (default 3) |

## Reports

Each run prints a text report and saves files under
`reports/<tool>/YYYY-MM-DD/`. The saved paths are printed at the end of the
text report, and `reports/` is gitignored.

```
reports/
├── fmm_rule_parity/2026-10-22/
│   ├── 224850_parity_10.0.0.1_32_tcp_8080_vs_pl-0cb0138_tcp_8080.html
│   ├── 224850_parity_10.0.0.1_32_tcp_8080_vs_pl-0cb0138_tcp_8080.compliance.csv
│   ├── 224850_parity_10.0.0.1_32_tcp_8080_vs_pl-0cb0138_tcp_8080.gaps.csv
│   └── 224850_parity_10.0.0.1_32_tcp_8080_vs_pl-0cb0138_tcp_8080.json
├── fmm_nacl_audit/2026-10-22/
│   └── 230112_nacl_<policy>.{html,csv,json}
└── sg_access_gap/2026-10-22/
    └── 231540_sggap_<group ids>.{html,csv,json}
```

Common output flags:

| Flag | Effect |
|---|---|
| `--out-dir DIR` | Base directory instead of `./reports` (env `FMM_REPORT_DIR`) |
| `--no-save` | Don't save files |
| `--html-out` / `--csv-out` / `--json-out PATH` | Write that file to a specific path |
| `--json` | Print JSON instead of the text report |
| `-v` / `-q` | Debug / warnings-only logging |

**HTML reports** are single self-contained files (data embedded, no external
assets, light/dark aware), safe to attach or email.

- The `fmm_rule_parity` and `fmm_nacl_audit` reports are interactive:
  - free-text search, filter dropdowns that show counts, and click-a-cell filtering
  - unique counts (accounts, regions, policies, VPCs, NACLs, containers ...) for the current filter
  - multi-column sort (shift-click a header)
  - "Download filtered CSV"
  - the current view is kept in the URL fragment, so it can be bookmarked
- The `sg_access_gap` report is a static page laid out per direction.

**Exit codes** (all tools): `0` nothing found, `1` findings (gaps, errors or
warnings), `2` fatal error (bad input, wrong account, AWS failure).

---

## fmm_rule_parity

Walks every FMS policy in one or more regions, expands the rules the policies
carry, and reports each rule where any **A target** (IP + protocol + port, or a
managed prefix list) is present but the expected **B target(s)** are not.

Typical use: "every rule that allows the old load balancer IP should have a
sibling rule for the new prefix list".

### Usage

```bash
./fmm_rule_parity.py --profile fms-admin --region ca-central-1,us-east-1 \
    -a 10.0.0.1 tcp 8080 -a 10.0.0.2 tcp 8080 \
    -b pl-0123abcd tcp 8080 -b pl-0456ef01 tcp 8080 --b-match all
```

More examples:

```bash
# Two regions, IP vs IP
./fmm_rule_parity.py --profile fms-admin --region us-east-1 --region us-west-2 \
    -a 10.0.0.1 tcp 8080 -b 192.168.1.1 tcp 8080

# IP vs managed prefix list: rules allowing the IP with no sibling rule referencing the list
./fmm_rule_parity.py --profile fms-admin -a 10.0.0.1 tcp 8080 -b pl-0123456789abcdef0 tcp 8080

# Any protocol/port, parity anywhere in the same policy, JSON to stdout
./fmm_rule_parity.py --profile fms-admin -a 10.0.0.0/24 any any -b 192.168.1.0/24 any any \
    --scope policy --json > report.json

# One policy, also list every rule touching either target
./fmm_rule_parity.py --profile fms-admin --policy prod-baseline-sg \
    -a 10.0.0.1 tcp 8080 -b 192.168.1.1 tcp 8080 --show-all
```

### Targets

A target is `IP[/prefix] PROTO PORT` or `pl-xxxx PROTO PORT`:

- **IP**: a CIDR, or a managed prefix list id / ARN (matched by reference by default; see `--pl-match`).
- **PROTO**: `tcp`, `udp`, `icmp`, `any`, or an IP protocol number.
- **PORT**: single (`8080`), range (`8000-8100`), or `any`.

Omitted `PROTO` / `PORT` default to `any`. Tokens may be space- or
comma-separated or quoted as one string, and filler words are ignored
(`-a 10.0.0.1 tcp port 8080` works).

`-a` and `-b` are repeatable. A rule is "A-present" when **any** `-a` target
matches it. B is satisfied when **any** `-b` target has a counterpart (the
default) or when **all** do (`--b-match all`). Targets are labelled `A1, A2, …`
and `B1, B2, …` in output.

### Rules inspected

| FMS policy type | Rules read from |
|---|---|
| `SECURITY_GROUPS_COMMON`, `SECURITY_GROUPS_CONTENT_AUDIT` | Referenced security groups: ingress and egress CIDR rules, with prefix list references expanded |
| `NETWORK_FIREWALL` | Referenced stateless and stateful rule groups: 5-tuple rules and Suricata rule headers, with `$IPSET` / `$PORTSET` variables and `ReferenceSets` prefix lists resolved |
| `NETWORK_ACL_COMMON` | Inline `networkAclEntrySet.firstEntries` / `lastEntries` |
| WAF, WAFV2, Shield, DNS Firewall, third-party | Skipped (no IP + port rules) |

### How matching works

A rule **matches** a target when all of these hold:

1. **Protocol** is compatible: equal, or either side is `any`.
2. **Port**: if both the target and the rule specify ports, the target port falls inside one of the rule's source or destination port ranges. Port-agnostic rules match any port.
3. **Address**:
   - *CIDR target*: contained in one of the rule's explicit source or destination networks. A rule with no address constraint on either side matches as `any`.
   - *Prefix list target, `--pl-match ref` (default)*: the rule references that prefix list (security group `PrefixListIds`, or a Network Firewall `ReferenceSets` variable). Wide CIDR rules such as `0.0.0.0/0` do **not** count.
   - *Prefix list target, `cidrs-all` / `cidrs-any`*: the list is expanded and the rule's CIDRs must cover all / any of its entries.

The role the target matched in (`src`, `dst`) is recorded.

A **gap** is a rule that matches an A target in some role while the same
scope (container by default, or policy with `--scope policy`) has no rule of
the same shape (kind, direction, action, protocol) matching the B target(s) in
that role. A single wide rule covering both targets counts as parity.

Prefix lists:
- Customer- and AWS-managed prefix lists are expanded with `ec2:GetManagedPrefixListEntries` and cached.
- Prefix lists are regional, so a `cidrs-*` target is resolved in every scanned region and the CIDRs combined.

References that can't be evaluated are listed on the finding but not
evaluated: prefix lists the account can't read, SG-to-SG references, and
negated or unknown Suricata variables.

### Options

| Flag | Description |
|---|---|
| `-a`, `--target-a IP PROTO PORT` | Target that must be present (repeatable; any may match) |
| `-b`, `--target-b IP PROTO PORT` | Target expected alongside A (repeatable) |
| `--b-match any\|all` | With several `-b`: parity needs any one (default) or all |
| `--pl-match ref\|cidrs-all\|cidrs-any` | How a prefix list target matches (see above) |
| `--profile NAME` | AWS profile (FMS administrator account) |
| `--region REGION` | Region(s): repeatable and/or comma-separated (default `AWS_REGION` or `us-east-1`) |
| `--all-regions` | Every enabled region that offers Firewall Manager |
| `--policy ID_OR_NAME` | Only this policy |
| `--scope container\|policy` | Where B must exist: same SG / rule group / NACL list (default) or anywhere in the policy |
| `--show-all` | Also list every rule matching A or B (text, gaps CSV, JSON) |
| `--all-containers` | Include rule groups and NACL lists in the on-screen compliance table (default: SGs only) |
| `--report-out PATH` | Compliance CSV path |
| `--csv-out PATH` | Gaps CSV path |

Plus the [common output flags](#reports).

### Output

- **Text**: summary (rules inspected, A matches, B matches, gaps), then each gap grouped by region / policy / container with the raw rule and the reason, then a compliance table per security group.
- **Compliance CSV** (`.compliance.csv`): one row per container with its status, below. A security group used by several policies appears once, listing every policy.
  | Status | Meaning |
  |---|---|
  | `NON_COMPLIANT` | At least one rule matches A with no B counterpart |
  | `COMPLIANT` | A is present and every A rule has its B counterpart |
  | `NOT_APPLICABLE` | No A target in this container |
- **Gaps CSV** (`.gaps.csv`): one row per gap (plus every A/B match with `--show-all`). Columns: `gap, matches_a, a_targets, matches_b, b_targets, region, policy_name, policy_id, policy_type, container, container_name, kind, direction, action, proto, src_nets, dst_nets, src_ports, dst_ports, src_pls, dst_pls, raw, reason, unresolved`. `a_targets` / `b_targets` show which target matched in which role (e.g. `A1:src;A2:src`); multi-valued cells are `;`-separated and `any` means unconstrained.
- **JSON**: `{targets_a, targets_b, b_mode, scope, regions, stats, findings, containers}` plus `matching_rules` with `--show-all`.
- **HTML**: two interactive tables.
  - *Compliance by container*: every container type. `NOT_APPLICABLE` rows are hidden until ticked.
  - *Rules matching A or B*: `GAP` marks A rules without a B counterpart. Rules without a gap are hidden until ticked.

### IAM permissions

`fms:ListPolicies`, `fms:GetPolicy`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeRegions`, `ec2:GetManagedPrefixListEntries`,
`network-firewall:DescribeRuleGroup`.

---

## fmm_nacl_audit

Checks the live network ACLs in FMS member accounts against Firewall Manager
`NETWORK_ACL_COMMON` policies.

How a run works:
1. Asks FMS which member accounts are in scope for each policy (`fms:ListComplianceStatus`).
2. Picks a local AWS profile for each of those accounts.
3. Finds the subnets that match the policy's tag scope, and the NACLs attached to them.
4. Checks each of those NACLs.

### What it checks

- **First / last rules.** Per direction, the lowest-numbered live entries must equal the policy's `FirstEntries`, and the highest-numbered entries below the `*` default must equal its `LastEntries`, in order. Compared: action, protocol, CIDR, port range, ICMP type/code.
- **Rule-count limit.** A direction with `--limit` rules or more is flagged; so is one within `--headroom` of it. The defaults are 30, the raised quota (AWS default is 20), and 3, so 27+ rules is flagged. FMS remediation temporarily adds rules, so headroom matters.
- **Duplicate rules.** The same action, protocol, CIDR, ports and ICMP at more than one rule number in a direction. Only the lowest-numbered copy is ever evaluated; the rest waste slots.
- **Default NACLs.** VPC default NACLs are never checked against the policy, even with `--nacl-scope all`. They must hold only the `*` deny-all rules. The finding lists any subnets still attached.
- **Tagging.** In-scope NACLs should be tagged `FMManaged=true`.

### Usage

```bash
# All NACL policies in a region; expected rules from the live FMS policy
./fmm_nacl_audit.py --profile fms-admin --region us-east-1

# Expected rules from a policy file (accounts still come from FMS)
aws fms get-policy --policy-id <id> --profile fms-admin > prod-nacl.json
./fmm_nacl_audit.py --policy-file prod-nacl.json

# Also diff the file against the live policy, and check NACLs against both
./fmm_nacl_audit.py --policy-file prod-nacl.json --compare-live

# Flag only NACLs at the limit (no headroom)
./fmm_nacl_audit.py --headroom 0
```

### Policies and regions

- FMS policies are regional. Each policy's member accounts are scanned only in that policy's region.
- A policy file's `PolicyArn` sets the region and wins over `--region`.
- Without a `PolicyArn`, the policy is looked up in every `--region` given (or `--all-regions`). The run stops if it's found in none or in more than one.
- A `--policy` that matches nothing is a fatal error, not a clean pass.
- A policy file may be any of:
  - `aws fms get-policy` output
  - the bare `Policy` object
  - a bare `NetworkAclEntrySet`
- Rules are read from `SecurityServicePolicyData.PolicyOption.NetworkAclCommonPolicy.NetworkAclEntrySet` (`FirstEntries` / `LastEntries`). A policy with neither is a fatal error.
- The file's policy is located in FMS by `--policy`, else by its `PolicyId` / `PolicyName`.
- Tag scope (`ResourceTags`) comes from the file when present, else from the live policy.

### Accounts and profiles

**FMS administrator account:** set it in `.env` as
`FMM_ADMIN_ACCOUNT=123456789012` (or pass `--admin-account`). Its profile is
found by account id, like member accounts. Precedence: `--profile`, then
`FMM_ADMIN_ACCOUNT` / `--admin-account`, then `AWS_PROFILE`.

**Member accounts** are mapped to profiles from the local AWS config
(`AWS_CONFIG_FILE` is honoured):
- A profile's account is its `sso_account_id`, `aws_account_id`, or the account in its `role_arn`.
- Profiles ending in `-priv` or `-cpar` are never used (`--exclude-profile-suffix` to change).
- If several profiles match, the first alphabetically is used, with a warning. Force one with `--account-profile 123456789012=my-profile`.
- Every profile is verified with `sts:GetCallerIdentity` before use. A mismatch is reported and the account is not scanned.
- Accounts with no matching profile are reported as `NO_PROFILE`.

### Options

| Flag | Description |
|---|---|
| `--admin-account ID` | FMS administrator account (env `FMM_ADMIN_ACCOUNT`) |
| `--profile NAME` | FMS administrator profile; overrides `--admin-account` |
| `--region` / `--all-regions` | As for `fmm_rule_parity` |
| `--policy ID_OR_NAME` | Only this policy (also locates a policy file's policy) |
| `--policy-file PATH` | Expected rules from this file instead of the live policy |
| `--compare-live` | With `--policy-file`: diff file vs live policy and check NACLs against both |
| `--account ID` | Only these account(s); repeatable / comma-separated |
| `--account-profile ACCT=PROFILE` | Force the profile for an account (repeatable) |
| `--exclude-profile-suffix LIST` | Profile suffixes never used (default `-priv,-cpar`) |
| `--nacl-scope subnets\|fmmanaged\|all` | Check NACLs on subnets in the policy's tag scope (default), NACLs tagged `FMManaged=true`, or all non-default NACLs |
| `--limit N` | Rules-per-direction limit (default 30, env `FMM_NACL_LIMIT`) |
| `--headroom N` | Also flag NACLs within N rules of the limit (default 3, env `FMM_NACL_HEADROOM`) |
| `--show-info` | Show info findings in the text report |

Plus the [common output flags](#reports).

### Findings

| Code | Severity | Meaning |
|---|---|---|
| `FIRST_MISSING` / `LAST_MISSING` | error | Too few entries in that direction to hold the block |
| `FIRST_MISMATCH` / `LAST_MISMATCH` | error | The entry in that position differs (field differences listed) |
| `FIRST_OUT_OF_ORDER` / `LAST_OUT_OF_ORDER` | error | The expected entry exists, but at another rule number |
| `DEFAULT_NACL_NOT_DENY_ALL` | error | VPC default NACL has a rule other than `*` deny all |
| `NO_PROFILE`, `PROFILE_ACCOUNT_MISMATCH`, `ACCOUNT_ERROR`, `FMS_ERROR` | error | Account or FMS could not be checked |
| `AT_LIMIT` / `NEAR_LIMIT` | warn | Rule count at the limit / within headroom |
| `DUPLICATE_RULE` | warn | Identical rule at several rule numbers; `actual` shows the rule and its numbers |
| `NOT_FMMANAGED` | warn | In-scope NACL lacks `FMManaged=true` |
| `POLICY_DRIFT` | warn / info | Policy file differs from the live policy (`--compare-live`) |
| `FIRST_RENUMBERED` / `LAST_RENUMBERED` | info | Correct and in order, but not at FMS's initial numbers (1… / …32766) |
| `CUSTOM_OUTSIDE_RANGE` | info | Rule matching no policy rule, numbered outside the 5000–32000 custom range |

Each finding's `baseline` is `file`, `live` or `file-vs-live`.

### Output

- **Text**: findings grouped by region / policy / account / NACL; info findings only with `--show-info`.
- **CSV / JSON**: every finding (`{stats, findings}` in JSON).
- **HTML**: run totals, then one interactive findings table.
  - Filters: severity, code, region, policy, account, VPC, NACL, direction, baseline.
  - Unique counts of accounts, regions, policies, VPCs, NACLs and subnets, plus a per-code summary.
  - Info findings are hidden until "show info" is ticked.

### IAM permissions

- FMS admin profile: `sts:GetCallerIdentity`, `fms:ListPolicies`, `fms:GetPolicy`, `fms:ListComplianceStatus`, and `ec2:DescribeRegions` (for `--all-regions`).
- Member-account profiles: `sts:GetCallerIdentity`, `ec2:DescribeNetworkAcls`, `ec2:DescribeSubnets`.

---

## sg_access_gap

Finds access granted by a **left** security group that the **right** security
group(s) do not grant. With several right groups, the left group's access is
checked against their **combined** access, as if all of them were attached to
the same network interface. A range split across two right groups therefore
counts as granted.

- Access the right groups grant beyond the left is not reported.
- Ingress and egress are checked separately.
- Descriptions are shown for reference but never compared.

### Usage

```bash
# LEFT RIGHT [RIGHT ...]
./sg_access_gap.py --profile prod-admin sg-0123456789abcdef0 sg-0fedcba9876543210
./sg_access_gap.py --profile prod-admin sg-0123456789abcdef0 sg-0fedcba9876543210 sg-0aaaabbbbccccdddd
./sg_access_gap.py --profile prod-admin \
    arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 \
    arn:aws:ec2:us-east-1:111122223333:security-group/sg-0fedcba9876543210
```

Groups may be ARNs or ids, mixed.
- ARNs carry their own region. Bare ids use `--region`, then `AWS_REGION`, then the profile's region.
- All groups must be in one account. The run stops (exit 2) if the ARNs name different accounts, if the profile's account (`sts:GetCallerIdentity`) differs from the ARNs, or if the groups have different owners.

### How rules are compared

Each rule becomes a set of boxes: protocol × port range (or ICMP type/code) ×
address range. Prefix lists are expanded to their current entries. Each left
rule is then checked against every rule of every right group in the same
direction:

| Code | Severity | Meaning |
|---|---|---|
| `MISSING` | error | Nothing in the right groups overlaps this left rule |
| `PARTIAL` | error | The right groups grant only part of it |
| `PREFIX_LIST_UNRESOLVED` | warn | Prefix list entries couldn't be read; rules using it are compared by id only |
| `COVERED` | info | The right groups grant all of it through different rules (a prefix list vs. its CIDRs, a /16 vs. two /17s, a broader rule, or pieces from several right groups) |
| `IDENTICAL` | info | A right group has the same protocol, ports and peer |
| `DIFFERENT_VPCS` | info | Groups are in different VPCs, so group references may not be comparable |

- For `MISSING` and `PARTIAL`, `uncovered` is the exact absent access (merged CIDRs, ports, ICMP types).
- Every finding lists the overlapping right-group rules (group, rule id, rule, description).
- Security group references match by group id. A left self-reference matches a self-reference in any right group.
- IPv4 and IPv6 are compared separately.

Each direction gets a verdict: `N gap(s)`, `covered` or `identical`.

### Options

| Flag | Description |
|---|---|
| `SG ...` | Group ARNs or ids: `LEFT RIGHT [RIGHT ...]` |
| `--profile NAME` | AWS profile (default `AWS_PROFILE`) |
| `--region REGION` | Region for bare group ids |
| `--show-covered` | Also list left rules the right groups fully grant (`COVERED`, `IDENTICAL`) |

Plus the [common output flags](#reports).

### Output

- **Text**: per direction, each gap with its absent access and the overlapping right rules.
- **CSV / JSON**: every finding. The JSON also holds each group's full rule list with descriptions.
- **HTML**: finding counts, the groups, per-direction verdicts, and a gaps table per direction. Fully granted left rules are collapsed, and each group's full rule list with descriptions is at the end.

### IAM permissions

`sts:GetCallerIdentity`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeSecurityGroupRules`, `ec2:DescribeManagedPrefixLists`,
`ec2:GetManagedPrefixListEntries`.

---

## Repository layout

```
fmm_rule_parity.py      FMS policy rule parity (A present, B missing)
fmm_nacl_audit.py       live NACLs vs FMS NACL policy
sg_access_gap.py        left SG access absent from right SG(s)
lib/aws_common.py       shared AWS helpers: sessions, clients, FMS policy calls,
                        region resolution; loads .env and sets up logging
lib/html_report.py      self-contained interactive HTML report renderer
.env.example            configuration template
requirements.txt        Python dependencies
```
