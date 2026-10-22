[← Index](../README.md)

# fmm_rule_parity

Walks every FMS policy in one or more regions, expands the rules the policies
carry, and reports each rule where any **A target** (IP + protocol + port, or a
managed prefix list) is present but the expected **B target(s)** are not.

Typical use: "every rule that allows the old load balancer IP should have a
sibling rule for the new prefix list".

## Usage

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

## Targets

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

## Rules inspected

| FMS policy type | Rules read from |
|---|---|
| `SECURITY_GROUPS_COMMON`, `SECURITY_GROUPS_CONTENT_AUDIT` | Referenced security groups: ingress and egress CIDR rules, with prefix list references expanded |
| `NETWORK_FIREWALL` | Referenced stateless and stateful rule groups: 5-tuple rules and Suricata rule headers, with `$IPSET` / `$PORTSET` variables and `ReferenceSets` prefix lists resolved |
| `NETWORK_ACL_COMMON` | Inline `networkAclEntrySet.firstEntries` / `lastEntries` |
| WAF, WAFV2, Shield, DNS Firewall, third-party | Skipped (no IP + port rules) |

## How matching works

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

## Options

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

Plus the [common output flags](../README.md#reports).

## Output

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

## IAM permissions

`fms:ListPolicies`, `fms:GetPolicy`, `ec2:DescribeSecurityGroups`,
`ec2:DescribeRegions`, `ec2:GetManagedPrefixListEntries`,
`network-firewall:DescribeRuleGroup`.
