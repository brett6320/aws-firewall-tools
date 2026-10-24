[← Index](../README.md)

# sg_rule_inventory

Reports every rule of a set of security groups and their **combined** access.
The HTML report includes an **access tester**: try traffic against the rules,
and switch individual groups or rules off to see what each one contributes.

Security groups only allow traffic. Every group attached to a network
interface adds to what it allows, so a set of groups allows the union of all
their rules.

The tool is read-only and for reporting only. It makes only Describe and Get
calls, and the tester runs entirely in the browser.

## Usage

```bash
# Groups by id (bare ids need a region)
./sg_rule_inventory.py --region us-east-1 sg-0123456789abcdef0 sg-0fedcba9876543210

# Groups by ARN: the profile is found from the ARN's account
./sg_rule_inventory.py arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0

# The groups attached to an interface, plus another group
./sg_rule_inventory.py arn:aws:ec2:us-east-1:111122223333:network-interface/eni-0123456789abcdef0 \
    sg-0aaaabbbbccccdddd

# An EC2 instance (each of its interfaces) and a Lambda function, in two accounts
./sg_rule_inventory.py arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0 \
    arn:aws:lambda:us-east-1:444455556666:function:orders-api:live
```

Targets, any number and mixed. Commas also separate targets.

| Target | Written as | Stands for |
|---|---|---|
| Security group | `sg-…` or its ARN | itself |
| Network interface | `eni-…` or its ARN | the groups attached to it |
| EC2 instance | `i-…` or `arn:aws:ec2:REGION:ACCOUNT:instance/i-…` | each of its network interfaces, with that interface's groups |
| Lambda function | `arn:aws:lambda:REGION:ACCOUNT:function:NAME[:VERSION or ALIAS]` | the security groups in its VPC configuration |

- The report shows which interface or function brought in which group. Interfaces and functions take part in the interface comparison, see [below](#comparing-interfaces).
- A Lambda function that is not attached to a VPC has no security groups. It is reported as a warning (exit 1) and skipped.
- ARNs carry their own region. Bare ids use `--region`, then `AWS_REGION`, then the profile's region.

### Accounts and profiles

Targets can be in several accounts when they are given as ARNs. Each account
is read with its own profile:

1. `--profile`, if given, is used for its own account.
2. Every other account named by an ARN uses its local profile:
   - It is found by account id, the same way as the other tools (see [Accounts and profiles](../README.md#accounts-and-profiles)).
   - Profiles ending in `-priv` or `-cpar` are never chosen.
   - `--account-profile ACCOUNT=PROFILE` forces a profile.
3. Bare ids belong to the `--profile` account. Without `--profile`, they belong to the ARNs' account when exactly one account is named, otherwise (no ARNs) to `AWS_PROFILE`, then the default credentials.

Every profile is checked with `sts:GetCallerIdentity` before anything is
read. The run stops (exit 2) if:
- an account has no usable profile, or its profile is a different account;
- bare ids are mixed with ARNs from several accounts and there is no `--profile` to say which account they are in;
- a target is not found in its account.

With several accounts, the account is shown on every group, rule, interface
and function, and can be filtered on in the HTML report. Security group
references across accounts (for example over VPC peering) are matched by
group id, like any other reference.

## What the report shows

| Section | Contents |
|---|---|
| Access tester | See [below](#access-tester) |
| Interfaces and functions | Each interface (given directly or from an EC2 instance) and Lambda function: type, account, what it is attached to, its VPC, and its groups |
| Group attachment differences | With two or more interfaces / functions: groups attached to some of them but not all |
| Interface differences | With two or more interfaces / functions: access allowed on some of them but not others. See [below](#comparing-interfaces) |
| Groups | Name, account, VPC, region, the interface or function it came from, ingress/egress rule counts, description |
| Rules | Every rule of every group, one row per rule. Filter and sort by group, group name, account, direction, protocol, ports, peer, peer type and *also granted*; unique counts and a per-group summary |
| Combined access | The union of all rules per direction: one row per protocol/port, with the merged CIDRs (or group / prefix-list references) and the groups and rules that grant them |

**Also granted** says how much of a rule's access other rules in the set
grant too:
- `no`: nothing else grants any of it.
- `partly`: some of it is granted elsewhere.
- `fully`: all of it is granted elsewhere, so removing the rule would not
  change the set's access.

Prefix lists are expanded to their current entries. Self-references show as
`self`.

## Comparing interfaces

Give two or more interfaces, EC2 instances or Lambda functions, for example
the members of an Auto Scaling group or the primary and standby of a pair,
and the report lists only what differs between them. Each interface of an
instance and each function counts as one.

- Each interface's access is the union of all its groups' rules, per direction.
- The interfaces' access is split into exact pieces (protocol / ports × addresses), each tagged with the interfaces that allow it.
- Pieces allowed on every interface are left out. Each remaining row gives:
  - direction, protocol / ports and the CIDRs (or group / prefix-list references);
  - **Allowed on** and **Not allowed on**;
  - **Rules**: the rules on the allowing interfaces that grant it.

Because access is compared exactly, interfaces with different groups but the
same effective access show no access difference. For example, one group
allowing `10.1.0.0/16` and another allowing two `/17`s are equivalent. Such
interfaces appear only under group attachment differences.

The table filters by direction, protocol / ports, allowed on and not allowed
on. A summary counts the differences per interface that lacks the access.
By default the text report gives the number of differences and how many
each interface / function lacks (or "no differences"); with `--show-rules`
it lists every difference and the rules responsible.

Groups given directly, not through an interface, instance or function, are
not part of this comparison.

## Access tester

The tester is in the HTML report and runs in the browser from the rule data
in the file. It needs no AWS access and sends nothing anywhere. Prefix lists
are evaluated as they were when the report was made.

Write one test per line, `DIRECTION ADDRESS PROTOCOL [PORT]`, or build tests
with the form. Lines starting with `#` are ignored.

```
ingress 10.1.2.3 tcp 443           from 10.1.2.3 to tcp port 443
egress 0.0.0.0/0 udp 53            to anywhere, udp 53
both 10.0.0.0/8 tcp 8000-8100      both directions, a CIDR, a port range
in sg-0123456789abcdef0 tcp 5432   from members of a referenced group
out pl-0123456789abcdef0 tcp 443   to a prefix list's CIDRs
in 2001:db8::/64 icmpv6 128        ICMPv6 type 128
in 10.0.0.5 icmp 8/0               ICMP type 8 code 0
in any all                         all traffic from anywhere (IPv4 and IPv6)
```

| Part | Meaning |
|---|---|
| `DIRECTION` | `ingress` / `in`, `egress` / `out`, or `both` |
| `ADDRESS` | An IP, a CIDR, `any`, a group id or a prefix list id. For ingress it is the source; for egress, the destination |
| `PROTOCOL` | `tcp`, `udp`, `icmp`, `icmpv6`, `all`, or a protocol number |
| `PORT` | Destination port or range (`443`, `8000-8100`). For ICMP it is `TYPE` or `TYPE/CODE`. Leave it out to test every port and get the allowed and not-allowed ports listed |

How addresses are matched:
- A group id matches rules that reference that group, including a group's
  self-reference. The report can't know the members' addresses, so this is
  by id only.
- A prefix list id is expanded to its CIDRs if a rule references that list.
  Otherwise it is matched by id.

Each result shows:

| Column | Meaning |
|---|---|
| Verdict | `ALLOWED`: all of the tested traffic is granted. `PARTIAL`: only some of it (for example, a CIDR or port range that is only partly covered). `DENIED`: none of it. `INVALID`: the line could not be parsed |
| Allowed / Not allowed | Filled when no port was given, or when the result is `PARTIAL`. Ports are listed per protocol for each address set, for example `tcp 22, 443, 8000-8100; udp 53 from 10.1.2.3/32` |
| Granted by | The switched-on rules that match the traffic |
| Switched-off rules that match | Rules that are switched off but would have matched |

Tests with identical outcomes share one row: same direction, same verdict, and
the same allowed / not-allowed ports. The verdict shows how many tests the row
covers (`×3`).
- A test's own address appears as `(tested address)`. So `in 10.1.2.3 tcp` and `in 10.1.2.4 tcp` share a row when the same ports are allowed for both.
- Results that cover only part of an address keep the exact CIDRs. They share a row only when they are identical.
- Tests in a row may be granted by different rules. A rule that matches every test in the row is listed plainly; any other rule names the tests it matches, `(for in 10.200.0.1 tcp 443)`.

**Comparing tests with a baseline.** Under the results, pick a **baseline** test and tick the tests to compare with it (all other tests by default; "All" / "None" to switch). For a `both` test, each direction is its own choice. The table has a column for the baseline and one per compared test, each with its number of differences, or "same outcome". Addresses are ignored. For each compared test it shows:
- direction and verdict;
- the protocol / ports compared, which is what the test and the baseline both cover. Anything only one of them covers is listed as not compared;
- the protocols / ports allowed for both, **allowed for the baseline but not here**, and **allowed here but not for the baseline**. "Allowed" means for every tested address; ports allowed for only part of a CIDR get a row of their own;
- the granting rules they share, those only for the baseline, and those only here, plus switched-off rules that would match, all within the compared protocol / ports.

Cells that differ from the baseline are highlighted, and their rows are marked. The baseline and the ticked tests are kept in the URL fragment and in exported scenarios.

To share a comparison:
- **Download comparison**: a small standalone page with only the comparison: the baseline, the compared tests, the table, the switched-off rules, the source report's account, generation time and rule data SHA-256, and the scope. It holds no rule data, so it is a few KB rather than the size of the report. If no scenario name was given, the name is "baseline vs N tests".
- **Download comparison CSV**: one line per row, one column per test; cells that differ from the baseline start with `[differs]`.

The comparison page also carries a compact scenario of just the compared tests and the on / off state. To check it, open the full report with the same rule data SHA-256 and load the comparison file with **Import scenario**. The tests are re-run, the comparison is recomputed and shown, and the evidence panel says whether it matches the file (see [below](#sharing-a-scenario-as-evidence)). The check covers the comparison's data, not hand edits to the visible table, but the verifier always sees the recomputed comparison in the report.

**Switching groups and rules off.** Every group and rule has a checkbox in the "Groups and rules used by the tester" panel. The panel is collapsed by default; its heading shows how many rules are on.
Untick one to see what the set would allow without it. "All on" restores
everything.

The tests, the switched-off groups and rules, and the scenario name and notes
are kept in the URL fragment, so a scenario can be bookmarked.

### Sharing a scenario as evidence

To show other engineers that a path is open (or closed), give the scenario
a name and notes, for example a change ticket, then:

| Button | Gives you |
|---|---|
| **Download scenario report** | A copy of this HTML report that opens on the scenario. It is a single self-contained file to attach to a ticket or email; the recipient needs nothing else |
| **Export scenario JSON** | The scenario alone (`format: sg_rule_inventory.scenario/1`): tests, switched-off groups and rules, name, notes, report identity, and the results at export time |
| **Import scenario** | Loads a scenario JSON, a downloaded scenario report or a downloaded comparison into a report and checks it the same way |

When a scenario report is opened, or a scenario JSON is imported, a panel at
the top of the tester shows:
- the name, notes, export time, and the source report's account and generation time;
- whether the **rule data** matches the scenario. The SHA-256 of the embedded rule data is recomputed and compared with the value stored at export;
- whether the **results are reproduced**. The tests are run again on the scenario's on/off state and compared with the exported results;
- if the scenario includes a comparison, the comparison as exported and whether it is **reproduced**;
- **switched-off** groups and rules, listed explicitly ("nothing" when every rule was on). Switched-off ids that are not in the report are flagged;
- the scope: security groups only. Network ACLs, route tables, firewalls and the far end's security groups are not evaluated.

The same SHA-256 appears in the report header, the text report and the JSON
(`rule_data_sha256`) of the run that made the report. A recipient can match
an exported scenario to that run.

This is a consistency check, not a signature. It shows the file was not
changed by accident and ties it to a run, but anyone who can edit the file
could recompute the hash.

## Options

| Flag | Description |
|---|---|
| `TARGET ...` | Security group, network interface or EC2 instance ids / ARNs, or Lambda function ARNs; see [Usage](#usage) |
| `--profile NAME` | AWS profile (default: chosen as [above](#accounts-and-profiles)) |
| `--region REGION` | Region for bare ids |
| `--show-rules` | Text report: list every rule per group, the combined access, and each interface difference with its rules. Without it, the text report is a summary: one line per group and counts only. The HTML, CSV and JSON reports always include everything |
| `--account-profile ACCT=PROFILE` | Force the profile for an account (repeatable) |
| `--exclude-profile-suffix LIST` | Profile suffixes never chosen (default `-priv,-cpar`) |

Plus the common output flags, described under [Reports](../README.md#reports).

## Output

- **Text**, by default a summary:
  - which account and profile were used, and the rule data SHA-256;
  - interfaces and their groups;
  - one line per group (rule counts, interface);
  - the number of rules and of combined access entries;
  - with two or more interfaces, the number of group attachment and access differences, and how many each interface lacks.
- **Text with `--show-rules`**: additionally, each group's rules by direction (with descriptions and *also granted*), the combined access per direction, and every interface difference with the rules responsible. Long CIDR lists are cut at 8; the files hold everything.
- **CSV**: one row per rule. List cells are `; `-separated.
- **JSON**: `{account, accounts, profile, profile_source, generated, interfaces, warnings, target_warnings, groups, rules, combined_access, interface_deltas, rule_data_sha256}`. `accounts` lists each account with its profile; `interfaces` holds interfaces and Lambda functions (`kind`: `eni`, `instance` or `lambda`). `interface_deltas` holds `{interfaces, groups, access}`.
- **HTML**: the sections above.

Reports are saved under `reports/sg_rule_inventory/YYYY-MM-DD/`.

Exit codes:
- `0`: done.
- `1`: the interfaces / functions given differ (groups or access), a Lambda function was skipped (not in a VPC), or a referenced prefix list could not be read. Rules using an unreadable prefix list are matched by id only.
- `2`: fatal (bad arguments, no usable profile, wrong account, AWS error).

## IAM permissions

- `sts:GetCallerIdentity`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeSecurityGroupRules`
- `ec2:DescribeNetworkInterfaces` (for interfaces)
- `ec2:DescribeInstances` (for EC2 instances)
- `lambda:GetFunctionConfiguration` (for Lambda functions)
- `ec2:DescribeManagedPrefixLists`
- `ec2:GetManagedPrefixListEntries`
