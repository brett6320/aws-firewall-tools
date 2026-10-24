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
```

Targets:
- Any number of security group ids or ARNs, and network interface ids or ARNs, mixed. Commas also separate targets.
- An interface stands for the groups attached to it. The report shows which interface brought in which group.
- All targets must be in one account. ARNs carry their own region; bare ids use `--region`, then `AWS_REGION`, then the profile's region.

### Choosing the profile

1. `--profile`, if given.
2. Otherwise, if any ARN names an account, the local profile for that account:
   - It is found by account id, the same way as the other tools (see [Accounts and profiles](../README.md#accounts-and-profiles)).
   - Profiles ending in `-priv` or `-cpar` are never chosen.
   - `--account-profile ACCOUNT=PROFILE` forces a profile.
3. Otherwise (bare ids only), `AWS_PROFILE`, then the default credentials.

The profile's account is checked with `sts:GetCallerIdentity` before anything
is read. The run stops (exit 2) if:
- it is not the account in the ARNs;
- ARNs name more than one account;
- the groups have different owners.

## What the report shows

| Section | Contents |
|---|---|
| Access tester | See [below](#access-tester) |
| Interfaces | Each interface given: what it is attached to, its VPC, and its groups |
| Groups | Name, VPC, region, the interface it came from, ingress/egress rule counts, description |
| Rules | Every rule of every group, one row per rule. Filter and sort by group, group name, direction, protocol, ports, peer, peer type and *also granted*; unique counts and a per-group summary |
| Combined access | The union of all rules per direction: one row per protocol/port, with the merged CIDRs (or group / prefix-list references) and the groups and rules that grant them |

**Also granted** says how much of a rule's access other rules in the set
grant too:
- `no`: nothing else grants any of it.
- `partly`: some of it is granted elsewhere.
- `fully`: all of it is granted elsewhere, so removing the rule would not
  change the set's access.

Prefix lists are expanded to their current entries. Self-references show as
`self`.

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

**Switching groups and rules off.** Every group and rule has a checkbox.
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
| **Import scenario JSON** | Loads such a file into a report and checks it the same way |

When a scenario report is opened, or a scenario JSON is imported, a panel at
the top of the tester shows:
- the name, notes, export time, and the source report's account and generation time;
- whether the **rule data** matches the scenario. The SHA-256 of the embedded rule data is recomputed and compared with the value stored at export;
- whether the **results are reproduced**. The tests are run again on the scenario's on/off state and compared with the exported results;
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
| `SG_OR_ENI ...` | Group or interface ids / ARNs |
| `--profile NAME` | AWS profile (default: chosen as [above](#choosing-the-profile)) |
| `--region REGION` | Region for bare ids |
| `--account-profile ACCT=PROFILE` | Force the profile for an account (repeatable) |
| `--exclude-profile-suffix LIST` | Profile suffixes never chosen (default `-priv,-cpar`) |

Plus the common output flags, described under [Reports](../README.md#reports).

## Output

- **Text**:
  - which account and profile were used, and the rule data SHA-256;
  - interfaces and their groups;
  - each group's rules by direction, with descriptions and *also granted*;
  - the combined access per direction. Long CIDR lists are cut at 8; the files hold everything.
- **CSV**: one row per rule. List cells are `; `-separated.
- **JSON**: `{account, profile, profile_source, generated, interfaces, warnings, groups, rules, combined_access, rule_data_sha256}`.
- **HTML**: the sections above.

Reports are saved under `reports/sg_rule_inventory/YYYY-MM-DD/`.

Exit codes:
- `0`: done.
- `1`: a referenced prefix list could not be read. Rules using it are matched by id only.
- `2`: fatal (bad arguments, no usable profile, wrong account, AWS error).

## IAM permissions

- `sts:GetCallerIdentity`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeSecurityGroupRules`
- `ec2:DescribeNetworkInterfaces` (for interfaces)
- `ec2:DescribeManagedPrefixLists`
- `ec2:GetManagedPrefixListEntries`
