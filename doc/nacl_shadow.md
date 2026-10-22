[← Index](../README.md)

# nacl_shadow

Finds network ACL rules that are hidden, completely or in part, by
lower-numbered rules.

NACL entries are evaluated in rule-number order and the first match wins. A
rule that is fully covered by earlier rules never matches anything:

- If an earlier rule with the **opposite** action covers it, the rule's
  intent is defeated. This is the usual cause of "I added an allow and it
  still doesn't work".
- If earlier rules with the **same** action cover it, the rule is dead weight.
  It still uses a slot against the rules-per-NACL limit.

## Usage

```bash
# One account (the profile's), one region
./nacl_shadow.py --profile prod-ro --region us-east-1

# Every account with a local profile, every region, FMS-managed NACLs only
./nacl_shadow.py --all-accounts --all-regions --fmmanaged-only

# Specific accounts and a single VPC
./nacl_shadow.py --account 111122223333,444455556666 --vpc vpc-0123456789abcdef0
```

Accounts:
- Without `--account` / `--all-accounts`, only the account of `--profile` (or
  of the default credentials) is scanned.
- With them, each account is scanned through its local profile, found by
  account id the same way as
  [fmm_nacl_audit](fmm_nacl_audit.md#accounts-and-profiles). Profiles ending
  in `-priv` / `-cpar` are never used.
- Every profile is verified with `sts:GetCallerIdentity`. Accounts that can't
  be scanned are reported as `NO_PROFILE`, `PROFILE_ACCOUNT_MISMATCH` or
  `ACCOUNT_ERROR`.

## How it works

1. For each NACL, the entries of each direction are sorted by rule number.
   The `*` default rules (32767 / 32768) are skipped.
2. Each entry becomes an exact box: protocol × port range (or ICMP
   type/code) × address range. IPv4 and IPv6 entries never overlap each
   other.
3. For each entry, the earlier entries that overlap it are subtracted from
   it. What's left is what the entry still matches.

Worked example (ingress):

```
#100 deny  tcp 22   10.0.0.0/8
#200 allow tcp 22   10.1.0.0/16        <- SHADOWED_CONFLICT: #100 denies all of it first
#300 allow tcp 443  192.168.0.0/16
#310 allow tcp 443  192.168.1.0/24     <- REDUNDANT: #300 already allows all of it
#400 deny  all      172.16.0.0/16
#500 allow tcp 8080 172.16.0.0/12      <- PARTIALLY_SHADOWED: still matches
                                          172.17.0.0/16, 172.18.0.0/15, 172.20.0.0/14, 172.24.0.0/13
```

## Options

| Flag | Description |
|---|---|
| `--profile NAME` | Scan this profile's account (default `AWS_PROFILE`) unless `--account` / `--all-accounts` |
| `--account ID` | Account(s) to scan via their local profiles; repeatable / comma-separated |
| `--all-accounts` | Every account that has a usable local profile |
| `--account-profile ACCT=PROFILE` | Force the profile for an account (repeatable) |
| `--exclude-profile-suffix LIST` | Profile suffixes never used (default `-priv,-cpar`) |
| `--region REGION` | Region(s): repeatable and/or comma-separated (default `AWS_REGION` or `us-east-1`) |
| `--all-regions` | Every enabled region |
| `--vpc VPC_ID` | Only NACLs in these VPC(s) (repeatable) |
| `--nacl ACL_ID` | Only these NACL(s) (repeatable) |
| `--fmmanaged-only` | Only NACLs tagged `FMManaged=true` |
| `--show-info` | Show info findings in the text report |

Plus the common output flags, described under [Reports](../README.md#reports).

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `SHADOWED_CONFLICT` | error | Fully covered by earlier rules, and at least one of them has the opposite action. The rule never matches and its intent is defeated |
| `REDUNDANT` | warn | Fully covered by earlier rules with the same action. The rule never matches; removing it frees a slot |
| `PARTIALLY_SHADOWED` | warn | Part of the rule's traffic is taken by an earlier rule with the opposite action; `effective` lists what it still matches |
| `PARTIAL_OVERLAP_SAME_ACTION` | info | Part of the rule overlaps earlier rules with the same action. Harmless, but maybe worth consolidating |
| `NO_PROFILE`, `PROFILE_ACCOUNT_MISMATCH`, `ACCOUNT_ERROR` | error | The account (or one region of it) could not be scanned |

Each finding lists:
- `shadowed_by`: the earlier rules that overlap it, as `#N direction action rule`.
- `effective`: what the rule still matches, as merged CIDRs per protocol/port. Empty when the rule never matches.
- Context: VPC, NACL, attached subnets, and whether the NACL is FMS-managed.

Default NACLs are included and marked "(default NACL)" in the detail.

## Output

- **Text**:
  - Run totals: accounts, regions, NACLs, rules evaluated, dead rules (`SHADOWED_CONFLICT` + `REDUNDANT`).
  - Findings grouped by account / region / NACL / direction.
  - Info findings only with `--show-info`. Long CIDR lists are cut at 8 per line; the files hold everything.
- **CSV**: one row per finding. List cells are `; `-separated.
- **JSON**: `{stats, findings}`.
- **HTML**: run totals and one interactive findings table.
  - Filters: severity, code, account, region, VPC, NACL, direction, FMManaged.
  - Unique counts of accounts, regions, VPCs, NACLs and subnets, plus a per-code summary.
  - Info findings are hidden until "show info" is ticked.

Reports are saved under `reports/nacl_shadow/YYYY-MM-DD/`.

Exit codes: `0` nothing found, `1` error or warn findings, `2` fatal (bad
arguments, credentials of the `--profile` account failing).

## IAM permissions

`sts:GetCallerIdentity`, `ec2:DescribeNetworkAcls`, and
`ec2:DescribeRegions` (for `--all-regions`).
