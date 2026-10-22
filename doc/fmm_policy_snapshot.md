[← Index](../README.md)

# fmm_policy_snapshot

Saves Firewall Manager (FMS) policies as snapshots, and compares them over
time or across regions.

**Intent.** FMS keeps no change history. A policy edited by hand, or changed
in one region but not another, is easy to miss. Snapshots give a reviewable
history; the diffs show exactly which fields changed.

## Usage

```bash
# Save every policy in two regions
./fmm_policy_snapshot.py snapshot --region us-east-1,ca-central-1

# What changed since the previous snapshot?
./fmm_policy_snapshot.py diff previous latest

# Has anything changed since the last snapshot?
./fmm_policy_snapshot.py diff latest live --region us-east-1

# Do the regions carry the same policies?
./fmm_policy_snapshot.py compare-regions --region us-east-1,ca-central-1

# Same, from a snapshot, matching policies by a tag instead of by name
./fmm_policy_snapshot.py compare-regions --source latest --baseline-region us-east-1 --match-tag baseline
```

## Subcommands

### snapshot

Reads every policy in the given regions and saves one file per policy:

```
snapshots/
└── 2026-10-22_133746/
    ├── index.json
    ├── us-east-1/
    │   ├── nacl-base__0a1b2c3d-....json
    │   └── sg-base__4e5f6a7b-....json
    └── ca-central-1/
        └── nacl-base__8c9d0e1f-....json
```

- Each file has the `aws fms get-policy` shape (`{"Policy": ..., "PolicyArn": ...}`),
  plus the policy's tags (`TagList`). A file can be passed straight to
  [`fmm_nacl_audit.py --policy-file`](fmm_nacl_audit.md).
- `index.json` records when the snapshot was taken, the FMS admin account, the
  regions read, and every policy saved (id, name, type, ARN, file).
- The snapshot is all or nothing: if any policy can't be read, nothing is
  saved and the run exits 2.

### diff OLD NEW

Compares two policy sets. Each side is a snapshot folder (a path, or a folder
name under `--snapshot-dir`), `latest`, `previous`, or `live` (read now).

- Policies are matched by region and policy id.
- Only regions present on both sides are compared; others are skipped with a warning.
- A policy only on one side is `POLICY_ADDED` or `POLICY_REMOVED`.
- A policy on both sides gets one `POLICY_CHANGED` finding per changed field.

### compare-regions

Compares every region's policies with a baseline region (`--baseline-region`,
default the first region). The source is `live` (default) or a snapshot
(`--source`).

- Policies are matched by name, or by the value of a tag (`--match-tag KEY`).
- Region names inside values (e.g. ARNs) are replaced by `{region}` first, and
  the policies' own ids and ARNs are ignored, so only real configuration
  differences remain.
- A policy present in only one of the two regions is `MISSING_IN_REGION`.
- Each field that differs is a `DIFFERS` finding.

## How policies are compared

Before comparing:

- `PolicyUpdateToken` is dropped (it changes on every save).
- `ManagedServiceData` (a JSON string) is parsed, so changes inside it are
  shown by path.

The comparison is field by field, with dotted paths, e.g.
`SecurityServicePolicyData.PolicyOption.NetworkAclCommonPolicy.NetworkAclEntrySet.FirstEntries[2].CidrBlock`:

- Objects are compared key by key.
- Lists of objects (rule entries, security groups) are compared position by position.
- Lists of plain values (account ids, resource types) are compared as sets, since
  their order means nothing. `old` shows the items removed, `new` the items added.

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `POLICY_ADDED` | warn | Policy exists in NEW but not in OLD |
| `POLICY_REMOVED` | warn | Policy exists in OLD but not in NEW |
| `POLICY_CHANGED` | warn | A field changed (`path`, `old`, `new`) |
| `POLICY_CHANGED` on `PolicyName` / `PolicyDescription` | info | Rename or description change |
| `MISSING_IN_REGION` | warn | Policy exists in one of the two regions only (`region` is where it's missing) |
| `DIFFERS` | warn | A field differs from the baseline region (`old` = baseline, `new` = region) |

Any difference, including info, gives exit code 1.

## Options

| Flag | Description |
|---|---|
| `--profile NAME` | FMS administrator profile; overrides `--admin-account` |
| `--admin-account ID` | FMS administrator account; its profile is found by account id (env `FMM_ADMIN_ACCOUNT`) |
| `--account-profile ACCT=PROFILE` | Force the profile used for an account |
| `--exclude-profile-suffix LIST` | Profile suffixes never used (default `-priv,-cpar`) |
| `--region REGION` | Region(s): repeatable and/or comma-separated (default `AWS_REGION`). For snapshot sources, limits the regions compared |
| `--all-regions` | Every enabled region that offers Firewall Manager (live only) |
| `--policy ID_OR_NAME` | Only this policy |
| `--type TYPE` | Only policies of this type, e.g. `NETWORK_ACL_COMMON` (repeatable) |
| `--snapshot-dir DIR` | Where snapshots live (default `./snapshots`, env `FMM_SNAPSHOT_DIR`) |
| `--source REF` | compare-regions: `live` (default), `latest`, `previous`, or a snapshot folder |
| `--baseline-region REGION` | compare-regions: region the others are compared with |
| `--match-tag KEY` | compare-regions: match policies by this tag's value instead of by name |

`diff` and `compare-regions` also take the common output flags: see
[Reports](../README.md#reports). `snapshot` takes `-v` / `-q`.

## Output

- **snapshot**: the snapshot folder described above, and a per-region count on screen.
- **diff / compare-regions**:
  - **Text**: differences grouped by policy.
  - **CSV / JSON**: one row per difference: `severity, code, region, policy_name, policy_id, other, path, old, new, detail`.
  - **HTML**: an interactive table.
    - Filters: severity, code, region, policy.
    - Unique counts of policies, regions and paths, plus a per-policy summary.

Reports are saved under `reports/fmm_policy_snapshot/YYYY-MM-DD/`.

## IAM permissions

FMS admin profile: `fms:ListPolicies`, `fms:GetPolicy`,
`fms:ListTagsForResource`, `sts:GetCallerIdentity`, and `ec2:DescribeRegions`
(for `--all-regions`).
