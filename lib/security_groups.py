"""
Security groups: parse group / interface / instance / Lambda identifiers, choose
the profile, find the groups that apply, and load them with their rules and
prefix lists.

Intent: tools that compare or report on security groups need the same steps -
accept ARNs or ids, read every rule with describe_security_group_rules, expand
prefix lists to their current CIDRs, and turn each rule into access boxes
(lib/boxes.py) - so this module does them once.

Rules are normalised so that self-references read 'self' and descriptions are
kept for display only (never part of a rule's identity).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

from lib.accounts import caller_account, pick_profile, profile_lookup
from lib.aws_common import _g, err_text, get_client
from lib.boxes import Box, addr_interval, fmt_proto_ports, proto_port_box

log = logging.getLogger("security_groups")

ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):security-group/(sg-[0-9a-f]+)$")
ID_RE = re.compile(r"^sg-[0-9a-f]{8,17}$")
ENI_ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):network-interface/(eni-[0-9a-f]+)$")
ENI_ID_RE = re.compile(r"^eni-[0-9a-f]{8,17}$")
INSTANCE_ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):instance/(i-[0-9a-f]+)$")
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
LAMBDA_ARN_RE = re.compile(r"^arn:aws[\w-]*:lambda:([a-z0-9-]+):(\d{12}):function:([A-Za-z0-9_-]+(?::[A-Za-z0-9_$-]+)?)$")
# Workloads stand for the security groups that apply to them.
WORKLOAD_ARN_RES = (ENI_ARN_RE, INSTANCE_ARN_RE, LAMBDA_ARN_RE)


@dataclass
class SG:
    """Security group metadata used in reports."""
    group_id: str
    name: str
    vpc_id: str
    owner: str
    region: str
    description: str = ""

    def __str__(self):
        """e.g. 'sg-0abc (web, vpc-1, us-east-1)'."""
        return f"{self.group_id} ({self.name}, {self.vpc_id}, {self.region})"


@dataclass
class SgRule:
    """One security group rule, plus the boxes describing the access it grants.

    `peer` is a CIDR, prefix list id, group id, or 'self' for a self-reference, so that
    self-references in different groups compare equal.
    """
    group_id: str
    rule_id: str
    egress: bool
    proto: str
    from_port: int | None
    to_port: int | None
    peer: str            # CIDR, pl-..., sg-..., or "self"
    peer_kind: str       # ipv4 | ipv6 | pl | sg
    description: str = ""
    peer_label: str = ""
    boxes: list[tuple[str, Box]] = field(default_factory=list)

    @classmethod
    def from_api(cls, r: dict) -> "SgRule":
        """Build from a DescribeSecurityGroupRules entry."""
        gid = r["GroupId"]
        if r.get("CidrIpv4"):
            kind, peer = "ipv4", str(ipaddress.ip_network(r["CidrIpv4"], strict=False))
        elif r.get("CidrIpv6"):
            kind, peer = "ipv6", str(ipaddress.ip_network(r["CidrIpv6"], strict=False))
        elif r.get("PrefixListId"):
            kind, peer = "pl", r["PrefixListId"]
        else:
            ref = _g(r, "ReferencedGroupInfo", {})
            kind, peer = "sg", ref.get("GroupId", "?")
            if peer == gid:
                peer = "self"
        return cls(group_id=gid, rule_id=r.get("SecurityGroupRuleId", ""), egress=bool(r.get("IsEgress")),
                   proto=str(r.get("IpProtocol", "-1")), from_port=r.get("FromPort"), to_port=r.get("ToPort"),
                   peer=peer, peer_kind=kind, description=r.get("Description") or "")

    @property
    def direction(self) -> str:
        """'ingress' or 'egress'."""
        return "egress" if self.egress else "ingress"

    def key(self) -> tuple:
        """Identity used for IDENTICAL matches: direction, protocol/port box and peer (not the description)."""
        return (self.egress, proto_port_box(self.proto, self.from_port, self.to_port), self.peer)

    def expand(self, prefix_lists: dict[str, list[str] | None]) -> None:
        """Fill `boxes`: one per CIDR, one per prefix list entry, or a single opaque box for group
        references and unreadable prefix lists (matched by id only).
        """
        pr, ports = proto_port_box(self.proto, self.from_port, self.to_port)
        if self.peer_kind in ("ipv4", "ipv6"):
            cidrs = [self.peer]
        elif self.peer_kind == "pl" and prefix_lists.get(self.peer) is not None:
            cidrs = prefix_lists[self.peer]
        else:
            self.boxes = [(f"{self.peer_kind}:{self.peer}", (pr, ports, (0, 0)))]
            return
        self.boxes = []
        for c in cidrs:
            net = ipaddress.ip_network(c, strict=False)
            self.boxes.append((f"ipv{net.version}", (pr, ports, addr_interval(net))))

    def access(self) -> str:
        """Protocol and ports only, e.g. 'tcp 443', 'icmp type 8', 'all traffic'."""
        return fmt_proto_ports(*proto_port_box(self.proto, self.from_port, self.to_port))

    def __str__(self) -> str:
        """e.g. 'tcp 443 from 10.0.0.0/8' or 'tcp 5432 from pl-123 (corp-db, 2 entries)'."""
        prep = "to" if self.egress else "from"
        peer = f"{self.peer} ({self.peer_label})" if self.peer_label else self.peer
        return f"{self.access()} {prep} {peer}"

    def ref(self) -> str:
        """Rule as listed under 'overlaps': group, rule id, rule and description."""
        d = f' "{self.description}"' if self.description else ""
        return f"{self.group_id} {self.rule_id} {self}{d}"


def split_specs(specs: list[str]) -> list[str]:
    """Arguments split on commas, blanks dropped."""
    return [s.strip() for x in specs for s in x.split(",") if s.strip()]


def spec_accounts(specs: list[str]) -> set[str]:
    """Account ids named by group, interface, instance or Lambda function ARNs among `specs`."""
    out = set()
    for spec in split_specs(specs):
        m = next((r.match(spec) for r in (ARN_RE, *WORKLOAD_ARN_RES) if r.match(spec)), None)
        if m:
            out.add(m.group(2))
    return out


def parse_target(spec: str, default_region: str | None, allow_workloads: bool = False) -> tuple[str | None, str, str]:
    """One target -> (account named by its ARN or None, region, id). id is a group id, or with
    allow_workloads also an interface id (eni-), an instance id (i-) or
    'lambda:<function>[:<version or alias>]' (Lambda only by ARN)."""
    arn_res = (ARN_RE, *WORKLOAD_ARN_RES) if allow_workloads else (ARN_RE,)
    m = next((r.match(spec) for r in arn_res if r.match(spec)), None)
    if m:
        region, account, rid = m.groups()
        return account, region, f"lambda:{rid}" if m.re is LAMBDA_ARN_RE else rid
    if ID_RE.match(spec) or (allow_workloads and (ENI_ID_RE.match(spec) or INSTANCE_ID_RE.match(spec))):
        if not default_region:
            raise ValueError(f"{spec}: bare id needs --region (or AWS_REGION / profile region)")
        return None, default_region, spec
    kinds = "security group, network interface, EC2 instance or Lambda function" if allow_workloads else "security group"
    raise ValueError(f"not a {kinds} ARN or id: {spec!r}")


def parse_account_targets(specs: list[str], default_region: str | None,
                          allow_workloads: bool = True) -> list[tuple[str | None, str, str]]:
    """Targets, possibly in several accounts -> [(account or None for bare ids, region, id)] in
    argument order, duplicates dropped. Without allow_workloads only security groups."""
    seen, out = set(), []
    for t in (parse_target(spec, default_region, allow_workloads) for spec in split_specs(specs)):
        if t not in seen:
            seen.add(t)
            out.append(t)
    if not out:
        raise ValueError("no targets given")
    return out


def resolve_account_profiles(args, arn_accounts: set[str], bare_ids: bool) \
        -> tuple[dict[str, tuple[str | None, str]], str | None]:
    """The profile to read each account with, and the account bare ids belong to.

    * --profile is used for its own account.
    * Each other account named by ARNs uses its local profile, found by account id (profiles
      ending in an excluded suffix such as -priv / -cpar are never used; --account-profile
      forces one).
    * Bare ids belong to the --profile account; without --profile, to the single ARN account
      if there is exactly one; with no ARNs at all, to AWS_PROFILE or the default credentials.
      Bare ids next to ARNs from several accounts (and no --profile) are ambiguous: refused.

    Every profile is verified with sts:GetCallerIdentity. Returns ({account: (profile,
    how it was chosen)}, bare-id account or None).
    """
    out: dict[str, tuple[str | None, str]] = {}
    if args.profile:
        out[caller_account(args.profile)] = (args.profile, "--profile")
    pmap, overrides = profile_lookup(args)
    for account in sorted(arn_accounts - set(out)):
        profile, note = pick_profile(account, pmap, overrides)
        if not profile:
            raise ValueError(f"no local AWS profile for account {account} (excluding "
                             f"{args.exclude_profile_suffix}); use --account-profile")
        if note and note != "override":
            log.warning("Account %s: %s", account, note)
        actual = caller_account(profile)
        if actual != account:
            raise ValueError(f"profile {profile} is account {actual}, expected {account}")
        out[account] = (profile, f"local profile for account {account}" + (" (override)" if note == "override" else ""))
    bare = None
    if args.profile and not bare_ids:
        mine = next(a for a, (p, _) in out.items() if p == args.profile)
        if mine not in arn_accounts:
            log.warning("--profile %s is account %s, which no target is in; not used", args.profile, mine)
    if bare_ids:
        if args.profile:
            bare = next(a for a, (p, _) in out.items() if p == args.profile)
        elif len(arn_accounts) == 1:
            bare = next(iter(arn_accounts))
        elif not arn_accounts:
            env = os.getenv("AWS_PROFILE") or None
            bare = caller_account(env)
            out[bare] = (env, "AWS_PROFILE" if env else "default credentials")
        else:
            raise ValueError(f"bare ids are ambiguous next to ARNs from several accounts "
                             f"({', '.join(sorted(arn_accounts))}); use ARNs, or --profile for the bare ids' account")
    return out, bare


def fetch_prefix_lists(ec2, ids: set[str]) -> tuple[dict[str, list[str] | None], dict[str, str], list[str]]:
    """Read the names and current entries of the referenced prefix lists.

    Returns (entries by id, None when unreadable; names by id; error lines for warnings).
    """
    entries: dict[str, list[str] | None] = {}
    names: dict[str, str] = {}
    errors = []
    if not ids:
        return entries, names, errors
    try:
        for page in ec2.get_paginator("describe_managed_prefix_lists").paginate(PrefixListIds=sorted(ids)):
            for pl in _g(page, "PrefixLists", []):
                names[pl["PrefixListId"]] = pl.get("PrefixListName", "")
    except ClientError as e:
        log.debug("describe_managed_prefix_lists: %s", e)
    for pid in sorted(ids):
        try:
            cidrs = []
            for page in ec2.get_paginator("get_managed_prefix_list_entries").paginate(PrefixListId=pid):
                cidrs.extend(e["Cidr"] for e in _g(page, "Entries", []))
            entries[pid] = cidrs
        except ClientError as e:
            entries[pid] = None
            errors.append(f"{pid}: {e.response.get('Error', {}).get('Code', e)}")
    return entries, names, errors


def resolve_workloads(session_factory, targets: list[tuple[str, str]]) \
        -> tuple[list[tuple[str, str]], list[dict], list[str]]:
    """Replace workload targets by the security groups that apply to them (argument order kept).

    * network interface (eni-): its groups
    * EC2 instance (i-): each of its network interfaces, with that interface's groups
    * Lambda function (lambda:name[:qualifier]): the groups in its VPC configuration; a
      function not attached to a VPC has none, and is reported in the warnings and skipped

    Returns the group targets, one dict per interface / function (id, kind: eni | instance |
    lambda, region, attachment, vpc_id, description, groups), and warning lines.
    """
    by_region: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for region, rid in targets:
        kind = "eni" if rid.startswith("eni-") else "instance" if rid.startswith("i-") else \
            "lambda" if rid.startswith("lambda:") else None
        if kind:
            by_region[region][kind].append(rid)
    found: dict[tuple[str, str], list[dict]] = {}
    warnings: list[str] = []
    for region, kinds in by_region.items():
        session = session_factory(region)
        if kinds["eni"] or kinds["instance"]:
            ec2 = get_client("ec2", session)
        try:
            if kinds["eni"]:
                for n in _g(ec2.describe_network_interfaces(NetworkInterfaceIds=kinds["eni"]), "NetworkInterfaces", []):
                    att = _g(n, "Attachment", {})
                    found[(region, n["NetworkInterfaceId"])] = [{
                        "id": n["NetworkInterfaceId"], "kind": "eni", "region": region,
                        "attachment": att.get("InstanceId") or n.get("InterfaceType") or "",
                        "vpc_id": n.get("VpcId", ""), "description": n.get("Description", ""),
                        "groups": [g["GroupId"] for g in _g(n, "Groups", [])]}]
            if kinds["instance"]:
                for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=kinds["instance"]):
                    for res in _g(page, "Reservations", []):
                        for inst in _g(res, "Instances", []):
                            name = next((t["Value"] for t in _g(inst, "Tags", []) if t.get("Key") == "Name"), "")
                            nics = sorted(_g(inst, "NetworkInterfaces", []),
                                          key=lambda n: _g(n, "Attachment", {}).get("DeviceIndex", 0))
                            found[(region, inst["InstanceId"])] = [{
                                "id": n["NetworkInterfaceId"], "kind": "instance", "region": region,
                                "attachment": f"{inst['InstanceId']} eth{_g(n, 'Attachment', {}).get('DeviceIndex', 0)}",
                                "vpc_id": n.get("VpcId", ""), "description": name or n.get("Description", ""),
                                "groups": [g["GroupId"] for g in _g(n, "Groups", [])]} for n in nics]
            if kinds["lambda"]:
                lam = get_client("lambda", session)
                for rid in kinds["lambda"]:
                    fn, _, qual = rid[len("lambda:"):].partition(":")
                    cfg = lam.get_function_configuration(FunctionName=fn, **({"Qualifier": qual} if qual else {}))
                    vpc = _g(cfg, "VpcConfig", {})
                    sgs = list(vpc.get("SecurityGroupIds") or [])
                    if not sgs:
                        warnings.append(f"Lambda {fn}{':' + qual if qual else ''}: not attached to a VPC, so no "
                                        "security groups apply; skipped")
                        found[(region, rid)] = []
                        continue
                    found[(region, rid)] = [{
                        "id": fn + (f":{qual}" if qual else ""), "kind": "lambda", "region": region,
                        "attachment": cfg.get("FunctionArn", ""), "vpc_id": vpc.get("VpcId", ""),
                        "description": f"Lambda {cfg.get('Runtime') or cfg.get('PackageType', '')}, "
                                       f"subnets {', '.join(vpc.get('SubnetIds') or [])}",
                        "groups": sgs}]
        except ClientError as e:
            raise ValueError(f"{region}: {err_text(e)}") from e
    out, seen, entries = [], set(), []
    for region, rid in targets:
        if (region, rid) in found:
            items = found[(region, rid)]
            entries += [x for x in items if x["id"] not in {e["id"] for e in entries}]
            gids = [g for x in items for g in x["groups"]]
        elif rid.startswith(("eni-", "i-", "lambda:")):
            raise ValueError(f"{region}: {rid} not found")
        else:
            gids = [rid]
        for gid in gids:
            if (region, gid) not in seen:
                seen.add((region, gid))
                out.append((region, gid))
    return out, entries, warnings


def load_groups(session_factory, targets: list[tuple[str, str]]):
    """Fetch the groups, their rules and referenced prefix lists, region by region, and expand
    every rule into boxes.

    Returns the groups in argument order, rules by group (sorted by direction, access, peer),
    and warning lines for prefix lists whose entries could not be read.
    """
    groups: dict[str, SG] = {}
    rules: dict[str, list[SgRule]] = {}
    warnings: list[str] = []
    by_region = defaultdict(list)
    for region, gid in targets:
        by_region[region].append(gid)
    for region, ids in by_region.items():
        ec2 = get_client("ec2", session_factory(region))
        try:
            resp = ec2.describe_security_groups(GroupIds=ids)
        except ClientError as e:
            raise ValueError(f"{region}: {e.response.get('Error', {}).get('Message', e)}") from e
        for g in resp["SecurityGroups"]:
            groups[g["GroupId"]] = SG(g["GroupId"], g.get("GroupName", ""), g.get("VpcId", ""),
                                      g.get("OwnerId", ""), region, g.get("Description", ""))
            rules[g["GroupId"]] = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": ids}]):
            for r in _g(page, "SecurityGroupRules", []):
                rules[r["GroupId"]].append(SgRule.from_api(r))
        pl_ids = {r.peer for gid in ids for r in rules[gid] if r.peer_kind == "pl"}
        entries, names, errors = fetch_prefix_lists(ec2, pl_ids)
        warnings.extend(f"{region} {err}" for err in errors)
        for gid in ids:
            for r in rules[gid]:
                if r.peer_kind == "pl":
                    n = entries.get(r.peer)
                    r.peer_label = ", ".join(x for x in (names.get(r.peer, ""),
                                                         f"{len(n)} entries" if n is not None else "unresolved") if x)
                r.expand(entries)
    ordered = [groups[gid] for _, gid in targets]
    for g in ordered:
        rules[g.group_id].sort(key=lambda r: (r.egress, r.key()[1], r.peer))
    return ordered, rules, warnings
