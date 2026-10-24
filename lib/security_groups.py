"""
Security groups: parse group / interface identifiers, choose the profile, and
load groups with their rules and prefix lists.

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

from lib.accounts import pick_profile, profile_lookup
from lib.aws_common import _g, err_text, get_client
from lib.boxes import Box, addr_interval, fmt_proto_ports, proto_port_box

log = logging.getLogger("security_groups")

ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):security-group/(sg-[0-9a-f]+)$")
ID_RE = re.compile(r"^sg-[0-9a-f]{8,17}$")
ENI_ARN_RE = re.compile(r"^arn:aws[\w-]*:ec2:([a-z0-9-]+):(\d{12}):network-interface/(eni-[0-9a-f]+)$")
ENI_ID_RE = re.compile(r"^eni-[0-9a-f]{8,17}$")


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
    """Account ids named by group or interface ARNs among `specs`."""
    out = set()
    for spec in split_specs(specs):
        m = ARN_RE.match(spec) or ENI_ARN_RE.match(spec)
        if m:
            out.add(m.group(2))
    return out


def parse_targets(specs: list[str], default_region: str | None, min_groups: int = 2,
                  allow_enis: bool = False) -> tuple[list[tuple[str, str]], str | None]:
    """-> [(region, group_or_eni_id)] in argument order (duplicates dropped), and the account
    named by ARNs (None if only ids). ENI ids / ARNs are accepted only with allow_enis.
    """
    targets, accounts = [], set()
    for spec in split_specs(specs):
        m = ARN_RE.match(spec) or (ENI_ARN_RE.match(spec) if allow_enis else None)
        if m:
            region, account, rid = m.groups()
            accounts.add(account)
            targets.append((region, rid))
        elif ID_RE.match(spec) or (allow_enis and ENI_ID_RE.match(spec)):
            if not default_region:
                raise ValueError(f"{spec}: bare id needs --region (or AWS_REGION / profile region)")
            targets.append((default_region, spec))
        else:
            kinds = "security group or network interface" if allow_enis else "security group"
            raise ValueError(f"not a {kinds} ARN or id: {spec!r}")
    if len(accounts) > 1:
        raise ValueError(f"security groups must be in one account; ARNs name {', '.join(sorted(accounts))}")
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]
    if len(targets) < min_groups:
        raise ValueError("need at least two distinct security groups" if min_groups == 2
                         else f"need at least {min_groups} security group(s)")
    return targets, (accounts.pop() if accounts else None)


def resolve_profile(args, account: str | None) -> tuple[str | None, str]:
    """Profile to read the groups with, and how it was chosen.

    --profile wins. Otherwise, when ARNs name an account, that account's local profile
    (profiles ending in an excluded suffix such as -priv / -cpar are never used;
    --account-profile forces one). Otherwise AWS_PROFILE, else the default credential chain.
    The caller verifies the profile's account.
    """
    if args.profile:
        return args.profile, "--profile"
    if account:
        profile, note = pick_profile(account, *profile_lookup(args))
        if not profile:
            raise ValueError(f"no local AWS profile for account {account} (excluding "
                             f"{args.exclude_profile_suffix}); use --profile or --account-profile")
        if note and note != "override":
            log.warning("Account %s: %s", account, note)
        return profile, f"local profile for account {account}" + (" (override)" if note == "override" else "")
    env = os.getenv("AWS_PROFILE") or None
    return env, "AWS_PROFILE" if env else "default credentials"


def check_account(profile: str | None, region: str, account: str | None) -> str:
    """Account id of the profile; ValueError when ARNs name a different account."""
    actual = get_client("sts", boto3.Session(profile_name=profile, region_name=region)).get_caller_identity()["Account"]
    if account and actual != account:
        raise ValueError(f"profile {profile or '(default)'} is account {actual}; ARNs name {account}")
    return actual


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


def resolve_enis(session_factory, targets: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[dict]]:
    """Replace ENI targets by their attached groups (in place, argument order kept).

    Returns the group targets and one dict per interface: eni_id, region, description,
    attachment (instance id or interface type), groups.
    """
    enis = defaultdict(list)
    for region, rid in targets:
        if rid.startswith("eni-"):
            enis[region].append(rid)
    found: dict[str, dict] = {}
    for region, ids in enis.items():
        ec2 = get_client("ec2", session_factory(region))
        try:
            resp = ec2.describe_network_interfaces(NetworkInterfaceIds=ids)
        except ClientError as e:
            raise ValueError(f"{region}: {err_text(e)}") from e
        for n in _g(resp, "NetworkInterfaces", []):
            att = _g(n, "Attachment", {})
            found[n["NetworkInterfaceId"]] = {
                "eni_id": n["NetworkInterfaceId"], "region": region, "description": n.get("Description", ""),
                "attachment": att.get("InstanceId") or n.get("InterfaceType") or "",
                "vpc_id": n.get("VpcId", ""), "groups": [g["GroupId"] for g in _g(n, "Groups", [])]}
    out, seen = [], set()
    for region, rid in targets:
        ids = found[rid]["groups"] if rid.startswith("eni-") else [rid]
        for gid in ids:
            if (region, gid) not in seen:
                seen.add((region, gid))
                out.append((region, gid))
    return out, [found[rid] for _, rid in targets if rid.startswith("eni-")]


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
