#!/usr/bin/env python3
"""
AWS Firewall Manager (FMS) rule parity review.

Intent: when access is being moved or duplicated (an old IP to a new prefix
list, one load balancer to two, a new CIDR alongside an old one), every FMS
rule that allows target A should have a sibling rule for target B. This tool
finds the rules where A is allowed but B is not, so nothing is missed.

What it does:

  1. Lists the Firewall Manager policies in one or more regions.
  2. Expands the rules each policy carries into one normalised form:
     security group rules (prefix lists expanded), Network Firewall stateless,
     stateful and Suricata rules (IP set / port set variables and prefix list
     references resolved), and NACL entries.
  3. Finds rules matching any A target (IP/CIDR or prefix list, protocol,
     port) and checks that the same container (or the same policy, with
     --scope policy) holds a same-shape rule matching the B target(s) in the
     same role (source or destination).
  4. Reports each gap, and a compliance status per container
     (NON_COMPLIANT / COMPLIANT / NOT_APPLICABLE).

Usage:

    ./fmm_rule_parity.py --profile fms-admin --region us-east-1 \
        -a 10.0.0.1 tcp 8080 -b pl-0123abcd tcp 8080

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Default region(s) when --region not given
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports: text on screen, plus auto-saved HTML (interactive: filter, sort,
unique counts), per-container compliance CSV, rule-level gaps CSV and JSON
under reports/fmm_rule_parity/YYYY-MM-DD/.

Exit codes: 0 no gaps, 1 gaps found, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
from pathlib import Path
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator

import truststore

truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib.aws_common import (_g, get_client, get_policy, get_session, list_policies,  # noqa: E402,F401
                            normalize_proto, resolve_regions)

log = logging.getLogger("fmm_rule_parity")

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
PortRange = tuple[int, int]
ANY_PORTS: PortRange = (0, 65535)


SUPPORTED_POLICY_TYPES = {
    "SECURITY_GROUPS_COMMON",
    "SECURITY_GROUPS_CONTENT_AUDIT",
    "NETWORK_FIREWALL",
    "NETWORK_ACL_COMMON",
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """One side of the parity question: an IP/CIDR or managed prefix list, plus protocol and port.

    A targets are what must be present in a rule; B targets are what is expected alongside them.
    """
    label: str
    nets: list[IPNet]        # one CIDR, or every CIDR of a managed prefix list
    proto: str               # 'tcp', 'udp', 'icmp', 'any', or a protocol number string
    ports: PortRange | None  # None => any port
    source: str = ""         # original IP/CIDR or prefix list id
    pl_id: str | None = None # set when the target is a managed prefix list
    match: str = "ref"       # ref: rule must reference the prefix list id itself;
                             # cidrs-all / cidrs-any: rule CIDRs must cover all / any of its entries

    PL_RE = re.compile(r"(?:^|prefix-list/)(pl-[0-9a-z]+)$", re.IGNORECASE)

    @classmethod
    def parse(cls, label: str, ip: str, proto: str, port: str,
              resolve_pl=None, pl_match: str = "ref") -> "Target":
        """Build a target from user tokens (IP or prefix list, PROTO, PORT).

        Prefix lists are kept by id for `ref` matching, or expanded through `resolve_pl` for the
        `cidrs-*` modes. Raises ValueError for unreadable or empty prefix lists.
        """
        p = normalize_proto(proto)
        ports = None if port.lower() in ("any", "all", "*", "-1") else parse_port_range(port)
        m = cls.PL_RE.search(ip.strip())
        if m:
            pl_id = m.group(1).lower()
            if pl_match == "ref":
                return cls(label=label, nets=[], proto=p, ports=ports, source=pl_id,
                           pl_id=pl_id, match="ref")
            if resolve_pl is None:
                raise ValueError(f"{ip}: prefix list CIDR matching needs an AWS session")
            nets = resolve_pl(pl_id)
            if nets is None:
                raise ValueError(f"{ip}: could not read managed prefix list")
            if not nets:
                raise ValueError(f"{ip}: prefix list has no entries")
            return cls(label=label, nets=nets, proto=p, ports=ports, source=pl_id,
                       pl_id=pl_id, match=pl_match)
        net = ipaddress.ip_network(ip, strict=False)
        return cls(label=label, nets=[net], proto=p, ports=ports, source=str(net), match="cidrs-all")

    def covered_by(self, rule_nets: list[IPNet], rule_pls: list[str]) -> bool:
        """True when a rule side (its CIDRs and referenced prefix lists) satisfies this target."""
        if self.match == "ref":
            return self.pl_id in rule_pls
        hits = [nets_contain(rule_nets, n) for n in self.nets]
        return all(hits) if self.match == "cidrs-all" else any(hits)

    def __str__(self) -> str:
        """Human-readable target, e.g. '10.0.0.1/32 tcp 8080' or 'pl-123 (prefix list, match=ref) tcp any'."""
        port = "any" if self.ports is None else fmt_ports(self.ports)
        desc = self.source
        if self.pl_id:
            desc += f" (prefix list, match={self.match}" + (f", {len(self.nets)} cidrs)" if self.nets else ")")
        return f"{desc} {self.proto} {port}"


@dataclass
class Rule:
    """One normalised firewall rule from an FMS policy (SG rule, Network Firewall rule or NACL entry).

    Every policy type is reduced to this shape so A/B matching and parity work the same way
    across them. `None` for nets/ports means unconstrained (any).
    """
    region: str
    policy_id: str
    policy_name: str
    policy_type: str
    container: str          # sg id, rule-group ARN, or NACL entry list name
    container_name: str     # human name: SG GroupName, rule group name, or NACL list
    kind: str               # sg-ingress, sg-egress, nfw-stateless, nfw-stateful (incl. Suricata), nacl
    direction: str          # ingress / egress / forward / any
    action: str
    proto: str
    src_nets: list[IPNet] | None   # None => any
    dst_nets: list[IPNet] | None
    src_ports: list[PortRange] | None
    dst_ports: list[PortRange] | None
    raw: str
    unresolved: list[str] = field(default_factory=list)
    src_pls: list[str] = field(default_factory=list)   # managed prefix list ids referenced
    dst_pls: list[str] = field(default_factory=list)

    def matches(self, t: Target) -> list[str]:
        """
        Return roles in which the target matches: 'src', 'dst', or 'any' when the
        rule constrains neither side. Empty list means no match.
        Only explicitly defined address/port lists count; a wildcard side never
        matches on its own when the other side is constrained.
        """
        if not proto_compatible(self.proto, t.proto):
            return []
        if t.ports is not None and self.proto in ("tcp", "udp", "any"):
            if self.src_ports is None and self.dst_ports is None:
                pass  # rule is port-agnostic
            elif not ((self.src_ports is not None and ports_contain(self.src_ports, t.ports))
                      or (self.dst_ports is not None and ports_contain(self.dst_ports, t.ports))):
                return []
        if self.src_nets is None and self.dst_nets is None:
            # Unconstrained on both sides: matches any CIDR target; never "references" a PL.
            return [] if t.match == "ref" else ["any"]
        roles = []
        if self.src_nets is not None and t.covered_by(self.src_nets, self.src_pls):
            roles.append("src")
        if self.dst_nets is not None and t.covered_by(self.dst_nets, self.dst_pls):
            roles.append("dst")
        return roles

    def shape_key(self) -> tuple:
        """Attributes that must agree for two rules to be considered 'parallel'."""
        return (self.kind, self.direction, self.action, self.proto)

    def to_dict(self) -> dict:
        """JSON-friendly dict of the rule (networks and ports rendered as strings)."""
        d = asdict(self)
        d["src_nets"] = None if self.src_nets is None else [str(n) for n in self.src_nets]
        d["dst_nets"] = None if self.dst_nets is None else [str(n) for n in self.dst_nets]
        d["src_ports"] = None if self.src_ports is None else [fmt_ports(p) for p in self.src_ports]
        d["dst_ports"] = None if self.dst_ports is None else [fmt_ports(p) for p in self.dst_ports]
        return d


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def proto_compatible(rule_proto: str, target_proto: str) -> bool:
    """True when a rule protocol and a target protocol can match (equal, or either is 'any')."""
    if rule_proto == "any" or target_proto == "any":
        return True
    return rule_proto == target_proto


def parse_port_range(s: str) -> PortRange:
    """Parse '8080', '8000-8100' or '8000:8100' into (from, to); 'any'/'*'/'-1' mean all ports."""
    s = s.strip()
    if s.lower() in ("any", "all", "*", "-1", ""):
        return ANY_PORTS
    for sep in ("-", ":"):
        if sep in s:
            a, b = s.split(sep, 1)
            return (int(a), int(b))
    v = int(s)
    return (v, v)


def fmt_ports(p: PortRange) -> str:
    """Render a port range as '8080', '8000-8100' or 'any'."""
    if p == ANY_PORTS:
        return "any"
    return str(p[0]) if p[0] == p[1] else f"{p[0]}-{p[1]}"


def ports_contain(ranges: list[PortRange] | None, want: PortRange) -> bool:
    """True when any range in `ranges` contains `want` (None = unconstrained, contains everything)."""
    if ranges is None:
        return True
    return any(r[0] <= want[0] and want[1] <= r[1] for r in ranges)


def nets_contain(nets: list[IPNet] | None, want: IPNet) -> bool:
    """True when `want` is a subnet of any same-family network in `nets` (None = any)."""
    if nets is None:
        return True
    for n in nets:
        if n.version != want.version:
            continue
        if want.subnet_of(n):
            return True
    return False


def safe_net(s: str) -> IPNet | None:
    """Parse a CIDR or IP, returning None instead of raising for anything unparseable."""
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Extractors
# --------------------------------------------------------------------------- #
class Extractor:
    """Reads the rules behind each FMS policy in one region and yields normalised `Rule`s.

    Resolves what the policy references (security groups, Network Firewall rule groups,
    managed prefix lists) and caches each lookup, since many policies share them.
    """
    def __init__(self, session: boto3.Session, region: str):
        """Create the FMS client for `region`; EC2 and Network Firewall clients are made on first use."""
        self.session = session
        self.region = region
        self.fms = get_client("fms", session)
        self._ec2 = None
        self._nfw = None
        self._sg_cache: dict[str, dict] = {}
        self._rg_cache: dict[str, dict] = {}
        self._pl_cache: dict[str, list[IPNet] | None] = {}

    @property
    def ec2(self):
        """Lazily created EC2 client (security groups, prefix lists)."""
        if self._ec2 is None:
            self._ec2 = get_client("ec2", self.session)
        return self._ec2

    @property
    def nfw(self):
        """Lazily created Network Firewall client (rule groups)."""
        if self._nfw is None:
            self._nfw = get_client("network-firewall", self.session)
        return self._nfw

    # -- top level ---------------------------------------------------------- #
    def rules_for_policy(self, policy: dict) -> Iterator[Rule]:
        """Yield every IP/port rule carried by one FMS policy, dispatching on its policy type.

        Policy types without IP/port semantics (WAF, Shield, DNS Firewall, ...) yield nothing.
        """
        ssp = _g(policy, "SecurityServicePolicyData", {})
        ptype = ssp.get("Type", "")
        msd_raw = ssp.get("ManagedServiceData") or "{}"
        try:
            msd = json.loads(msd_raw)
        except json.JSONDecodeError:
            log.warning("Policy %s: ManagedServiceData not JSON, skipping", policy.get("PolicyName"))
            return
        base = dict(region=self.region, policy_id=policy["PolicyId"],
                    policy_name=policy["PolicyName"], policy_type=ptype)

        if ptype in ("SECURITY_GROUPS_COMMON", "SECURITY_GROUPS_CONTENT_AUDIT"):
            for sg in _g(msd, "securityGroups", []):
                yield from self._sg_rules(sg["id"], base)
        elif ptype == "NETWORK_FIREWALL":
            for ref in _g(msd, "networkFirewallStatelessRuleGroupReferences", []):
                yield from self._nfw_rule_group(ref["resourceARN"], base)
            for ref in _g(msd, "networkFirewallStatefulRuleGroupReferences", []):
                yield from self._nfw_rule_group(ref["resourceARN"], base)
        elif ptype == "NETWORK_ACL_COMMON":
            entry_set = _g(msd, "networkAclEntrySet", {})
            for list_name in ("firstEntries", "lastEntries"):
                for idx, e in enumerate(_g(entry_set, list_name, [])):
                    yield self._nacl_rule(e, idx, f"networkAclEntrySet.{list_name}", base)
        else:
            log.debug("Policy %s type %s has no IP/port rules to inspect; skipped",
                      policy["PolicyName"], ptype)

    # -- managed prefix lists ----------------------------------------------- #
    _PL_ARN_RE = re.compile(r"prefix-list/(pl-[0-9a-z]+)$")

    def _prefix_list_nets(self, pl_id: str) -> list[IPNet] | None:
        """Expand a managed prefix list (customer- or AWS-managed) to CIDRs. None on failure."""
        if pl_id in self._pl_cache:
            return self._pl_cache[pl_id]
        nets: list[IPNet] = []
        try:
            paginator = self.ec2.get_paginator("get_managed_prefix_list_entries")
            for page in paginator.paginate(PrefixListId=pl_id):
                for e in _g(page, "Entries", []):
                    n = safe_net(e["Cidr"])
                    if n:
                        nets.append(n)
            log.debug("Prefix list %s: %d entries", pl_id, len(nets))
            result: list[IPNet] | None = nets
        except ClientError as e:
            log.error("get_managed_prefix_list_entries %s failed: %s %s", pl_id,
                      e.response["Error"]["Code"], e.response["Error"]["Message"])
            result = None
        self._pl_cache[pl_id] = result
        return result

    def _prefix_list_from_arn(self, arn: str) -> list[IPNet] | None:
        """Expand a prefix list given by ARN (as in Network Firewall ReferenceSets); None if unreadable."""
        m = self._PL_ARN_RE.search(arn)
        return self._prefix_list_nets(m.group(1)) if m else None

    # -- security groups ---------------------------------------------------- #
    def _describe_sg(self, sg_id: str) -> dict | None:
        """Fetch (and cache) one security group; None if it cannot be read."""
        if sg_id in self._sg_cache:
            return self._sg_cache[sg_id]
        try:
            resp = self.ec2.describe_security_groups(GroupIds=[sg_id])
            sg = resp["SecurityGroups"][0]
        except ClientError as e:
            log.error("describe_security_groups %s failed: %s %s", sg_id,
                      e.response["Error"]["Code"], e.response["Error"]["Message"])
            sg = None
        self._sg_cache[sg_id] = sg
        return sg

    def _sg_rules(self, sg_id: str, base: dict) -> Iterator[Rule]:
        """Yield one Rule per CIDR and one per prefix list in a security group's ingress/egress permissions.

        SG-to-SG references and unreadable prefix lists are kept as `unresolved` so they are reported,
        and unreadable prefix list ids stay matchable by id.
        """
        sg = self._describe_sg(sg_id)
        if not sg:
            return
        for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
            for perm in _g(sg, key, []):
                proto = normalize_proto(perm.get("IpProtocol"))
                if proto in ("tcp", "udp"):
                    ports = [(perm.get("FromPort", 0), perm.get("ToPort", 65535))]
                else:
                    ports = None
                nets: list[IPNet] = []
                unresolved: list[str] = []
                for r in _g(perm, "IpRanges", []):
                    n = safe_net(r["CidrIp"])
                    nets.append(n) if n else unresolved.append(r["CidrIp"])
                for r in _g(perm, "Ipv6Ranges", []):
                    n = safe_net(r["CidrIpv6"])
                    nets.append(n) if n else unresolved.append(r["CidrIpv6"])
                prefix_lists: list[tuple[str, list[IPNet]]] = []
                for r in _g(perm, "PrefixListIds", []):
                    pl_id = r["PrefixListId"]
                    pl_nets = self._prefix_list_nets(pl_id)
                    if pl_nets is None:
                        unresolved.append(pl_id)   # still id-matchable, see below
                    else:
                        prefix_lists.append((pl_id, pl_nets))
                for r in _g(perm, "UserIdGroupPairs", []):
                    unresolved.append(r.get("GroupId", "sg-?"))
                if not nets and not prefix_lists and not unresolved:
                    continue
                port_txt = fmt_ports(ports[0]) if ports else "any"

                def emit(cidrs: list[IPNet], label: str, unres: list[str], pls: list[str] = []) -> Rule:
                    """Build the Rule for one CIDR set (or prefix list) of the current permission."""
                    return Rule(
                        **base, container=sg_id, container_name=sg.get("GroupName", ""),
                        kind=f"sg-{direction}", direction=direction,
                        action="allow", proto=proto,
                        src_nets=cidrs if direction == "ingress" else None,
                        dst_nets=cidrs if direction == "egress" else None,
                        src_ports=None, dst_ports=ports,
                        raw=f"{sg_id} {direction} {proto} {port_txt} {label}",
                        unresolved=unres,
                        src_pls=pls if direction == "ingress" else [],
                        dst_pls=pls if direction == "egress" else [],
                    )

                # One Rule per CIDR, one per prefix list (carrying all its CIDRs).
                for n in nets:
                    yield emit([n], str(n), [])
                for pl_id, pl_nets in prefix_lists:
                    yield emit(pl_nets, f"{pl_id}({len(pl_nets)} cidrs)", [], [pl_id])
                if unresolved and not nets and not prefix_lists:
                    # Keep unreadable prefix list ids referenceable by id-based targets.
                    pls = [u for u in unresolved if u.startswith("pl-")]
                    yield emit([], ",".join(unresolved), unresolved, pls)

    # -- network firewall --------------------------------------------------- #
    def _describe_rg(self, arn: str) -> dict | None:
        """Fetch (and cache) one Network Firewall rule group; None if it cannot be read."""
        if arn in self._rg_cache:
            return self._rg_cache[arn]
        try:
            rg = self.nfw.describe_rule_group(RuleGroupArn=arn)
        except ClientError as e:
            log.error("describe_rule_group %s failed: %s %s", arn,
                      e.response["Error"]["Code"], e.response["Error"]["Message"])
            rg = None
        self._rg_cache[arn] = rg
        return rg

    def _nfw_rule_group(self, arn: str, base: dict) -> Iterator[Rule]:
        """Yield the rules of a Network Firewall rule group (stateless, stateful 5-tuple, or Suricata).

        IP set / port set variables and ReferenceSets prefix lists are resolved first so rule
        addresses can be matched as CIDRs and, for prefix lists, by id.
        """
        rg = self._describe_rg(arn)
        if not rg:
            return
        body = _g(rg, "RuleGroup", {})
        rtype = _g(rg, "RuleGroupResponse", {}).get("Type", "")
        base = {**base, "container_name": _g(rg, "RuleGroupResponse", {}).get("RuleGroupName", "")}
        rs = _g(body, "RulesSource", {})
        variables = _g(body, "RuleVariables", {})
        ipsets = {k: [safe_net(d) for d in _g(v, "Definition", [])]
                  for k, v in _g(variables, "IPSets", {}).items()}
        pl_vars: dict[str, str] = {}   # $VAR -> pl-id
        for k, ref in _g(_g(body, "ReferenceSets", {}), "IPSetReferences", {}).items():
            ref_arn = ref.get("ReferenceArn", "")
            m = self._PL_ARN_RE.search(ref_arn)
            if m:
                pl_vars[k] = m.group(1)
            pl_nets = self._prefix_list_from_arn(ref_arn)
            if pl_nets is not None:
                ipsets[k] = pl_nets
            else:
                ipsets[k] = []   # id still matchable; CIDRs unknown
                log.warning("%s: IP set reference $%s -> %s could not be expanded",
                            arn, k, ref_arn)
        portsets = {k: [parse_port_range(d) for d in _g(v, "Definition", [])]
                    for k, v in _g(variables, "PortSets", {}).items()}

        if rtype == "STATELESS":
            for i, r in enumerate(_g(_g(rs, "StatelessRulesAndCustomActions", {}), "StatelessRules", [])):
                yield from self._nfw_stateless(r, i, arn, base)
        else:
            for i, r in enumerate(_g(rs, "StatefulRules", [])):
                yield self._nfw_stateful(r, i, arn, base, ipsets, portsets, pl_vars)
            if rs.get("RulesString"):
                yield from self._nfw_suricata(rs["RulesString"], arn, base, ipsets, portsets, pl_vars)
            if rs.get("RulesSourceList"):
                log.debug("%s: domain-list rule group, no IP/port rules", arn)

    def _nfw_stateless(self, r: dict, idx: int, arn: str, base: dict) -> Iterator[Rule]:
        """Yield one Rule per protocol of a stateless rule (its match attributes become src/dst nets and ports)."""
        m = _g(_g(r, "RuleDefinition", {}), "MatchAttributes", {})
        actions = ",".join(_g(_g(r, "RuleDefinition", {}), "Actions", []))
        src = [safe_net(s["AddressDefinition"]) for s in _g(m, "Sources", [])] or None
        dst = [safe_net(s["AddressDefinition"]) for s in _g(m, "Destinations", [])] or None
        sp = [(p["FromPort"], p["ToPort"]) for p in _g(m, "SourcePorts", [])] or None
        dp = [(p["FromPort"], p["ToPort"]) for p in _g(m, "DestinationPorts", [])] or None
        protos = [normalize_proto(p) for p in _g(m, "Protocols", [])] or ["any"]
        for proto in protos:
            yield Rule(
                **base, container=arn, kind="nfw-stateless", direction="any",
                action=actions, proto=proto,
                src_nets=[n for n in src if n] if src else None,
                dst_nets=[n for n in dst if n] if dst else None,
                src_ports=sp, dst_ports=dp,
                raw=f"stateless[{idx}] prio={r.get('Priority')} {actions} {proto} "
                    f"src={[str(n) for n in src] if src else 'any'}:{[fmt_ports(p) for p in sp] if sp else 'any'} "
                    f"dst={[str(n) for n in dst] if dst else 'any'}:{[fmt_ports(p) for p in dp] if dp else 'any'}",
            )

    @staticmethod
    def _resolve_addr(tok: str, ipsets: dict, pl_vars: dict | None = None
                      ) -> tuple[list[IPNet] | None, list[str], list[str]]:
        """Resolve a Suricata/stateful address token.
        Returns (nets or None=any, unresolved tokens, referenced prefix list ids)."""
        pl_vars = pl_vars or {}
        tok = tok.strip()
        if tok.lower() == "any":
            return None, [], []
        nets: list[IPNet] = []
        unresolved: list[str] = []
        pls: list[str] = []
        parts = [tok]
        if tok.startswith("[") and tok.endswith("]"):
            parts = [p.strip() for p in tok[1:-1].split(",") if p.strip()]
        for p in parts:
            if p.startswith("!"):
                unresolved.append(p)
                continue
            if p.startswith("$"):
                name = p[1:]
                if name in pl_vars:
                    pls.append(pl_vars[name])
                if name in ipsets:
                    nets.extend(n for n in ipsets[name] if n)
                else:
                    unresolved.append(p)
                continue
            n = safe_net(p)
            nets.append(n) if n else unresolved.append(p)
        return nets, unresolved, pls

    @staticmethod
    def _resolve_ports(tok: str, portsets: dict) -> tuple[list[PortRange] | None, list[str]]:
        """Resolve a Suricata/stateful port token (literal, range, list or $PORTSET) to port ranges.

        Returns (ranges or None = any, unresolved tokens); negations are reported, not evaluated.
        """
        tok = tok.strip()
        if tok.lower() == "any":
            return None, []
        out: list[PortRange] = []
        unresolved: list[str] = []
        parts = [tok]
        if tok.startswith("[") and tok.endswith("]"):
            parts = [p.strip() for p in tok[1:-1].split(",") if p.strip()]
        for p in parts:
            if p.startswith("!"):
                unresolved.append(p)
            elif p.startswith("$"):
                if p[1:] in portsets:
                    out.extend(portsets[p[1:]])
                else:
                    unresolved.append(p)
            else:
                try:
                    out.append(parse_port_range(p))
                except ValueError:
                    unresolved.append(p)
        return out, unresolved

    def _nfw_stateful(self, r: dict, idx: int, arn: str, base: dict, ipsets, portsets,
                      pl_vars: dict | None = None) -> Rule:
        """Convert one stateful 5-tuple rule (Header) to a Rule, resolving variables and prefix lists."""
        h = _g(r, "Header", {})
        src, u1, sp_pls = self._resolve_addr(_g(h, "Source", "ANY"), ipsets, pl_vars)
        dst, u2, dp_pls = self._resolve_addr(_g(h, "Destination", "ANY"), ipsets, pl_vars)
        sp, u3 = self._resolve_ports(_g(h, "SourcePort", "ANY"), portsets)
        dp, u4 = self._resolve_ports(_g(h, "DestinationPort", "ANY"), portsets)
        direction = "forward" if _g(h, "Direction", "FORWARD") == "FORWARD" else "any"
        return Rule(
            **base, container=arn, kind="nfw-stateful", direction=direction,
            action=str(_g(r, "Action", "")).lower(), proto=normalize_proto(h.get("Protocol")),
            src_nets=src, dst_nets=dst, src_ports=sp, dst_ports=dp,
            raw=f"stateful[{idx}] {r.get('Action')} {h.get('Protocol')} {h.get('Source')}:{h.get('SourcePort')} "
                f"{'->' if direction == 'forward' else '<>'} {h.get('Destination')}:{h.get('DestinationPort')}",
            unresolved=u1 + u2 + u3 + u4, src_pls=sp_pls, dst_pls=dp_pls,
        )

    _SURICATA_RE = re.compile(
        r"^\s*(?P<action>pass|drop|alert|reject)\s+(?P<proto>\S+)\s+(?P<src>\S+|\[[^\]]*\])\s+"
        r"(?P<sport>\S+|\[[^\]]*\])\s+(?P<dir>->|<>)\s+(?P<dst>\S+|\[[^\]]*\])\s+(?P<dport>\S+|\[[^\]]*\])",
        re.IGNORECASE,
    )

    def _nfw_suricata(self, rules_string: str, arn: str, base: dict, ipsets, portsets,
                      pl_vars: dict | None = None) -> Iterator[Rule]:
        """Parse the header of each Suricata rule in a RulesString into a Rule; unparseable lines are skipped."""
        for lineno, line in enumerate(rules_string.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = self._SURICATA_RE.match(s)
            if not m:
                log.debug("%s line %d: unparsed Suricata rule: %s", arn, lineno, s[:80])
                continue
            src, u1, sp_pls = self._resolve_addr(m["src"], ipsets, pl_vars)
            dst, u2, dp_pls = self._resolve_addr(m["dst"], ipsets, pl_vars)
            sp, u3 = self._resolve_ports(m["sport"], portsets)
            dp, u4 = self._resolve_ports(m["dport"], portsets)
            yield Rule(
                **base, container=arn, kind="nfw-stateful",
                direction="forward" if m["dir"] == "->" else "any",
                action=m["action"].lower(), proto=normalize_proto(m["proto"]),
                src_nets=src, dst_nets=dst, src_ports=sp, dst_ports=dp,
                raw=f"suricata L{lineno}: {s[:160]}",
                unresolved=u1 + u2 + u3 + u4, src_pls=sp_pls, dst_pls=dp_pls,
            )

    # -- network ACL -------------------------------------------------------- #
    def _nacl_rule(self, e: dict, idx: int, container: str, base: dict) -> Rule:
        """Convert one NACL entry from the policy's networkAclEntrySet into a Rule."""
        egress = bool(e.get("egress", False))
        proto = normalize_proto(_g(e, "protocol", "-1"))
        pr = e.get("portRange")
        ports = [(pr["from"], pr["to"])] if pr and proto in ("tcp", "udp") else None
        cidr = e.get("cidrBlock") or e.get("ipv6CidrBlock") or ""
        n = safe_net(cidr) if cidr else None
        nets = [n] if n else []
        return Rule(
            **base, container=container, container_name=container, kind="nacl",
            direction="egress" if egress else "ingress",
            action=str(_g(e, "ruleAction", "")).lower(), proto=proto,
            src_nets=None if egress else nets, dst_nets=nets if egress else None,
            src_ports=None, dst_ports=ports,
            raw=f"entry[{idx}] {'egress' if egress else 'ingress'} {e.get('ruleAction')} {proto} "
                f"{fmt_ports(ports[0]) if ports else 'any'} {cidr or 'any'}",
            unresolved=[] if (n or not cidr) else [cidr],
        )


# --------------------------------------------------------------------------- #
# Target sets
# --------------------------------------------------------------------------- #
@dataclass
class TargetSet:
    """A group of targets. A-side always 'any'; B-side 'any' or 'all'."""
    side: str                 # 'A' or 'B'
    targets: list[Target]
    mode: str = "any"         # any | all

    def hits(self, r: Rule) -> dict[str, list[str]]:
        """{target.label: roles} for every member target that matches the rule."""
        out = {}
        for t in self.targets:
            roles = r.matches(t)
            if roles:
                out[t.label] = roles
        return out

    def roles(self, r: Rule) -> list[str]:
        """Union of roles over all member targets (A-side semantics: match any)."""
        seen: list[str] = []
        for roles in self.hits(r).values():
            for role in roles:
                if role not in seen:
                    seen.append(role)
        return seen

    def __str__(self) -> str:
        """Targets with their labels, plus the match mode when there are several."""
        items = "; ".join(f"{t.label}={t}" for t in self.targets)
        suffix = f" (match {self.mode})" if len(self.targets) > 1 else ""
        return items + suffix


# --------------------------------------------------------------------------- #
# Parity analysis
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A parity gap: a rule matching A in some role with no same-shape B counterpart in scope."""
    rule: Rule
    roles_a: list[str]
    a_hits: dict[str, list[str]]       # which A targets matched, with roles
    missing_b: dict[str, list[str]]    # role -> B labels with no counterpart
    reason: str

    def to_dict(self) -> dict:
        """JSON-friendly dict of the finding."""
        return {"rule": self.rule.to_dict(), "roles_a": self.roles_a, "a_hits": self.a_hits,
                "missing_b": self.missing_b, "reason": self.reason}


def analyze(rules: list[Rule], A: TargetSet, B: TargetSet, scope: str) -> tuple[list[Finding], dict]:
    """
    For every rule matching any A target (in some role), look in the same scope
    for same-shape rules matching each B target in that role. B is satisfied per
    role when any (B.mode='any') or every (B.mode='all') B target has one.
    """
    def scope_key(r: Rule) -> tuple:
        """Where a B counterpart must live: the same container, or anywhere in the same policy."""
        if scope == "policy":
            return (r.region, r.policy_id)
        return (r.region, r.policy_id, r.container)

    # scope -> set of (shape..., role, b_label)
    b_index: dict[tuple, set[tuple]] = {}
    a_hits = b_hits = 0
    for r in rules:
        hb = B.hits(r)
        if hb:
            b_hits += 1
            for label, roles in hb.items():
                for role in roles:
                    b_index.setdefault(scope_key(r), set()).add(r.shape_key() + (role, label))

    findings: list[Finding] = []
    for r in rules:
        ha = A.hits(r)
        if not ha:
            continue
        a_hits += 1
        ra = A.roles(r)
        have = b_index.get(scope_key(r), set())
        missing: dict[str, list[str]] = {}
        for role in ra:
            present = [t.label for t in B.targets if (r.shape_key() + (role, t.label)) in have]
            ok = bool(present) if B.mode == "any" else len(present) == len(B.targets)
            if not ok:
                missing[role] = [t.label for t in B.targets if t.label not in present]
        if missing:
            parts = [f"{role}: missing {','.join(labels)}" for role, labels in missing.items()]
            findings.append(Finding(
                rule=r, roles_a=ra, a_hits=ha, missing_b=missing,
                reason=f"A matched ({', '.join(f'{k} as {'/'.join(v)}' for k, v in ha.items())}); "
                       f"no {r.kind} {r.direction} {r.action} {r.proto} rule in same {scope} for "
                       f"{'; '.join(parts)} (B mode={B.mode})",
            ))
    stats = {"rules_total": len(rules), "a_matches": a_hits, "b_matches": b_hits,
             "a_without_b": len(findings), "b_mode": B.mode,
             "a_targets": len(A.targets), "b_targets": len(B.targets)}
    return findings, stats


CSV_COLUMNS = [
    "gap", "matches_a", "a_targets", "matches_b", "b_targets", "region", "policy_name", "policy_id",
    "policy_type", "container", "container_name", "kind", "direction", "action", "proto",
    "src_nets", "dst_nets", "src_ports", "dst_ports", "src_pls", "dst_pls", "raw", "reason", "unresolved",
]


def _fmt_hits(h: dict[str, list[str]]) -> str:
    """Render target hits as 'A1:src;A2:src/dst' for CSV cells."""
    return ";".join(f"{k}:{'/'.join(v)}" for k, v in h.items())


def build_rows(rules: list[Rule], findings: list[Finding], A: TargetSet, B: TargetSet,
               include_all: bool) -> list[dict]:
    """One row per rule. Gaps always included; with include_all, every rule matching A or B."""
    reason_by_rule = {id(f.rule): f.reason for f in findings}
    rows: list[dict] = []
    for r in rules:
        ha, hb = A.hits(r), B.hits(r)
        gap = id(r) in reason_by_rule
        if not gap and not (include_all and (ha or hb)):
            continue
        d = r.to_dict()
        rows.append({
            "gap": gap,
            "matches_a": "/".join(A.roles(r)), "a_targets": _fmt_hits(ha),
            "matches_b": "/".join(B.roles(r)), "b_targets": _fmt_hits(hb),
            "region": d["region"], "policy_name": d["policy_name"], "policy_id": d["policy_id"],
            "policy_type": d["policy_type"], "container": d["container"],
            "container_name": d["container_name"], "kind": d["kind"],
            "direction": d["direction"], "action": d["action"], "proto": d["proto"],
            "src_nets": "any" if d["src_nets"] is None else ";".join(d["src_nets"]),
            "dst_nets": "any" if d["dst_nets"] is None else ";".join(d["dst_nets"]),
            "src_ports": "any" if d["src_ports"] is None else ";".join(d["src_ports"]),
            "dst_ports": "any" if d["dst_ports"] is None else ";".join(d["dst_ports"]),
            "src_pls": ";".join(d["src_pls"]), "dst_pls": ";".join(d["dst_pls"]),
            "raw": d["raw"], "reason": reason_by_rule.get(id(r), ""),
            "unresolved": ";".join(d["unresolved"]),
        })
    return rows


def build_json(rules: list[Rule], findings: list[Finding], stats: dict, A: TargetSet, B: TargetSet,
               scope: str, include_all: bool, regions: list[str]) -> dict:
    """Assemble the JSON report: targets, settings, stats, findings, per-container compliance
    (and every A/B-matching rule with --show-all).
    """
    out = {
        "targets_a": [{"label": t.label, "target": str(t)} for t in A.targets],
        "targets_b": [{"label": t.label, "target": str(t)} for t in B.targets],
        "b_mode": B.mode, "scope": scope, "regions": regions, "stats": stats,
        "findings": [f.to_dict() for f in findings],
        "containers": build_container_report(rules, findings, A, B),
    }
    if include_all:
        out["matching_rules"] = [
            {"a_hits": A.hits(r), "b_hits": B.hits(r), **r.to_dict()}
            for r in rules if A.hits(r) or B.hits(r)
        ]
    return out


def write_csv(path: str, rows: list[dict]) -> None:
    """Write the rule-level gaps CSV (`build_rows` output)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    log.info("Wrote %d rows to %s", len(rows), path)


def write_json(path: str, payload: dict) -> None:
    """Write the JSON report."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    log.info("Wrote JSON to %s", path)


REPORT_COLUMNS = ["status", "region", "container_type", "container", "container_name",
                  "policies", "rules_total", "rules_matching_a", "rules_matching_b",
                  "a_targets_seen", "b_targets_seen", "gaps", "gap_rules"]


def build_container_report(rules: list[Rule], findings: list[Finding], A: TargetSet, B: TargetSet) -> list[dict]:
    """
    One row per (region, container). Status:
      NON_COMPLIANT  - at least one rule matches an A target with no B counterpart
      COMPLIANT      - A present and every A rule has its B counterpart(s)
      NOT_APPLICABLE - no A target present in this container
    """
    gap_ids = {id(f.rule) for f in findings}
    agg: dict[tuple, dict] = {}
    for r in rules:
        key = (r.region, r.container)
        row = agg.setdefault(key, {
            "region": r.region, "container": r.container, "container_name": r.container_name,
            "container_type": r.kind.split("-")[0].upper(),
            "policies": set(), "rules_total": 0, "rules_matching_a": 0, "rules_matching_b": 0,
            "a_targets_seen": set(), "b_targets_seen": set(), "gaps": 0, "gap_rules": [],
        })
        row["policies"].add(r.policy_name)
        row["rules_total"] += 1
        ha, hb = A.hits(r), B.hits(r)
        if ha:
            row["rules_matching_a"] += 1
            row["a_targets_seen"].update(ha)
        if hb:
            row["rules_matching_b"] += 1
            row["b_targets_seen"].update(hb)
        if id(r) in gap_ids and r.raw not in row["gap_rules"]:
            row["gaps"] += 1
            row["gap_rules"].append(r.raw)
    out = []
    for row in agg.values():
        if row["gaps"]:
            row["status"] = "NON_COMPLIANT"
        elif row["rules_matching_a"]:
            row["status"] = "COMPLIANT"
        else:
            row["status"] = "NOT_APPLICABLE"
        row["policies"] = sorted(row["policies"])
        row["a_targets_seen"] = sorted(row["a_targets_seen"])
        row["b_targets_seen"] = sorted(row["b_targets_seen"])
        out.append(row)
    order = {"NON_COMPLIANT": 0, "COMPLIANT": 1, "NOT_APPLICABLE": 2}
    out.sort(key=lambda r: (order[r["status"]], r["container_type"], r["region"], r["container"]))
    return out


def write_report_csv(path: str, report: list[dict]) -> None:
    """Write the per-container compliance CSV (list cells joined with ';' / ' | ')."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REPORT_COLUMNS)
        w.writeheader()
        for row in report:
            w.writerow({**row, "policies": ";".join(row["policies"]),
                        "a_targets_seen": ";".join(row["a_targets_seen"]),
                        "b_targets_seen": ";".join(row["b_targets_seen"]),
                        "gap_rules": " | ".join(row["gap_rules"])})
    log.info("Wrote %d container rows to %s", len(report), path)


def print_container_report(report: list[dict], sg_only: bool) -> None:
    """Print the compliance table (security groups only unless `sg_only` is False)."""
    rows = [r for r in report if r["container_type"] == "SG"] if sg_only else report
    label = "security group" if sg_only else "container"
    counts = {s: sum(1 for r in rows if r["status"] == s)
              for s in ("NON_COMPLIANT", "COMPLIANT", "NOT_APPLICABLE")}
    print(f"=== Compliance by {label} ===")
    print(f"NON_COMPLIANT: {counts['NON_COMPLIANT']}   COMPLIANT: {counts['COMPLIANT']}   "
          f"NOT_APPLICABLE: {counts['NOT_APPLICABLE']}")
    if not rows:
        return
    w_id = max(len(r["container"]) for r in rows)
    w_name = min(40, max(len(r["container_name"]) for r in rows))
    print(f"{'STATUS':<15} {'REGION':<14} {'TYPE':<5} {'ID':<{w_id}} {'NAME':<{w_name}} "
          f"A  B  GAPS  A-SEEN          B-SEEN          POLICIES")
    for r in rows:
        print(f"{r['status']:<15} {r['region']:<14} {r['container_type']:<5} {r['container']:<{w_id}} "
              f"{r['container_name'][:w_name]:<{w_name}} {r['rules_matching_a']:<2} {r['rules_matching_b']:<2} "
              f"{r['gaps']:<5} {','.join(r['a_targets_seen']):<15} {','.join(r['b_targets_seen']):<15} "
              f"{'; '.join(r['policies'])}")
    print()


def render_html(rules: list[Rule], findings: list[Finding], stats: dict, A: TargetSet, B: TargetSet,
                scope: str, regions: list[str], report: list[dict]) -> str:
    """Build the interactive HTML report: run totals, compliance by container, and every rule
    matching A or B with gaps marked. Non-applicable containers and non-gap rules start hidden.
    """
    status = [r["status"] for r in report]
    cards = [(len(regions), "regions"), (len({r.policy_id for r in rules}), "policies"),
             (stats["rules_total"], "rules inspected"), (stats["a_matches"], "A matches"),
             (stats["b_matches"], "B matches"), (stats["a_without_b"], "A without B"),
             (status.count("NON_COMPLIANT"), "non-compliant containers"),
             (status.count("COMPLIANT"), "compliant containers")]
    meta = [f"Targets A: {A}", f"Targets B: {B}",
            f"Scope: {scope} · regions: {', '.join(regions)} · generated {dt.datetime.now():%Y-%m-%d %H:%M:%S}"]
    containers = {
        "id": "containers", "title": "Compliance by container", "row_label": "containers",
        "note": "NON_COMPLIANT: a rule matches A with no B counterpart. COMPLIANT: A present and every A rule has "
                "its B counterpart. NOT_APPLICABLE: no A target in this container.",
        "columns": [["status", "Status"], ["region", "Region"], ["container_type", "Type"],
                    ["container", "Container"], ["container_name", "Name"], ["policies", "Policies"],
                    ["rules_total", "Rules"], ["rules_matching_a", "A rules"], ["rules_matching_b", "B rules"],
                    ["gaps", "Gaps"], ["a_targets_seen", "A seen"], ["b_targets_seen", "B seen"],
                    ["gap_rules", "Gap rules"]],
        "rows": report,
        "filters": ["status", "region", "container_type", "policies"],
        "uniq": [["region", "Regions"], ["policies", "Policies"], ["container_type", "Types"]],
        "wrap": ["policies", "gap_rules"],
        "badges": {"status": {"NON_COMPLIANT": "error", "COMPLIANT": "ok", "NOT_APPLICABLE": "info"}},
        "order": {"status": ["NON_COMPLIANT", "COMPLIANT", "NOT_APPLICABLE"]},
        "sort": [["status", 1], ["container_type", 1], ["region", 1]],
        "hide": {"key": "status", "values": ["NOT_APPLICABLE"], "label": "show not applicable"},
        "by": {"key": "container_type", "label": "By container type", "badge": None},
    }
    rows = [{**r, "gap": "GAP" if r["gap"] else "ok"} for r in build_rows(rules, findings, A, B, include_all=True)]
    rule_table = {
        "id": "rules", "title": "Rules matching A or B", "row_label": "rules",
        "note": "GAP rows match an A target with no B counterpart in the same " + scope + ".",
        "columns": [["gap", "Gap"], ["matches_a", "A role"], ["a_targets", "A targets"], ["matches_b", "B role"],
                    ["b_targets", "B targets"], ["region", "Region"], ["policy_name", "Policy"],
                    ["policy_type", "Policy type"], ["container", "Container"], ["container_name", "Name"],
                    ["kind", "Kind"], ["direction", "Direction"], ["action", "Action"], ["proto", "Proto"],
                    ["src_nets", "Source"], ["dst_nets", "Destination"], ["src_ports", "Src ports"],
                    ["dst_ports", "Dst ports"], ["raw", "Rule"], ["reason", "Reason"],
                    ["unresolved", "Unresolved"]],
        "rows": rows,
        "filters": ["gap", "region", "policy_name", "policy_type", "container", "kind", "direction", "action",
                    "proto"],
        "uniq": [["region", "Regions"], ["policy_name", "Policies"], ["container", "Containers"]],
        "wrap": ["src_nets", "dst_nets", "raw", "reason", "unresolved"],
        "badges": {"gap": {"GAP": "error", "ok": "ok"}},
        "order": {"gap": ["GAP", "ok"]},
        "sort": [["gap", 1], ["region", 1], ["policy_name", 1], ["container", 1]],
        "hide": {"key": "gap", "values": ["ok"], "label": "show rules without a gap"},
        "by": {"key": "policy_name", "label": "By policy", "badge": None},
    }
    return html_report.render("FMS rule parity report", meta=meta, cards=cards, tables=[containers, rule_table])


def _slug(ts: TargetSet) -> str:
    """Filename-safe summary of a target set, shortened with a hash when long."""
    parts = []
    for t in ts.targets:
        port = "any" if t.ports is None else fmt_ports(t.ports)
        parts.append(re.sub(r"[^A-Za-z0-9._-]+", "_", f"{t.source}_{t.proto}_{port}"))
    slug = "+".join(parts)
    if len(slug) > 60:
        import hashlib
        slug = slug[:48] + "_" + hashlib.sha1(slug.encode()).hexdigest()[:8]
    return slug


def default_report_paths(out_dir: str, A: TargetSet, B: TargetSet, now: dt.datetime | None = None) -> dict[str, Path]:
    """./reports/fmm_rule_parity/YYYY-MM-DD/HHMMSS_parity_<A>_vs_<B>.{html,compliance.csv,gaps.csv,json}"""
    now = now or dt.datetime.now()
    day_dir = Path(out_dir) / "fmm_rule_parity" / now.strftime("%Y-%m-%d")
    stem = f"{now.strftime('%H%M%S')}_parity_{_slug(A)}_vs_{_slug(B)}"
    return {
        "report": day_dir / f"{stem}.compliance.csv",
        "csv": day_dir / f"{stem}.gaps.csv",
        "json": day_dir / f"{stem}.json",
        "html": day_dir / f"{stem}.html",
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
_FILLER_TOKENS = {"port", "ports", "proto", "protocol", "on", "over", "via"}


def split_target_tokens(tokens: list[str]) -> tuple[str, str, str]:
    """
    Normalize user input into (ip, proto, port). Accepts:
      10.0.0.1 tcp 8080 | "10.0.0.1 tcp 8080" | 10.0.0.1,tcp,8080 | 10.0.0.1 tcp port 8080
      10.0.0.1 tcp (port defaults to any) | 10.0.0.1 (proto and port default to any)
    """
    parts: list[str] = []
    for t in tokens:
        parts.extend(x for x in re.split(r"[\s,]+", t.strip()) if x)
    parts = [x for x in parts if x.lower() not in _FILLER_TOKENS]
    if len(parts) == 1:
        parts += ["any", "any"]
    elif len(parts) == 2:
        parts.append("any")
    if len(parts) != 3:
        raise ValueError(f"expected 'IP PROTO PORT', got {' '.join(tokens)!r}")
    return parts[0], parts[1], parts[2]


def parse_targets(side: str, specs: list[list[str]], mode: str, resolve_pl, pl_match: str) -> TargetSet:
    """Parse the -a or -b arguments into a labelled TargetSet (A1, A2, ... when several)."""
    targets = []
    for i, tokens in enumerate(specs, 1):
        label = f"{side}{i}" if len(specs) > 1 else side
        targets.append(Target.parse(label, *split_target_tokens(tokens),
                                    resolve_pl=resolve_pl, pl_match=pl_match))
    return TargetSet(side=side, targets=targets, mode=mode)


def collect_rules(profile: str | None, regions: Iterable[str], policy_filter: str | None) -> list[Rule]:
    """Read every supported FMS policy in the given regions and return all of their rules.

    List/get failures are logged and that region or policy is skipped.
    """
    rules: list[Rule] = []
    for region in regions:
        log.info("Region %s: listing Firewall Manager policies", region)
        session = get_session(profile, region)
        ex = Extractor(session, region)
        try:
            summaries = list(list_policies(ex.fms))
        except ClientError as e:
            log.error("Region %s: list_policies failed: %s %s", region,
                      e.response["Error"]["Code"], e.response["Error"]["Message"])
            continue
        log.info("Region %s: %d policies", region, len(summaries))
        for s in summaries:
            if policy_filter and policy_filter not in (s["PolicyId"], s["PolicyName"]):
                continue
            if s.get("SecurityServiceType") not in SUPPORTED_POLICY_TYPES:
                log.debug("Skipping %s (%s)", s["PolicyName"], s.get("SecurityServiceType"))
                continue
            try:
                pol = get_policy(ex.fms, s["PolicyId"])
            except ClientError as e:
                log.error("get_policy %s failed: %s", s["PolicyId"], e.response["Error"]["Code"])
                continue
            n_before = len(rules)
            rules.extend(ex.rules_for_policy(pol))
            log.info("  %s [%s]: %d rules", pol["PolicyName"], s.get("SecurityServiceType"),
                     len(rules) - n_before)
    return rules


def print_report(findings: list[Finding], stats: dict, A: TargetSet, B: TargetSet,
                 rules: list[Rule], show_all: bool, regions: list[str]) -> None:
    """Print the text report: run summary, optional A/B matches, then each gap grouped by
    region / policy / container with its reason.
    """
    print()
    print(f"Regions:   {', '.join(regions)}")
    print(f"Targets A: {A}")
    print(f"Targets B: {B}")
    print(f"Rules inspected: {stats['rules_total']}   A matches: {stats['a_matches']}   "
          f"B matches: {stats['b_matches']}   A without B: {stats['a_without_b']}")
    print()
    if show_all:
        print("=== All rules matching any A or B target ===")
        for r in rules:
            ha, hb = A.hits(r), B.hits(r)
            if ha or hb:
                print(f"[{','.join(ha) or '-':<8}|{','.join(hb) or '-':<8}] {r.region} {r.policy_name} "
                      f"| {r.container} | {r.raw}")
        print()
    if not findings:
        print("No parity gaps: every rule matching an A target has its B counterpart(s).")
        return
    print("=== A present, B missing ===")
    cur = None
    for f in findings:
        r = f.rule
        hdr = (r.region, r.policy_name, r.policy_type, r.container)
        if hdr != cur:
            cur = hdr
            print(f"\n{r.region}  policy={r.policy_name} ({r.policy_type})\n  container={r.container}")
        print(f"    - {r.raw}")
        print(f"      {f.reason}")
        if r.unresolved:
            print(f"      unresolved refs (not evaluated): {', '.join(r.unresolved)}")


def main() -> int:
    """Command-line entry point. Returns the exit code: 0 no gaps, 1 gaps, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Find AWS Firewall Manager rules where any A target is present but B target(s) are missing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Each target is:  IP[/prefix] PROTO PORT   or   pl-xxxx PROTO PORT
  IP:    CIDR, or a managed prefix list id / ARN (matched by reference; see --pl-match)
  PROTO: tcp | udp | icmp | any | <number>
  PORT:  single (8080), range (8000-8100), or any

-a and -b are repeatable. A rule is "A-present" if ANY -a target matches it.
B is satisfied when ANY -b target has a counterpart (default) or ALL do (--b-match all).

Example:
  %(prog)s --profile fms-admin --region ca-central-1,us-east-1 \\
      -a 10.0.0.1 tcp 8080 -a 10.0.0.2 tcp 8080 \\
      -b pl-0123abcd tcp 8080 -b pl-0456ef01 tcp 8080 --b-match all
""")
    p.add_argument("--target-a", "-a", nargs="+", action="append", metavar="IP PROTO PORT", required=True,
                   help="Target that must be present (repeatable; any may match)")
    p.add_argument("--target-b", "-b", nargs="+", action="append", metavar="IP PROTO PORT", required=True,
                   help="Target expected alongside A (repeatable; see --b-match)")
    p.add_argument("--b-match", choices=["any", "all"], default="any",
                   help="With several -b targets: parity needs any one (default) or all of them")
    p.add_argument("--pl-match", choices=["ref", "cidrs-all", "cidrs-any"], default="ref",
                   help="When a target is a prefix list id: 'ref' (default) matches rules that reference "
                        "that prefix list; 'cidrs-all'/'cidrs-any' expand it and match rules whose CIDRs "
                        "cover all/any of its entries")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile name")
    p.add_argument("--region", action="append",
                   help="Region(s) to scan: repeatable and/or comma-separated. Default: AWS_REGION or us-east-1")
    p.add_argument("--all-regions", action="store_true",
                   help="Scan every enabled region that offers Firewall Manager")
    p.add_argument("--policy", help="Restrict to a single policy ID or name")
    p.add_argument("--scope", choices=["container", "policy"], default="container",
                   help="Where a B counterpart must exist: same SG/rule group/NACL list "
                        "(container, default) or anywhere in same policy")
    p.add_argument("--show-all", action="store_true", help="Also list every rule matching any A or B target")
    p.add_argument("--json", action="store_true", help="Emit JSON to stdout instead of text report")
    p.add_argument("--out-dir", default=os.getenv("FMM_REPORT_DIR", "./reports"),
                   help="Base directory for auto-saved reports, organised as <out-dir>/fmm_rule_parity/YYYY-MM-DD/ "
                        "(default: ./reports, env FMM_REPORT_DIR)")
    p.add_argument("--no-save", action="store_true", help="Do not auto-save reports to --out-dir")
    p.add_argument("--json-out", metavar="PATH", help="Write JSON report to file (overrides auto path)")
    p.add_argument("--html-out", metavar="PATH", help="Write HTML report to file (overrides auto path)")
    p.add_argument("--report-out", metavar="PATH",
                   help="Write per-container compliance CSV (overrides auto path)")
    p.add_argument("--all-containers", action="store_true",
                   help="Compliance table lists rule groups and NACL lists too (default: SGs only)")
    p.add_argument("--csv-out", metavar="PATH",
                   help="Write rule-level CSV: one row per gap (plus every A/B match with --show-all); "
                        "overrides auto path")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        regions = resolve_regions(args.profile, args.region, args.all_regions)
    except ClientError as e:
        log.error("Could not enumerate regions: %s %s", e.response["Error"]["Code"],
                  e.response["Error"]["Message"])
        return 2

    extractors: dict[str, Extractor] = {}

    def resolve_pl(pl_id: str):
        """Prefix lists are regional: look in every scanned region, union the CIDRs."""
        nets: list[IPNet] = []
        found = False
        for region in regions:
            ex = extractors.setdefault(region, Extractor(get_session(args.profile, region), region))
            got = ex._prefix_list_nets(pl_id)
            if got is not None:
                found = True
                nets.extend(n for n in got if n not in nets)
        return nets if found else None

    try:
        A = parse_targets("A", args.target_a, "any", resolve_pl, args.pl_match)
        B = parse_targets("B", args.target_b, args.b_match, resolve_pl, args.pl_match)
    except ValueError as e:
        p.error(f"bad target: {e}")

    log.debug("Using profile=%s regions=%s", args.profile or "default", regions)
    log.info("Targets A: %s | Targets B: %s | scope=%s", A, B, args.scope)

    rules = collect_rules(args.profile, regions, args.policy)
    findings, stats = analyze(rules, A, B, args.scope)

    payload = build_json(rules, findings, stats, A, B, args.scope, args.show_all, regions)
    report = payload["containers"]

    auto = {} if args.no_save else default_report_paths(args.out_dir, A, B)
    json_path = args.json_out or auto.get("json")
    csv_path = args.csv_out or auto.get("csv")
    report_path = args.report_out or auto.get("report")
    html_path = args.html_out or auto.get("html")
    for path in (json_path, csv_path, report_path, html_path):
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    if json_path:
        write_json(str(json_path), payload)
    if csv_path:
        write_csv(str(csv_path), build_rows(rules, findings, A, B, args.show_all))
    if report_path:
        write_report_csv(str(report_path), report)
    if html_path:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(rules, findings, stats, A, B, args.scope, regions, report))
        log.info("Wrote HTML to %s", html_path)

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print_report(findings, stats, A, B, rules, args.show_all, regions)
        print()
        print_container_report(report, sg_only=not args.all_containers)
        saved = [str(x) for x in (html_path, report_path, csv_path, json_path) if x]
        if saved:
            print("Saved:")
            for x in saved:
                print(f"  {x}")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
