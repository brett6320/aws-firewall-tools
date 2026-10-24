"""
Access "boxes": exact set arithmetic over protocol x port x address ranges.

Intent: compare firewall rules by the traffic they match rather than by how
they are written. A rule becomes one or more boxes (protocol range, port or
ICMP range, address range); unions, differences and overlaps of boxes then
answer questions like "what does rule A allow that rules B, C do not" or
"is this rule fully hidden by earlier rules", down to exact CIDRs and ports.

Used by sg_access_gap.py, sg_rule_inventory.py and sg_migration_check.py (security groups) and nacl_shadow.py
(NACL entries). sg_rule_inventory's HTML tester mirrors subtract() in JavaScript.

Encoding:
  * protocol: IP protocol number 0-255; all traffic is (0, 255)
  * ports: TCP/UDP port range; for ICMP/ICMPv6 the value is type*256+code, so
    "type 8, any code" is the contiguous range (2048, 2303); other protocols
    span every port
  * address: integer range of an IPv4 or IPv6 network. Boxes from different
    address spaces ("ipv4", "ipv6", or an opaque id like "sg:sg-123") must be
    kept apart by the caller.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict

PROTO_NUMS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
PROTO_NAMES = {v: k for k, v in PROTO_NUMS.items()}
ALL_PROTOS = (0, 255)
ALL_PORTS = (0, 65535)

Interval = tuple[int, int]
Box = tuple[Interval, Interval, Interval]   # protocol, port (or ICMP type*256+code), address


def intersects(a: Box, b: Box) -> bool:
    """True when two boxes overlap in every dimension."""
    return all(x[0] <= y[1] and y[0] <= x[1] for x, y in zip(a, b))


def subtract(a: Box, b: Box) -> list[Box]:
    """a minus b, as disjoint boxes."""
    if not intersects(a, b):
        return [a]
    out, cur = [], list(a)
    for d in range(len(a)):
        lo, hi = cur[d]
        blo, bhi = b[d]
        if lo < blo:
            out.append(tuple(cur[:d] + [(lo, blo - 1)] + cur[d + 1:]))
            lo = blo
        if hi > bhi:
            out.append(tuple(cur[:d] + [(bhi + 1, hi)] + cur[d + 1:]))
            hi = bhi
        cur[d] = (lo, hi)
    return out


def merge(boxes) -> list[Box]:
    """Coalesce boxes that differ in one dimension only and touch or overlap there."""
    boxes = set(boxes)
    changed = True
    while changed:
        changed = False
        for d in range(3):
            groups = defaultdict(list)
            for b in boxes:
                groups[b[:d] + b[d + 1:]].append(b[d])
            merged_set = set()
            for rest, ivs in groups.items():
                ivs.sort()
                merged = [ivs[0]]
                for lo, hi in ivs[1:]:
                    if lo <= merged[-1][1] + 1:
                        merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
                    else:
                        merged.append((lo, hi))
                changed |= len(merged) < len(ivs)
                merged_set.update(rest[:d] + (iv,) + rest[d:] for iv in merged)
            boxes = merged_set
    return sorted(boxes)


def remainder(box: Box, others: list[Box]) -> list[Box]:
    """The part of `box` not covered by any of `others`, as disjoint boxes."""
    pieces = [box]
    for o in others:
        pieces = [q for p in pieces for q in subtract(p, o)]
        if not pieces:
            break
    return pieces


def proto_num(p) -> int | None:
    """None = all protocols."""
    s = str(p).strip().lower()
    if s in ("-1", "all", ""):
        return None
    return PROTO_NUMS[s] if s in PROTO_NUMS else int(s)


def proto_port_box(proto, from_port, to_port) -> tuple[Interval, Interval]:
    """Protocol and port intervals for an SG rule.

    TCP/UDP use port ranges. ICMP type/code is encoded as type*256+code so that 'type 8, any
    code' is a contiguous range. Other protocols, and all-traffic rules, span every port.
    """
    p = proto_num(proto)
    if p is None:
        return ALL_PROTOS, ALL_PORTS
    if p in (6, 17):
        if from_port in (None, -1):
            return (p, p), ALL_PORTS
        return (p, p), (from_port, to_port)
    if p in (1, 58):            # FromPort = ICMP type, ToPort = code, -1 = any
        if from_port in (None, -1):
            return (p, p), ALL_PORTS
        if to_port in (None, -1):
            return (p, p), (from_port * 256, from_port * 256 + 255)
        return (p, p), (from_port * 256 + to_port,) * 2
    return (p, p), ALL_PORTS


def fmt_proto_ports(pr: Interval, ports: Interval) -> str:
    """Render a protocol/port box for people, e.g. 'tcp 443', 'icmp type 8', 'all traffic'."""
    if pr == ALL_PROTOS:
        return "all traffic"
    if pr[0] != pr[1]:
        return f"protocols {pr[0]}-{pr[1]}" + ("" if ports == ALL_PORTS else f" ports {ports[0]}-{ports[1]}")
    p = pr[0]
    name = PROTO_NAMES.get(p, f"proto {p}")
    if ports == ALL_PORTS:
        return f"{name} all" if p in PROTO_NAMES else name
    if p in (1, 58):
        def tc(v):
            """ICMP 'type/code' text for an encoded value."""
            return f"{v // 256}/{v % 256}"
        lo, hi = ports
        if lo % 256 == 0 and hi == lo + 255:
            return f"{name} type {lo // 256}"
        if lo == hi:
            return f"{name} type {lo // 256} code {lo % 256}"
        if lo % 256 == 0 and hi % 256 == 255:
            return f"{name} types {lo // 256}-{hi // 256}"
        return f"{name} type/code {tc(lo)}-{tc(hi)}"
    return f"{name} {ports[0]}" if ports[0] == ports[1] else f"{name} {ports[0]}-{ports[1]}"


def addr_interval(net) -> Interval:
    """A network as an inclusive (first, last) integer address range."""
    return int(net.network_address), int(net.broadcast_address)


def fmt_addrs(space: str, iv: Interval) -> list[str]:
    """Address range back to the fewest CIDRs covering it; group/prefix-list spaces print their id."""
    if space not in ("ipv4", "ipv6"):
        return [space.split(":", 1)[1]]
    cls = ipaddress.IPv4Address if space == "ipv4" else ipaddress.IPv6Address
    return [str(n) for n in ipaddress.summarize_address_range(cls(iv[0]), cls(iv[1]))]
