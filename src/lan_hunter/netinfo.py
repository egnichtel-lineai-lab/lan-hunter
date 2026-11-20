"""Local network interface / subnet detection."""
from __future__ import annotations

import ipaddress
import json
import subprocess

# Interface name prefixes that are virtual/container/VPN and should not be
# treated as physical LAN segments by default.
VIRTUAL_PREFIXES = (
    "docker", "br-", "veth", "virbr", "lxd", "br-ovs", "ovs", "kube",
    "flannel", "cali", "cni", "tap", "tun", "wg", "zt", "dummy", "ifb",
    "usb", "wwan", "p2p", "ap", "lo",
)


def ip_json(args: list[str]) -> list[dict]:
    proc = subprocess.run(
        ["ip", "-j"] + args, capture_output=True, text=True, timeout=15
    )
    if proc.returncode != 0:
        return []
    try:
        return json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []


def interfaces() -> list[dict]:
    return ip_json(["addr"])


def is_virtual(name: str) -> bool:
    return name == "lo" or any(name.startswith(p) for p in VIRTUAL_PREFIXES)


def lan_subnets() -> dict[str, str]:
    """Detect directly-connected IPv4 subnets on physical interfaces.

    Returns {network_str: interface_name}.
    """
    found: dict[str, str] = {}
    for iface in interfaces():
        name = iface.get("ifname", "")
        if is_virtual(name):
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            ip, plen = a.get("local"), a.get("prefixlen")
            if not ip or plen is None:
                continue
            try:
                net = ipaddress.ip_interface(f"{ip}/{plen}").network
            except ValueError:
                continue
            if net.version != 4 or net.prefixlen > 28 or net.prefixlen < 8:
                continue
            found.setdefault(str(net), name)
    return found


def local_ips() -> set[str]:
    ips = set()
    for iface in interfaces():
        for a in iface.get("addr_info", []):
            if a.get("family") in ("inet", "inet6") and a.get("local"):
                ips.add(a["local"])
    return ips


def default_gateway() -> str | None:
    routes = ip_json(["route"])
    for r in routes:
        if r.get("dst") == "default" and r.get("gateway"):
            return r["gateway"]
    return None


def expand_target(target: str) -> list[str]:
    """Validate/normalize a scan target (CIDR, IP, or range)."""
    target = target.strip()
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            if net.version != 4:
                raise ValueError("only IPv4 supported")
            if net.prefixlen > 24:
                # small subnets fine; anything <= /24 allowed
                pass
            if net.num_addresses > 2 ** 16:
                raise ValueError(f"target {target} too large (>{2**16} hosts)")
            return [str(net)]
        ipaddress.ip_address(target)
        return [target]
    except ValueError as exc:
        raise ValueError(f"invalid target {target!r}: {exc}") from exc
