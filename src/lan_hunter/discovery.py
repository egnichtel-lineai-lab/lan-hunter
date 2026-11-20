"""Host discovery: arp-scan sweeps, kernel ARP table, and avahi mDNS browsing."""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

from .models import Device, MDNSService


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def kernel_arp_table() -> list[tuple[str, str, str]]:
    """Return [(ip, mac, iface)] from the kernel ARP table."""
    rows = []
    try:
        with open("/proc/net/arp") as fh:
            next(fh)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    ip, _hw, _flags, mac, _mask, iface = parts[:6]
                    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                        rows.append((ip, mac.lower(), iface))
    except OSError:
        pass
    return rows


def wake_arp_table(subnets: list[str]) -> None:
    """Populate the kernel ARP table by pinging each subnet's broadcast."""
    for net in subnets:
        try:
            network = ipaddress.ip_network(net)
        except ValueError:
            continue
        bcast = str(network.broadcast_address)
        try:
            _run(["ping", "-c", "3", "-W", "1", bcast], timeout=8)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass


def arp_scan(subnets: list[str], iface: str | None = None) -> list[tuple[str, str, str | None]]:
    """Live hosts via arp-scan. Returns [(ip, mac, vendor_or_None)].

    NOTE: arp-scan's third column is the OUI vendor name resolved from the
    MAC prefix, NOT a hostname. It must never be treated as a hostname.
    """
    results: list[tuple[str, str, str | None]] = []
    if shutil.which("arp-scan") is None:
        return results
    for net in subnets:
        cmd = ["arp-scan", "--retry", "2", "--timeout", "800"]
        if iface:
            cmd += ["--interface", iface]
        cmd.append(net)
        try:
            proc = _run(cmd, timeout=180)
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
        for line in proc.stdout.splitlines():
            m = re.match(
                r"^(\d+\.\d+\.\d+\.\d+)\t+([0-9a-fA-F:]{17})\t+(.*)$", line.strip()
            )
            if m:
                host = m.group(3).split()[0] if m.group(3).strip() else None
                results.append((m.group(1), m.group(2).lower(), host))
    return results


def nmap_ping_scan(targets: list[str], sudo: bool = True) -> str | None:
    """nmap -sn over targets, returns raw XML."""
    cmd = (["sudo"] if sudo else []) + [
        "nmap", "-sn", "-n", "--max-parallelism", "64",
        "--min-parallelism", "10", "-T4", "--stats-every", "10s",
        "-oX", "-",
    ] + targets
    try:
        proc = _run(cmd, timeout=1200)
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    return proc.stdout if "<nmaprun" in (proc.stdout or "") else None


def reverse_dns(ips: list[str], timeout: float = 2.5,
                max_workers: int = 48) -> dict[str, str]:
    """Concurrent PTR (reverse-DNS) lookups via the system resolver.

    Returns {ip: hostname} for addresses that have a PTR record. Uses
    getaddrinfo(AI_CANONNAME)-free gethostbyaddr so it honours /etc/resolv.conf
    and nsswitch (i.e. the same resolver the OS uses, including any mDNS/LLMNR
    NSS plugins). Failures and timeouts are silently skipped.
    """
    out: dict[str, str] = {}
    todo = [ip for ip in dict.fromkeys(ips) if _is_ip(ip)]
    if not todo:
        return out
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        def lookup(ip: str) -> tuple[str, str | None]:
            try:
                name = socket.gethostbyaddr(ip)[0]
                return ip, (name.rstrip(".") or None)
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                return ip, None
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for ip, name in pool.map(lookup, todo):
                if name:
                    out[ip] = name
    finally:
        socket.setdefaulttimeout(old_timeout)
    return out


def _unescape_avahi(s: str) -> str:
    """Decode avahi-browse escapes.

    avahi-browse emits zero-padded 3-digit DECIMAL byte escapes (verified
    empirically: \\032 = space, \\058 = ':', and a UTF-8 smart quote arrives as
    three escapes \\226\\128\\153). Literal dots are escaped as '\\.'.
    Escapes must be turned back into BYTES and the whole string decoded once
    as UTF-8, otherwise each byte decodes in isolation and produces mojibake.
    """
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt.isdigit() and i + 4 <= n and s[i + 2:i + 4].isdigit():
                val = int(s[i + 1:i + 4])
                out.append(val if val <= 255 else ord("?"))
                i += 4
                continue
            out += nxt.encode("utf-8", "surrogatepass")
            i += 2
            continue
        out += s[i].encode("utf-8", "surrogatepass")
        i += 1
    text = out.decode("utf-8", "replace")
    return "".join(c for c in text if c.isprintable() or c == " ").strip()


def avahi_services(seconds: int = 12) -> list[MDNSService]:
    """Browse mDNS/DNS-SD announcements (printers, Chromecasts, HomeKit...).

    Resolved ('=') records need ~10s to appear, so allow enough time.
    The same service is announced on every interface and address family;
    results are deduplicated on (name, type, address, port).
    """
    services: list[MDNSService] = []
    if shutil.which("avahi-browse") is None:
        return services
    try:
        # single string with shell=True: passing a list here would make the
        # shell execute only argv[0] ("timeout") and drop the real command.
        proc = subprocess.run(
            f"timeout {seconds} avahi-browse -a -p -r -t",
            shell=True, capture_output=True, text=True, timeout=seconds + 15,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return services
    seen: set[tuple] = set()
    for line in proc.stdout.splitlines():
        if not line.startswith("="):
            continue  # only resolved records carry address/port
        # avahi-browse resolved format (verified empirically; there is NO
        # flags field): =;iface;proto;name;type;domain;hostname;address;port;txt
        # The leading ';' after '=' yields an empty first field; drop it so
        # parts[0] is the interface.
        parts = line[1:].split(";")[1:]
        if len(parts) < 8:
            continue
        svc = MDNSService(
            name=_unescape_avahi(parts[2]) or None,
            service_type=_unescape_avahi(parts[3]) or None,
        )
        if parts[5]:
            svc.hostname = parts[5].split(".local")[0] or None
        # validate the address really is an IP before trusting it.
        if parts[6] and _is_ip(parts[6]):
            svc.address = parts[6]
        if parts[7].isdigit():
            svc.port = int(parts[7])
        if len(parts) > 8:
            txt = ";".join(parts[8:]).strip()
            svc.txt = _unescape_avahi(txt)[:500] or None
        dedupe = (svc.name, svc.service_type, svc.address, svc.port)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        services.append(svc)
    return services


def attach_mdns(devices: dict[str, Device], mdns_list: list[MDNSService]) -> None:
    """Best-effort attach mDNS records to devices by resolved address or hostname."""
    by_addr: dict[str, list[MDNSService]] = {}
    by_host: dict[str, list[MDNSService]] = {}
    for m in mdns_list:
        if m.address:
            by_addr.setdefault(m.address, []).append(m)
        if m.hostname:
            by_host.setdefault(m.hostname.lower(), []).append(m)
    for dev in devices.values():
        for ip in dev.ip_list:
            for m in by_addr.get(ip, []):
                if m not in dev.mdns:
                    dev.mdns.append(m)
        for host in dev.hostnames:
            for m in by_host.get(host.lower(), []):
                if m not in dev.mdns:
                    dev.mdns.append(m)
