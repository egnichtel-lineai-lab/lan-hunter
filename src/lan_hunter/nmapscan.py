"""nmap wrapper: OS detection + service enumeration with scan profiles."""
from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import Device, OSMatch, Service

# Ports commonly opened by IoT / embedded / OT devices, beyond nmap's top-1000.
IOT_PORTS = [
    21, 23, 2323, 80, 443, 53, 5353, 1900, 161, 162, 502, 102, 47808,
    1883, 8883, 5683, 5684, 554, 8554, 3702, 1900, 9000, 8080, 8081,
    4443, 3000, 5000, 5001, 9200, 11211, 137, 138, 139, 445, 1433,
    3306, 3389, 5432, 5900, 62078, 10000, 20000, 49151, 179, 6667,
]

# NSE scripts that are safe-ish and highly informative for identification.
ID_SCRIPTS = [
    "http-title", "http-server-header", "http-headers", "http-favicon",
    "ssl-cert", "ssl-date", "tls-alpn",
    "ssh2-enum-algos", "ssh-hostkey",
    "upnp-info", "smb-os-discovery", "nbstat",
    "snmp-sysdescr", "snmp-info",
    "modbus-discover", "bacnet-info", "enip-info", "fox-info",
    "x11-access", "realvnc-auth-bypass", "dns-service-discovery",
]

# Conservative script set used by the safe/balanced profiles: read-only
# banner-grabbing scripts only, no stateful or interactive probes.
SAFE_SCRIPTS = [
    "http-title", "http-server-header", "http-headers", "http-favicon",
    "ssl-cert", "ssh-hostkey",
    "upnp-info", "smb-os-discovery",
    "nbstat", "snmp-sysdescr", "modbus-discover", "dns-service-discovery",
]

NSE_SCRIPT_DIR = "/usr/share/nmap/scripts"


def available_scripts(requested: list[str]) -> str:
    """Filter requested NSE scripts against the installed script library.

    nmap aborts entirely if --script names an unknown script, so drop
    anything not present in this nmap's script directory.
    """
    try:
        installed = {f[:-4] for f in os.listdir(NSE_SCRIPT_DIR)
                     if f.endswith(".nse")}
    except OSError:
        installed = set(requested)  # can't verify: pass through
    keep = [s for s in requested if s in installed]
    return ",".join(keep) if keep else "default"


def profile_args(profile: str) -> tuple[list[str], str]:
    """Return (nmap flags, port spec) for a scan profile."""
    ports = ",".join(str(p) for p in sorted(set(IOT_PORTS)))
    if profile == "safe":
        # no --osscan-limit: many IoT hosts show only filtered ports, which
        # the limit would skip entirely, defeating the OS fingerprinting goal.
        return (
            ["-sS", "-sV", "--version-light", "-O",
             "-T2", "--max-rtt-timeout", "800ms", "--max-retries", "1",
             "--host-timeout", "8m",
             "--script", available_scripts(SAFE_SCRIPTS)],
            f"T:{ports}",
        )
    if profile == "balanced":
        return (
            ["-sS", "-sV", "-O", "-T3",
             "--host-timeout", "10m",
             "--script", available_scripts(SAFE_SCRIPTS)],
            f"T:{ports},T:9-49151",
        )
    if profile == "aggressive":
        return (
            ["-sS", "-sU", "-sV", "-O", "-A", "-T4", "--host-timeout", "15m",
             "--script", available_scripts(ID_SCRIPTS)],
            "T:1-65535,U:53,67,137,138,161,162,5353,1900,5683,5684,11211,5060,5061",
        )
    raise ValueError(f"unknown profile {profile!r}")


def nmap_scan(targets: list[str], profile: str = "safe", sudo: bool = True,
              extra_args: list[str] | None = None
              ) -> tuple[str | None, list[str]]:
    """Run nmap; returns (xml_or_None, error_messages)."""
    flags, ports = profile_args(profile)
    # NOTE: no --open here: nmap then omits hosts whose ports are all
    # filtered, losing their OS fingerprints and firewall-state evidence.
    # State filtering happens in parse_nmap_xml instead.
    cmd = (["sudo"] if sudo else []) + [
        "nmap", "-n", "-Pn", "--max-parallelism", "32",
        "--min-parallelism", "5", "--stats-every", "15s",
        "-p", ports, "-oX", "-",
    ] + flags + (extra_args or []) + targets
    errors: list[str] = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        return None, [f"nmap invocation failed: {exc}"]
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        errors.append(f"nmap exited {proc.returncode}: {err[:400]}")
    if "<nmaprun" in (proc.stdout or ""):
        return proc.stdout, errors
    errors.append("nmap produced no XML output")
    return None, errors


def _text(elem: ET.Element | None) -> str | None:
    if elem is None:
        return None
    t = (elem.text or "").strip()
    return t or None


def parse_nmap_xml(xml_text: str) -> tuple[dict[str, Device], list[str]]:
    """Parse nmap XML into {ip: Device}. Returns (devices, warnings)."""
    devices: dict[str, Device] = {}
    warnings: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        warnings.append(f"nmap XML parse error: {exc}")
        return devices, warnings

    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = None
        mac = None
        hostname = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = (addr.get("addr") or "").upper() or None
        for hn in host.findall("hostnames/hostname"):
            if hn.get("name"):
                hostname = hn.get("name")
                break
        if not ip:
            continue

        dev = Device(mac=mac, hostname=hostname, sources={"nmap"})
        dev.add_ip(ip, hostname=hostname)

        # OS matches. nmap XML layout:
        #   <osmatch name="..." accuracy="95" line="107903">
        #     <osclass type="..." vendor="..." osfamily="..." osgen="..."
        #              accuracy="..." cpe="cpe:/o:microsoft:windows..."/>
        for os_el in host.findall("os/osmatch"):
            acc = os_el.get("accuracy")
            name = os_el.get("name")
            osclass = os_el.find("osclass")
            vendor = family = gen = ostype = None
            if osclass is not None:
                vendor = osclass.get("vendor")
                family = osclass.get("osfamily")
                gen = osclass.get("osgen")
                ostype = osclass.get("type")
            dev.os_matches.append(OSMatch(
                vendor=vendor, family=family, generation=gen, type=ostype,
                accuracy=int(acc) if acc else None, line=name,
            ))

        # ports / services
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "open"
            if state not in ("open", "filtered"):
                continue
            svc = Service(
                port=int(port.get("portid")),
                protocol=port.get("protocol", "tcp"),
                state=state,
            )
            svc_el = port.find("service")
            if svc_el is not None:
                svc.name = _text(svc_el.find("name"))
                svc.product = _text(svc_el.find("product"))
                svc.version = _text(svc_el.find("version"))
                svc.extrainfo = _text(svc_el.find("extrainfo"))
                svc.tunnel = _text(svc_el.find("tunnel"))
                svc.method = _text(svc_el.find("method"))
                conf = svc_el.get("conf")
                if conf:
                    svc.method = f"{svc.method or ''}/{conf}%"
            for script in port.findall("script"):
                id_ = script.get("id") or "script"
                # nmap stores script results in the "output" attribute;
                # structured table/elems results live in child elements.
                out = (script.get("output") or "").strip()
                if not out:
                    out = ET.tostring(script, encoding="unicode")[:400]
                svc.scripts[id_] = out
            dev.add_service(svc)

        # hostscript scripts (e.g. smb-os-discovery at host level)
        hs = host.find("hostscript")
        if hs is not None:
            for script in hs.findall("script"):
                id_ = script.get("id") or "hostscript"
                out = (script.get("output") or script.text or "").strip()
                if out:
                    warnings.append(f"{ip} hostscript {id_}: {out[:200]}")

        devices[ip] = dev
    return devices, warnings


def tool_versions() -> dict[str, str]:
    versions = {}
    for tool in ("nmap", "arp-scan"):
        if shutil.which(tool):
            try:
                out = subprocess.run([tool, "--version"], capture_output=True,
                                     text=True, timeout=10).stdout
                first = out.splitlines()[0].strip() if out else "?"
                versions[tool] = first
            except Exception:
                versions[tool] = "?"
    return versions
