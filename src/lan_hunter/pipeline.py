"""Scan pipeline: discovery -> identity -> OS/service scan -> correlation."""
from __future__ import annotations

import sys

from . import discovery, nmapscan
from .models import Device, ScanResult, now_iso
from .netinfo import expand_target, lan_subnets, local_ips
from .oui import get_vendor_db, normalize_mac


def log(msg: str):
    print(f"[lan-hunter] {msg}", file=sys.stderr, flush=True)


def resolve_targets(targets: list[str] | None, no_detect: bool = False) -> list[str]:
    if targets:
        out = []
        for t in targets:
            out.extend(expand_target(t))
        return out
    if no_detect:
        raise SystemExit("no targets given and auto-detection disabled")
    subnets = lan_subnets()
    if not subnets:
        raise SystemExit("could not auto-detect LAN subnets; pass targets explicitly")
    log("auto-detected subnets: " + ", ".join(
        f"{net} ({iface})" for net, iface in subnets.items()))
    return list(subnets.keys())


def run_scan(targets: list[str], profile: str = "safe", sudo: bool = True,
             no_mdns: bool = False, no_arp: bool = False,
             no_dns: bool = False,
             skip_nmap: bool = False) -> ScanResult:
    result = ScanResult(targets=targets, profile=profile,
                        tool_versions=nmapscan.tool_versions())

    # ---- phase 1: L2/L3 discovery --------------------------------------
    subnets = [t for t in targets if "/" in t]
    my_ips = local_ips()

    def note(dev: Device) -> Device:
        # returns the (possibly pre-existing, merged) device so callers can
        # update fields on the canonical instance, not the temporary one.
        return result.add_device(dev)

    if not no_arp and subnets:
        discovery.wake_arp_table(subnets)
    if not no_arp:
        log("ARP sweep (kernel table + arp-scan)...")
        for ip, mac, iface in discovery.kernel_arp_table():
            if ip in my_ips:
                continue
            dev = Device(mac=normalize_mac(mac), sources={"arp"})
            dev.add_ip(ip, iface=iface)
            note(dev)
        for ip, mac, vendor in discovery.arp_scan(subnets):
            if ip in my_ips:
                continue
            # arp-scan's third column is the OUI vendor name, not a hostname
            dev = Device(mac=normalize_mac(mac), sources={"arp-scan"})
            dev.add_ip(ip)
            d = note(dev)
            if vendor and not d.vendor:
                d.vendor, d.vendor_source = vendor, "arp-scan-oui"
    if not skip_nmap:
        log(f"nmap host discovery (-sn) on {', '.join(targets)}...")
        ping_xml = discovery.nmap_ping_scan(targets, sudo=sudo)
        if ping_xml:
            found, warns = nmapscan.parse_nmap_xml(ping_xml)
            result.warnings.extend(warns)
            for ip, dev in found.items():
                if ip in my_ips:
                    continue
                dev.sources.add("nmap-ping")
                note(dev)
        else:
            result.warnings.append("nmap -sn discovery failed (permissions?)")

    up_count = sum(1 for d in result.devices.values() if d.ips)
    log(f"discovery complete: {up_count} candidate devices")

    # ---- phase 1b: reverse DNS (PTR) ----------------------------------
    if not no_dns:
        all_ips = sorted({ip for d in result.devices.values()
                          for ip in d.ip_list})
        log(f"reverse DNS (PTR) lookups on {len(all_ips)} addresses...")
        ptr = discovery.reverse_dns(all_ips)
        resolved = 0
        for ip, name in ptr.items():
            for d in result.devices.values():
                if ip in d.ip_list:
                    d.add_ip(ip, hostname=name)
                    if not d.hostname:
                        d.hostname = name
                    resolved += 1
        log(f"PTR: {len(ptr)} hostnames resolved for {resolved} device-IPs")

    # ---- phase 2: mDNS ------------------------------------------------
    mdns_pending = []
    if not no_mdns:
        log("mDNS/DNS-SD browse (12s)...")
        mdns_pending = discovery.avahi_services(seconds=12)
        log(f"mDNS: {len(mdns_pending)} resolved service records")
        # mDNS records whose address never matched a discovered host still
        # deserve inventory entries (e.g. devices that ignore ARP/pings).
        known_ips = {ip for d in result.devices.values() for ip in d.ip_list}
        for m in mdns_pending:
            if (m.address and discovery._is_ip(m.address)
                    and m.address not in known_ips and m.address not in my_ips):
                dev = Device(sources={"mdns"})
                dev.add_ip(m.address, hostname=m.hostname)
                if m.hostname:
                    dev.hostname = m.hostname
                dev.mdns.append(m)
                known_ips.add(m.address)
                note(dev)

    # ---- phase 3: OS + service scan -----------------------------------
    live_ips = sorted({ip for d in result.devices.values() for ip in d.ip_list})
    if skip_nmap:
        log("skipping nmap service/OS scan (--no-service-scan)")
    elif live_ips:
        log(f"nmap {profile} service/OS scan on {len(live_ips)} hosts "
            f"(this can take a while)...")
        xml, errs = nmapscan.nmap_scan(live_ips, profile=profile, sudo=sudo)
        result.warnings.extend(errs)
        if xml:
            scanned, warns = nmapscan.parse_nmap_xml(xml)
            result.warnings.extend(warns)
            for ip, dev in scanned.items():
                if ip in my_ips:
                    continue
                existing = None
                for d in result.devices.values():
                    if ip in d.ip_list:
                        existing = d
                        break
                if existing is not None:
                    existing.sources.add("nmap")
                    if dev.mac and not existing.mac:
                        existing.mac = dev.mac
                    if dev.hostname and not existing.hostname:
                        existing.hostname = dev.hostname
                    existing.os_matches = dev.os_matches or existing.os_matches
                    for s in dev.services:
                        existing.add_service(s)
                    existing.up = True
                else:
                    note(dev)
    result.finished = now_iso()

    # ---- phase 4: identity / correlation ------------------------------
    db = get_vendor_db()
    for dev in result.devices.values():
        if dev.mac and not dev.vendor:
            dev.vendor = db.lookup(dev.mac)
            dev.vendor_source = "ieee-oui" if dev.vendor else None
    if not no_mdns:
        discovery.attach_mdns(result.devices, mdns_pending)

    # add_device() already merges entries sharing the same MAC key, so
    # multi-homed devices (eth0 + wlan0) collapse into one inventory row.
    result.warnings = list(dict.fromkeys(result.warnings))
    log(f"scan complete: {sum(1 for d in result.devices.values() if d.up)} devices up")
    return result
