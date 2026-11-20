"""lan-hunter command line interface."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .diffing import diff_devices, format_diff
from .models import Device
from .pipeline import log, resolve_targets, run_scan
from .reporting import render_csv, render_html, render_json, render_table
from .store import Store

def _default_db_path() -> str:
    """Inventory path. When invoked via sudo, prefer the invoking user's
    home (SUDO_UID) so scans and queries share one inventory regardless of
    how the tool was elevated."""
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        try:
            import pwd
            home = pwd.getpwuid(int(sudo_uid)).pw_dir
            return str(Path(home) / ".lan-hunter" / "inventory.db")
        except (KeyError, ValueError):
            pass
    return str(Path.home() / ".lan-hunter" / "inventory.db")


DEFAULT_DB = os.environ.get("LAN_HUNTER_DB", _default_db_path())


def _sudo_available() -> bool:
    """Check whether nmap can run under passwordless sudo (the sudoers rule
    typically allows only nmap/arp-scan, not arbitrary commands)."""
    for candidate in ("/usr/bin/nmap", "/usr/sbin/nmap", "nmap"):
        try:
            proc = subprocess.run(["sudo", "-n", candidate, "--version"],
                                  capture_output=True, timeout=10)
            if proc.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
    return False


def _ensure_sudo(args) -> bool:
    if getattr(args, "no_sudo", False):
        return False
    if _sudo_available():
        return True
    log("WARNING: passwordless sudo not available.")
    log("  nmap SYN scans and -O OS detection need root privileges.")
    log("  Either run:  sudo lan-hunter scan ...")
    log("  or configure a sudoers rule for nmap/arp-scan (see README).")
    log("  Falling back to unprivileged scan (connect scan, no OS detection).")
    return False


# ---------------- scan ----------------

def cmd_scan(args) -> int:
    targets = resolve_targets(args.targets)
    sudo = _ensure_sudo(args)
    result = run_scan(
        targets=targets,
        profile=args.profile,
        sudo=sudo,
        no_mdns=args.no_mdns,
        no_arp=args.no_arp,
        no_dns=args.no_dns,
        skip_nmap=args.no_service_scan,
    )

    store = Store(args.db)
    try:
        scan_id = store.save_scan(result)
        seen = {k for k, d in result.devices.items() if d.up}
        if seen:
            store.mark_absent_in(targets, seen)
        log(f"saved scan #{scan_id} to {args.db}")
    finally:
        store.close()

    fmt = args.format
    if fmt == "table":
        print(render_table(result))
    elif fmt == "json":
        print(render_json(result))
    elif fmt == "csv":
        print(render_csv(result), end="")
    elif fmt == "html":
        out = Path(args.output or f"lan-hunter-scan-{scan_id}.html")
        out.write_text(render_html(result), encoding="utf-8")
        log(f"wrote {out}")
    if args.output and fmt in ("json", "csv"):
        Path(args.output).write_text(
            render_json(result) if fmt == "json" else render_csv(result),
            encoding="utf-8")
        log(f"wrote {args.output}")
    if result.warnings:
        print("\nWarnings:", file=sys.stderr)
        for w in result.warnings[:20]:
            print(f"  - {w}", file=sys.stderr)
    return 0


# ---------------- devices ----------------

def cmd_devices(args) -> int:
    store = Store(args.db)
    try:
        devices = store.list_devices(up_only=not args.all)
    finally:
        store.close()
    if args.format == "json":
        print(json.dumps(devices, indent=2, default=str))
        return 0
    if args.format == "csv":
        import csv as _csv
        w = _csv.writer(sys.stdout)
        w.writerow(["key", "mac", "ips", "vendor", "hostname", "os",
                    "open_ports", "first_seen", "last_seen", "up"])
        for d in devices:
            w.writerow([
                d["key"], d["mac"] or "",
                ";".join(i["ip"] for i in d["ips"]), d["vendor"] or "",
                d["hostname"] or "",
                (d["os_matches"][0]["vendor"] or "") + " " +
                (d["os_matches"][0]["family"] or "") if d["os_matches"] else "",
                ";".join(f"{s['port']}/{s['protocol']}" for s in d["services"]
                         if s["state"] == "open"),
                d["first_seen"], d["last_seen"], bool(d["last_up"]),
            ])
        return 0
    # table
    hdr = (f"{'KEY':<20} {'IPS':<16} {'HOSTNAME':<26} {'VENDOR':<24} "
           f"{'OS':<26} {'PORTS':<24} {'LAST SEEN':<20} UP")
    print(hdr)
    print("-" * len(hdr))
    for d in devices:
        os_label = ""
        if d["os_matches"]:
            m = d["os_matches"][0]
            os_label = " ".join(x for x in (m["vendor"], m["family"], m["generation"]) if x)[:24]
        ports = ",".join(f"{s['port']}" for s in d["services"] if s["state"] == "open")[:22]
        print(f"{d['key']:<20} {'; '.join(i['ip'] for i in d['ips'])[:15]:<16} "
              f"{(d['hostname'] or '-')[:25]:<26} "
              f"{(d['vendor'] or '-')[:23]:<24} {os_label or '-':<26} "
              f"{ports or '-':<24} {d['last_seen']:<20} "
              f"{'yes' if d['last_up'] else 'no'}")
    print(f"\n{len(devices)} devices "
          f"({'use -a to include devices not seen in the latest scan' if not args.all else 'including down'})")
    return 0


# ---------------- show ----------------

def cmd_show(args) -> int:
    store = Store(args.db)
    try:
        d = store.get_device(args.device)
    finally:
        store.close()
    if not d:
        print(f"no device matching {args.device!r}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(d, indent=2, default=str))
        return 0
    print(f"Device {d['key']}")
    print("=" * 60)
    print(f"  MAC:      {d['mac'] or '-'}")
    print(f"  Vendor:   {d['vendor'] or '-'} ({d['vendor_source'] or '-'})")
    print(f"  IPs:      " + ", ".join(
        f"{i['ip']}" + (f" [{i['iface']}]" if i['iface'] else "")
        + (f" ({i['hostname']})" if i['hostname'] else "") for i in d["ips"]) or "-")
    print(f"  Hostnames: {', '.join(sorted({i['hostname'] for i in d['ips'] if i['hostname']})) or '-'}")
    print(f"  First seen: {d['first_seen']}   Last seen: {d['last_seen']}"
          f"   {'UP' if d['last_up'] else 'DOWN'}")
    if d["os_matches"]:
        print("  OS fingerprints:")
        for m in d["os_matches"][:5]:
            label = " ".join(x for x in (m["vendor"], m["family"], m["generation"]) if x)
            print(f"    - {label or m['line'] or '?'}"
                  + (f" ({m['accuracy']}%)" if m["accuracy"] else ""))
    if d["mdns"]:
        print("  mDNS advertisements:")
        for m in d["mdns"][:15]:
            print(f"    - {m['service_type'] or '?'}  {m['name'] or ''}"
                  + (f"  port {m['port']}" if m["port"] else ""))
    if d["services"]:
        print("  Services / endpoints:")
        for s in d["services"]:
            bits = [f"    {s['protocol']}/{s['port']:<6} {s['state']:<9}"]
            ident = " ".join(x for x in (s["name"], s["product"], s["version"],
                                         s["extrainfo"]) if x)
            bits.append(ident or "")
            print(" ".join(bits))
            scripts = json.loads(s["scripts"] or "{}")
            for sid, out in scripts.items():
                first = out.strip().splitlines()[:3]
                for line in first:
                    print(f"        {sid}: {line[:110]}")
    return 0


# ---------------- scans / diff ----------------

def cmd_scans(args) -> int:
    store = Store(args.db)
    try:
        rows = store.list_scans(limit=args.limit)
    finally:
        store.close()
    if not rows:
        print("no scans recorded yet - run: lan-hunter scan")
        return 0
    print(f"{'ID':<5} {'STARTED':<21} {'PROFILE':<10} {'DEVICES':<8} TARGETS")
    for r in rows:
        print(f"{r['id']:<5} {r['started']:<21} {r['profile'] or '-':<10} "
              f"{r['device_count']:<8} {r['targets']}")
    return 0


def cmd_diff(args) -> int:
    store = Store(args.db)
    try:
        scans = store.list_scans(limit=100)
        if args.scans:
            a_id, b_id = int(args.scans[0]), int(args.scans[1])
        else:
            if len(scans) < 2:
                print("need at least two scans to diff", file=sys.stderr)
                return 1
            b_id, a_id = scans[0]["id"], scans[1]["id"]
        old = store.load_scan_snapshot(a_id)
        new = store.load_scan_snapshot(b_id)
    finally:
        store.close()
    print(f"diff scan #{a_id} -> #{b_id}")
    print(format_diff(diff_devices(old, new)))
    return 0


# ---------------- report ----------------

def cmd_report(args) -> int:
    store = Store(args.db)
    try:
        devices = store.list_devices(up_only=not args.all)
    finally:
        store.close()
    # rebuild Device objects for the renderers
    from .models import DeviceIP, MDNSService, OSMatch, Service
    result_devices = {}
    for d in devices:
        dev = Device(mac=d["mac"], hostname=d["hostname"], vendor=d["vendor"],
                     up=bool(d["last_up"]))
        for i in d["ips"]:
            dev.add_ip(i["ip"], i["iface"], i["hostname"])
        for m in d["os_matches"]:
            dev.os_matches.append(OSMatch(
                vendor=m["vendor"], family=m["family"], generation=m["generation"],
                type=m["type"], accuracy=m["accuracy"], line=m["line"]))
        for s in d["services"]:
            dev.add_service(Service(
                port=s["port"], protocol=s["protocol"], state=s["state"],
                name=s["name"], product=s["product"], version=s["version"],
                extrainfo=s["extrainfo"], tunnel=s["tunnel"], method=s["method"],
                scripts=json.loads(s["scripts"] or "{}")))
        for m in d["mdns"]:
            dev.mdns.append(MDNSService(name=m["name"], service_type=m["service_type"],
                                        port=m["port"], hostname=m["hostname"]))
        result_devices[dev.key] = dev
    from .models import ScanResult
    result = ScanResult(started="inventory-snapshot", finished="inventory-snapshot",
                        targets=["stored inventory"], profile="inventory")
    result.devices = result_devices

    if args.format == "json":
        out = render_json(result)
    elif args.format == "csv":
        out = render_csv(result)
    elif args.format == "html":
        out = render_html(result)
    else:
        out = render_table(result)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        log(f"wrote {args.output}")
    else:
        print(out)
    return 0


# ---------------- parser ----------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lan-hunter",
        description="LAN/IoT device enumeration, MAC/OS fingerprinting and "
                    "service discovery with a historical inventory.")
    p.add_argument("--version", action="version", version=f"lan-hunter {__version__}")
    p.add_argument("--db", default=DEFAULT_DB, help=f"SQLite inventory path (default {DEFAULT_DB})")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="discover devices and scan them")
    sc.add_argument("targets", nargs="*",
                    help="CIDR/IP/range (default: auto-detect connected subnets)")
    sc.add_argument("--profile", choices=["safe", "balanced", "aggressive"],
                    default="safe",
                    help="safe: gentle on IoT firmware (default); "
                         "aggressive: full port range + more scripts (may crash cheap firmware)")
    sc.add_argument("--format", choices=["table", "json", "csv", "html"], default="table")
    sc.add_argument("-o", "--output", help="write report to file")
    sc.add_argument("--no-mdns", action="store_true", help="skip mDNS/DNS-SD browse")
    sc.add_argument("--no-arp", action="store_true", help="skip ARP sweep")
    sc.add_argument("--no-dns", action="store_true",
                    help="skip reverse DNS (PTR) lookups")
    sc.add_argument("--no-service-scan", action="store_true",
                    help="discovery + identity only (no nmap service/OS scan)")
    sc.add_argument("--no-sudo", action="store_true", help="run nmap unprivileged")
    sc.set_defaults(func=cmd_scan)

    dv = sub.add_parser("devices", help="list inventory")
    dv.add_argument("-a", "--all", action="store_true", help="include devices not currently up")
    dv.add_argument("--format", choices=["table", "json", "csv"], default="table")
    dv.set_defaults(func=cmd_devices)

    sh = sub.add_parser("show", help="show one device in detail")
    sh.add_argument("device", help="MAC, IP or inventory key")
    sh.add_argument("--format", choices=["text", "json"], default="text")
    sh.set_defaults(func=cmd_show)

    sv = sub.add_parser("scans", help="list past scans")
    sv.add_argument("--limit", type=int, default=30)
    sv.set_defaults(func=cmd_scans)

    df = sub.add_parser("diff", help="diff two scans (default: last two)")
    df.add_argument("scans", nargs="*", metavar="SCAN_ID",
                    help="two scan ids: older newer")
    df.set_defaults(func=cmd_diff)

    rp = sub.add_parser("report", help="render the stored inventory as a report")
    rp.add_argument("--format", choices=["table", "json", "csv", "html"], default="table")
    rp.add_argument("-o", "--output", help="write report to file")
    rp.add_argument("-a", "--all", action="store_true", help="include down devices")
    rp.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
