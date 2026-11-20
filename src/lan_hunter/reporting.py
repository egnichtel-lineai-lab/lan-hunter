"""Output renderers: rich terminal table, JSON, CSV, HTML."""
from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict

from .models import Device, ScanResult


def _os_label(dev: Device) -> str:
    m = dev.primary_os
    if not m:
        return "-"
    label = m.label or m.line or "?"
    if m.accuracy is not None:
        label += f" ({m.accuracy}%)"
    return label


def _svc_brief(dev: Device, limit: int = 3) -> str:
    open_svcs = [s for s in dev.sorted_services() if s.state == "open"]
    parts = []
    for s in open_svcs[:limit]:
        p = f"{s.port}/{s.protocol}"
        if s.name:
            p += f"({s.name})"
        parts.append(p)
    if len(open_svcs) > limit:
        parts.append(f"+{len(open_svcs) - limit}")
    return ", ".join(parts) if parts else "-"


def render_table(result: ScanResult) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _plain_table(result)

    table = Table(title=f"lan-hunter scan ({result.profile}) - "
                       f"{sum(1 for d in result.devices.values() if d.up)} devices up")
    table.add_column("IP(s)", style="cyan", no_wrap=True)
    table.add_column("MAC", style="magenta", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Services", overflow="fold")

    devices = sorted(
        (d for d in result.devices.values() if d.up),
        key=lambda d: _ip_sort_key(d),
    )
    for d in devices:
        table.add_row(
            ", ".join(d.ip_list) or "-",
            d.mac or "-",
            d.vendor or "-",
            ", ".join(d.hostnames[:2]) or "-",
            _os_label(d),
            _svc_brief(d),
        )
    buf = io.StringIO()
    Console(file=buf, width=200).print(table)
    return buf.getvalue()


def _ip_sort_key(d: Device):
    try:
        parts = d.ip_list[0].split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, IndexError):
        return (999, 999, 999, 999)


def _plain_table(result: ScanResult) -> str:
    rows = [("IP", "MAC", "VENDOR", "OS", "SERVICES")]
    for d in sorted((x for x in result.devices.values() if x.up), key=_ip_sort_key):
        rows.append((",".join(d.ip_list), d.mac or "-", d.vendor or "-",
                     _os_label(d), _svc_brief(d)))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for r in rows:
        out.append("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    def dev_dict(d: Device):
        return {
            "mac": d.mac,
            "ips": [asdict(i) for i in d.ips],
            "hostname": d.hostname,
            "hostnames": d.hostnames,
            "vendor": d.vendor,
            "vendor_source": d.vendor_source,
            "os": [asdict(m) for m in d.os_matches],
            "services": [
                {k: v for k, v in asdict(s).items() if v not in (None, {}, "")}
                for s in d.sorted_services()
            ],
            "mdns": [asdict(m) for m in d.mdns],
            "sources": sorted(d.sources),
            "up": d.up,
        }
    payload = {
        "scan": {
            "started": result.started,
            "finished": result.finished,
            "targets": result.targets,
            "profile": result.profile,
            "tool_versions": result.tool_versions,
            "warnings": result.warnings,
        },
        "devices": [dev_dict(d) for d in result.devices.values() if d.up],
    }
    return json.dumps(payload, indent=2)


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["mac", "ip", "iface", "hostname", "vendor", "os",
                "os_accuracy", "port", "protocol", "state", "service",
                "product", "version", "extrainfo"])
    for d in sorted(result.devices.values(), key=_ip_sort_key):
        if not d.up:
            continue
        m = d.primary_os
        base = [d.mac or "", ";".join(d.ip_list),
                ",".join(i.iface or "" for i in d.ips),
                ";".join(d.hostnames), d.vendor or "",
                m.label if m else "", m.accuracy if m else ""]
        if not d.services:
            w.writerow(base + ["", "", "", "", "", "", ""])
        for s in d.sorted_services():
            w.writerow(base + [s.port, s.protocol, s.state, s.name or "",
                               s.product or "", s.version or "", s.extrainfo or ""])
    return buf.getvalue()


_CSS = """
body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a2e;background:#fafafa}
h1{color:#16213e} table{border-collapse:collapse;width:100%;margin-bottom:2rem;
background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}
th,td{padding:.5rem .75rem;border-bottom:1px solid #eee;text-align:left;
font-size:.9rem;vertical-align:top} th{background:#16213e;color:#fff;
position:sticky;top:0} tr:hover{background:#f0f4ff}
.mac{font-family:monospace;color:#7b2cbf} .svc{font-family:monospace;font-size:.85rem}
.badge{display:inline-block;background:#e0e7ff;color:#3730a3;border-radius:4px;
padding:0 .4rem;margin:0 .15rem .15rem 0} .os{color:#065f46}
.meta{color:#666;font-size:.85rem}
"""


def render_html(result: ScanResult) -> str:
    e = html.escape
    devices = sorted((d for d in result.devices.values() if d.up), key=_ip_sort_key)
    rows = []
    for d in devices:
        svcs = "".join(
            f"<div class='svc'>{e(s.summary())}</div>"
            + "".join(
                f"<details><summary class='meta'>{e(k)}</summary>"
                f"<pre>{e(v[:1500])}</pre></details>"
                for k, v in sorted(s.scripts.items()))
            for s in d.sorted_services() if s.state == "open"
        ) or "<span class='meta'>no open tcp services</span>"
        mdns = "".join(
            f"<span class='badge'>{e(m.service_type or '?')}: {e(m.name or '')}"
            f"{':' + str(m.port) if m.port else ''}</span>"
            for m in d.mdns)
        rows.append(
            f"<tr><td>{e(', '.join(d.ip_list))}</td>"
            f"<td class='mac'>{e(d.mac or '-')}</td>"
            f"<td>{e(d.vendor or '-')}</td>"
            f"<td>{e(', '.join(d.hostnames)) or '-'}</td>"
            f"<td class='os'>{e(_os_label(d))}</td>"
            f"<td>{svcs}{mdns}</td></tr>")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>lan-hunter scan {e(result.started)}</title><style>{_CSS}</style></head>
<body><h1>lan-hunter device inventory</h1>
<p class="meta">Started {e(result.started)} &middot; finished {e(result.finished or '?')}
&middot; profile {e(result.profile)} &middot; targets {e(', '.join(result.targets))}
&middot; {len(devices)} devices up
&middot; tools {e(', '.join(f'{k} {v}' for k, v in result.tool_versions.items()))}</p>
<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>OS</th>
<th>Services / Endpoints</th></tr>{''.join(rows)}</table>
</body></html>"""
