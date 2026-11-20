"""Compare two scans / snapshots to surface network changes."""
from __future__ import annotations

from .models import Device


def _svc_set(dev: Device) -> set[tuple]:
    return {(s.port, s.protocol, s.state, s.name or "", s.product or "")
            for s in dev.services}


def diff_devices(old: dict[str, Device], new: dict[str, Device]) -> dict:
    """Diff two {key: Device} maps. Returns categorized changes."""
    changes = {
        "new_devices": [],
        "gone_devices": [],
        "new_services": [],      # (key, service)
        "closed_services": [],   # (key, service)
        "changed_services": [],  # (key, old_svc, new_svc)
        "new_os": [],            # (key, osmatch)
        "vendor_changes": [],    # (key, old_vendor, new_vendor)
    }
    for key, dev in new.items():
        if key not in old:
            changes["new_devices"].append(dev)
            continue
        o = old[key]
        old_svcs = {s.key: s for s in o.services}
        new_svcs = {s.key: s for s in dev.services}
        for k, s in new_svcs.items():
            if k not in old_svcs:
                changes["new_services"].append((key, s))
            else:
                os_ = old_svcs[k]
                if (os_.state, os_.name, os_.product, os_.version) != \
                        (s.state, s.name, s.product, s.version):
                    changes["changed_services"].append((key, os_, s))
        for k, s in old_svcs.items():
            if k not in new_svcs:
                changes["closed_services"].append((key, s))
        if dev.os_matches and not o.os_matches:
            changes["new_os"].append((key, dev.os_matches[0]))
        if dev.vendor and o.vendor and dev.vendor != o.vendor:
            changes["vendor_changes"].append((key, o.vendor, dev.vendor))
    for key, dev in old.items():
        if key not in new:
            changes["gone_devices"].append(dev)
    return changes


def format_diff(diff: dict) -> str:
    lines = []
    if diff["new_devices"]:
        lines.append(f"NEW DEVICES ({len(diff['new_devices'])}):")
        for d in diff["new_devices"]:
            lines.append(f"  + {d.key}  {', '.join(d.ip_list)}  {d.vendor or ''}")
    if diff["gone_devices"]:
        lines.append(f"DISAPPEARED DEVICES ({len(diff['gone_devices'])}):")
        for d in diff["gone_devices"]:
            lines.append(f"  - {d.key}  {', '.join(d.ip_list)}  {d.vendor or ''}")
    for key, s in diff["new_services"]:
        lines.append(f"  + NEW SERVICE  {key}: {s.summary()}")
    for key, s in diff["closed_services"]:
        lines.append(f"  - CLOSED       {key}: {s.summary()}")
    for key, o, n in diff["changed_services"]:
        lines.append(f"  ~ CHANGED      {key}: {o.summary()} -> {n.summary()}")
    for key, m in diff["new_os"]:
        lines.append(f"  + OS DETECTED    {key}: {m.label} ({m.accuracy}%)")
    for key, ov, nv in diff["vendor_changes"]:
        lines.append(f"  ~ VENDOR         {key}: {ov} -> {nv}")
    if not lines:
        lines.append("No changes detected.")
    return "\n".join(lines)
