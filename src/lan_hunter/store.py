"""SQLite inventory store: scans, devices, services, OS matches, mDNS."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from pathlib import Path

from .models import Device, MDNSService, OSMatch, ScanResult, Service, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT,
    targets TEXT,
    profile TEXT,
    tool_versions TEXT,
    warnings TEXT,
    device_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,          -- MAC (preferred) or ip:<ip>
    mac TEXT,
    vendor TEXT,
    vendor_source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_up INTEGER DEFAULT 1,
    hostname TEXT
);

CREATE TABLE IF NOT EXISTS device_ips (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    iface TEXT,
    hostname TEXT,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (device_id, ip)
);

CREATE TABLE IF NOT EXISTS os_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id),
    vendor TEXT, family TEXT, generation TEXT, type TEXT,
    accuracy INTEGER, line TEXT,
    seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT,
    name TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    tunnel TEXT,
    method TEXT,
    scripts TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (device_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS mdns_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id),
    name TEXT,
    service_type TEXT,
    port INTEGER,
    hostname TEXT,
    address TEXT,
    txt TEXT,
    seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_device ON services(device_id);
CREATE INDEX IF NOT EXISTS idx_ips_ip ON device_ips(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self):
        """Add columns introduced after the initial schema."""
        wanted = {
            "mdns_services": {"address": "TEXT", "txt": "TEXT"},
        }
        for table, cols in wanted.items():
            existing = {r["name"] for r in self.conn.execute(
                f"PRAGMA table_info({table})")}
            for col, sqltype in cols.items():
                if col not in existing:
                    self.conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {col} {sqltype}")

    # ---------- writes ----------

    def save_scan(self, result: ScanResult) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (started, finished, targets, profile, tool_versions,"
            " warnings, device_count) VALUES (?,?,?,?,?,?,?)",
            (
                result.started, result.finished or now_iso(),
                json.dumps(result.targets), result.profile,
                json.dumps(result.tool_versions),
                json.dumps(result.warnings),
                sum(1 for d in result.devices.values() if d.up),
            ),
        )
        scan_id = cur.lastrowid
        ts = now_iso()
        for dev in result.devices.values():
            if not dev.up:
                continue
            dev_id = self._upsert_device(dev, ts)
            for ip in dev.ips:
                self.conn.execute(
                    "INSERT INTO device_ips (device_id, ip, iface, hostname, last_seen)"
                    " VALUES (?,?,?,?,?)"
                    " ON CONFLICT(device_id, ip) DO UPDATE SET"
                    " iface=COALESCE(excluded.iface, device_ips.iface),"
                    " hostname=COALESCE(excluded.hostname, device_ips.hostname),"
                    " last_seen=excluded.last_seen",
                    (dev_id, ip.ip, ip.iface, ip.hostname, ts),
                )
            for m in dev.os_matches:
                self.conn.execute(
                    "INSERT INTO os_matches (device_id, scan_id, vendor, family,"
                    " generation, type, accuracy, line, seen_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (dev_id, scan_id, m.vendor, m.family, m.generation, m.type,
                     m.accuracy, m.line, ts),
                )
            for s in dev.services:
                self.conn.execute(
                    "INSERT INTO services (device_id, scan_id, port, protocol, state,"
                    " name, product, version, extrainfo, tunnel, method, scripts,"
                    " first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(device_id, port, protocol) DO UPDATE SET"
                    " state=excluded.state, name=excluded.name,"
                    " product=excluded.product, version=excluded.version,"
                    " extrainfo=excluded.extrainfo, tunnel=excluded.tunnel,"
                    " method=excluded.method, scripts=excluded.scripts,"
                    " scan_id=excluded.scan_id, last_seen=excluded.last_seen",
                    (dev_id, scan_id, s.port, s.protocol, s.state, s.name,
                     s.product, s.version, s.extrainfo, s.tunnel, s.method,
                     json.dumps(s.scripts), ts, ts),
                )
            for m in dev.mdns:
                self.conn.execute(
                    "INSERT INTO mdns_services (device_id, scan_id, name,"
                    " service_type, port, hostname, address, txt, seen_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (dev_id, scan_id, m.name, m.service_type, m.port, m.hostname,
                     getattr(m, "address", None), getattr(m, "txt", None), ts),
                )
        self.conn.commit()
        return scan_id

    def _upsert_device(self, dev: Device, ts: str) -> int:
        row = self.conn.execute(
            "SELECT id FROM devices WHERE key=?", (dev.key,)
        ).fetchone()
        if row:
            dev_id = row["id"]
            self.conn.execute(
                "UPDATE devices SET last_seen=?, last_up=1,"
                " vendor=COALESCE(vendor, ?), vendor_source=COALESCE(vendor_source, ?),"
                " hostname=COALESCE(hostname, ?), mac=COALESCE(mac, ?)"
                " WHERE id=?",
                (ts, dev.vendor, dev.vendor_source, dev.hostname, dev.mac, dev_id),
            )
        else:
            cur = self.conn.execute(
                "INSERT INTO devices (key, mac, vendor, vendor_source, first_seen,"
                " last_seen, last_up, hostname) VALUES (?,?,?,?,?,?,1,?)",
                (dev.key, dev.mac, dev.vendor, dev.vendor_source, ts, ts, dev.hostname),
            )
            dev_id = cur.lastrowid
        return dev_id

    def mark_absent(self, seen_keys: set[str]) -> None:
        self.conn.execute(
            "UPDATE devices SET last_up=0 WHERE last_up=1 AND key NOT IN (%s)"
            % ",".join("?" * len(seen_keys)),
            tuple(seen_keys),
        ) if seen_keys else None
        self.conn.commit()

    # ---------- reads ----------

    def list_scans(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def list_devices(self, up_only: bool = False) -> list[dict]:
        q = "SELECT * FROM devices"
        if up_only:
            q += " WHERE last_up=1"
        q += " ORDER BY last_seen DESC"
        out = []
        for row in self.conn.execute(q):
            d = dict(row)
            d["ips"] = [dict(r) for r in self.conn.execute(
                "SELECT ip, iface, hostname FROM device_ips WHERE device_id=?",
                (row["id"],))]
            d["services"] = [dict(r) for r in self.conn.execute(
                "SELECT * FROM services WHERE device_id=? ORDER BY protocol, port",
                (row["id"],))]
            d["os_matches"] = [dict(r) for r in self.conn.execute(
                "SELECT * FROM os_matches WHERE device_id=?"
                " ORDER BY id DESC LIMIT 5", (row["id"],))]
            d["mdns"] = [dict(r) for r in self.conn.execute(
                "SELECT * FROM mdns_services WHERE device_id=?"
                " ORDER BY id DESC LIMIT 20", (row["id"],))]
            out.append(d)
        return out

    def get_device(self, key: str) -> dict | None:
        key = key.upper() if ":" not in key else key
        row = self.conn.execute(
            "SELECT * FROM devices WHERE upper(key)=? OR upper(mac)=? OR key=?",
            (key, key, key),
        ).fetchone()
        if not row:
            row = self.conn.execute(
                "SELECT d.* FROM devices d JOIN device_ips i ON i.device_id=d.id"
                " WHERE i.ip=?", (key,),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["ips"] = [dict(r) for r in self.conn.execute(
            "SELECT ip, iface, hostname FROM device_ips WHERE device_id=?", (row["id"],))]
        d["services"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM services WHERE device_id=? ORDER BY protocol, port", (row["id"],))]
        d["os_matches"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM os_matches WHERE device_id=? ORDER BY id DESC", (row["id"],))]
        d["mdns"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM mdns_services WHERE device_id=? ORDER BY id DESC", (row["id"],))]
        d["history"] = [dict(r) for r in self.conn.execute(
            "SELECT s.started, s.profile FROM scans s JOIN services sv"
            " ON sv.scan_id=s.id WHERE sv.device_id=? GROUP BY s.id ORDER BY s.id DESC",
            (row["id"],))]
        return d

    def scan_device_keys(self, scan_id: int) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT d.key FROM devices d JOIN services s ON s.device_id=d.id"
            " WHERE s.scan_id=?", (scan_id,)).fetchall()
        rows2 = self.conn.execute(
            "SELECT DISTINCT d.key FROM devices d JOIN os_matches o ON o.device_id=d.id"
            " WHERE o.scan_id=?", (scan_id,)).fetchall()
        rows3 = self.conn.execute(
            "SELECT DISTINCT d.key FROM devices d JOIN mdns_services m"
            " ON m.device_id=d.id WHERE m.scan_id=?", (scan_id,)).fetchall()
        return ({r["key"] for r in rows} | {r["key"] for r in rows2}
                | {r["key"] for r in rows3})

    def mark_absent_in(self, subnets: list[str], seen_keys: set[str]) -> None:
        """Mark devices DOWN if they live in the scanned subnets but were not
        seen in the latest scan. Devices outside those subnets are untouched."""
        try:
            nets = [ipaddress.ip_network(s) for s in subnets if "/" in s]
        except ValueError:
            return
        if not nets:
            return
        candidates = self.conn.execute(
            "SELECT d.id, d.key FROM devices d WHERE d.last_up=1").fetchall()
        for row in candidates:
            if row["key"] in seen_keys:
                continue
            ips = self.conn.execute(
                "SELECT ip FROM device_ips WHERE device_id=?", (row["id"],)).fetchall()
            in_scope = any(
                any(ipaddress.ip_address(r["ip"]) in n for n in nets)
                for r in ips if _is_v4(r["ip"])
            )
            if in_scope:
                self.conn.execute(
                    "UPDATE devices SET last_up=0 WHERE id=?", (row["id"],))
        self.conn.commit()

    def load_scan_snapshot(self, scan_id: int) -> dict[str, Device]:
        """Reconstruct {key: Device} as observed during a specific scan."""
        rows = self.conn.execute(
            "SELECT DISTINCT d.* FROM devices d"
            " LEFT JOIN services s ON s.device_id=d.id AND s.scan_id=?"
            " LEFT JOIN os_matches o ON o.device_id=d.id AND o.scan_id=?"
            " LEFT JOIN mdns_services m ON m.device_id=d.id AND m.scan_id=?"
            " WHERE s.id IS NOT NULL OR o.id IS NOT NULL OR m.id IS NOT NULL",
            (scan_id, scan_id, scan_id)).fetchall()
        devices: dict[str, Device] = {}
        for row in rows:
            dev = Device(mac=row["mac"], hostname=row["hostname"],
                         vendor=row["vendor"], up=True)
            for r in self.conn.execute(
                    "SELECT ip, iface, hostname FROM device_ips WHERE device_id=?",
                    (row["id"],)):
                dev.add_ip(r["ip"], r["iface"], r["hostname"])
            for r in self.conn.execute(
                    "SELECT * FROM services WHERE device_id=? AND scan_id=?",
                    (row["id"], scan_id)):
                dev.add_service(Service(
                    port=r["port"], protocol=r["protocol"], state=r["state"],
                    name=r["name"], product=r["product"], version=r["version"],
                    extrainfo=r["extrainfo"], tunnel=r["tunnel"],
                    method=r["method"],
                    scripts=json.loads(r["scripts"] or "{}")))
            for r in self.conn.execute(
                    "SELECT * FROM os_matches WHERE device_id=? AND scan_id=?",
                    (row["id"], scan_id)):
                dev.os_matches.append(OSMatch(
                    vendor=r["vendor"], family=r["family"],
                    generation=r["generation"], type=r["type"],
                    accuracy=r["accuracy"], line=r["line"]))
            for r in self.conn.execute(
                    "SELECT * FROM mdns_services WHERE device_id=? AND scan_id=?",
                    (row["id"], scan_id)):
                dev.mdns.append(MDNSService(
                    name=r["name"], service_type=r["service_type"],
                    port=r["port"], hostname=r["hostname"],
                    address=r["address"] if "address" in r.keys() else None,
                    txt=r["txt"] if "txt" in r.keys() else None))
            devices[dev.key] = dev
        return devices

    def close(self):
        self.conn.close()


def _is_v4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False
