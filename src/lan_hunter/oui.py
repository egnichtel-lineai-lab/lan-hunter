"""Offline MAC vendor lookup using IEEE OUI/MAM databases + nmap fallback."""
from __future__ import annotations

import csv
import os
import re

IEEE_DIR = "/usr/share/ieee-data"
NMAP_MAC_DB = "/usr/share/nmap/nmap-mac-prefixes"


def normalize_mac(mac: str) -> str | None:
    """Canonical form: uppercase, colon-separated."""
    if not mac:
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(h) == 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))
    if len(h) == 6:  # partial (MA-S style) - keep as-is
        return ":".join(h[i:i + 2] for i in range(0, 6, 2))
    return None


def mac_hex(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


class VendorDB:
    """Longest-prefix MAC -> vendor lookup, fully offline."""

    def __init__(self):
        self._exact: dict[str, str] = {}   # 7 or 9 hex chars (MA-S, MA-M, IAB)
        self._oui: dict[str, str] = {}     # 6 hex chars (MA-L)
        self.loaded = False

    def load(self):
        if self.loaded:
            return self

        def read_csv(path: str, target: dict, keylen: int | None):
            if not os.path.exists(path):
                return
            with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    assign = (row.get("Assignment") or "").strip().upper()
                    name = (row.get("Organization Name") or "").strip()
                    if not assign or not name or name.lower() == "private":
                        continue
                    if keylen and len(assign) != keylen:
                        continue
                    target.setdefault(assign, name)

        read_csv(os.path.join(IEEE_DIR, "oui.csv"), self._oui, 6)
        read_csv(os.path.join(IEEE_DIR, "oui36.csv"), self._exact, 9)
        read_csv(os.path.join(IEEE_DIR, "mam.csv"), self._exact, 7)
        read_csv(os.path.join(IEEE_DIR, "iab.csv"), self._exact, 9)

        # nmap's mac-prefixes as fallback ("001122 Vendor Name")
        if os.path.exists(NMAP_MAC_DB):
            with open(NMAP_MAC_DB, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2 and re.fullmatch(r"[0-9A-Fa-f]{6}", parts[0]):
                        self._oui.setdefault(parts[0].upper(), parts[1].strip())
        self.loaded = True
        return self

    def lookup(self, mac: str) -> str | None:
        self.load()
        h = mac_hex(mac)
        if len(h) < 6:
            return None
        for n in (9, 7, 6):
            if len(h) >= n and h[:n] in self._exact:
                return self._exact[h[:n]]
        return self._oui.get(h[:6])


_DB: VendorDB | None = None


def get_vendor_db() -> VendorDB:
    global _DB
    if _DB is None:
        _DB = VendorDB().load()
    return _DB
