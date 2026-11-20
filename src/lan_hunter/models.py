"""Dataclasses shared across lan-hunter modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str | None:
        parts = [p for p in (self.product, self.version, self.extrainfo) if p]
        return " ".join(parts) if parts else None

    @property
    def key(self) -> tuple:
        return (self.port, self.protocol)

    def summary(self) -> str:
        bits = [f"{self.protocol}/{self.port}"]
        if self.state and self.state != "open":
            bits.append(self.state)
        if self.name:
            bits.append(self.name)
        if self.banner:
            bits.append(f"({self.banner})")
        return " ".join(bits)


@dataclass
class OSMatch:
    vendor: str | None = None
    family: str | None = None
    generation: str | None = None
    type: str | None = None
    accuracy: int | None = None
    line: str | None = None

    @property
    def label(self) -> str | None:
        parts = [p for p in (self.vendor, self.family, self.generation) if p]
        return " ".join(parts) if parts else None


@dataclass
class DeviceIP:
    ip: str
    iface: str | None = None
    hostname: str | None = None


@dataclass
class MDNSService:
    name: str | None = None
    service_type: str | None = None
    port: int | None = None
    hostname: str | None = None
    address: str | None = None
    txt: str | None = None


@dataclass
class Device:
    """A device keyed by MAC address (or IP when no MAC is known)."""

    mac: str | None = None
    ips: list[DeviceIP] = field(default_factory=list)
    hostname: str | None = None
    vendor: str | None = None
    vendor_source: str | None = None
    os_matches: list[OSMatch] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    mdns: list[MDNSService] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    up: bool = True

    def __post_init__(self) -> None:
        # MACs arrive uppercase from arp tools and lowercase from nmap;
        # canonicalise here so device keys never fork on case.
        if self.mac:
            self.mac = self.mac.upper()

    @property
    def key(self) -> str:
        if self.mac:
            return self.mac
        return "ip:" + (self.ips[0].ip if self.ips else "unknown")

    @property
    def ip_list(self) -> list[str]:
        return [i.ip for i in self.ips]

    @property
    def primary_os(self) -> OSMatch | None:
        return self.os_matches[0] if self.os_matches else None

    @property
    def hostnames(self) -> list[str]:
        names = []
        if self.hostname:
            names.append(self.hostname)
        for i in self.ips:
            if i.hostname and i.hostname not in names:
                names.append(i.hostname)
        for m in self.mdns:
            if m.hostname and m.hostname not in names:
                names.append(m.hostname)
        return names

    def add_ip(self, ip: str, iface: str | None = None, hostname: str | None = None):
        for existing in self.ips:
            if existing.ip == ip:
                if iface and not existing.iface:
                    existing.iface = iface
                if hostname and not existing.hostname:
                    existing.hostname = hostname
                return
        self.ips.append(DeviceIP(ip=ip, iface=iface, hostname=hostname))

    def add_service(self, svc: Service):
        for existing in self.services:
            if existing.key == svc.key:
                # prefer richer info
                if svc.product and not existing.product:
                    existing.product = svc.product
                if svc.version and not existing.version:
                    existing.version = svc.version
                if svc.extrainfo and not existing.extrainfo:
                    existing.extrainfo = svc.extrainfo
                existing.scripts.update(svc.scripts)
                return
        self.services.append(svc)

    def sorted_services(self) -> list[Service]:
        return sorted(self.services, key=lambda s: (s.protocol, s.port))


@dataclass
class ScanResult:
    started: str = field(default_factory=now_iso)
    finished: str | None = None
    targets: list[str] = field(default_factory=list)
    profile: str = "safe"
    devices: dict[str, Device] = field(default_factory=dict)
    tool_versions: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def add_device(self, dev: Device) -> Device:
        existing = self.devices.get(dev.key)
        if existing is None:
            self.devices[dev.key] = dev
            return dev
        for ip in dev.ips:
            existing.add_ip(ip.ip, ip.iface, ip.hostname)
        existing.sources |= dev.sources
        if dev.hostname and not existing.hostname:
            existing.hostname = dev.hostname
        if dev.vendor and not existing.vendor:
            existing.vendor = dev.vendor
            existing.vendor_source = dev.vendor_source
        if dev.os_matches and not existing.os_matches:
            existing.os_matches = dev.os_matches
        for s in dev.services:
            existing.add_service(s)
        for m in dev.mdns:
            existing.mdns.append(m)
        existing.up = existing.up or dev.up
        return existing
