# lan-hunter

LAN/IoT device enumeration, identification and service discovery for your
home network. Combines ARP sweeps, mDNS/DNS-SD browsing, IEEE OUI vendor
lookups, reverse DNS, nmap OS fingerprinting and service/banner enumeration
into a single CLI with a **historical SQLite inventory** that detects new
devices and changed services between scans.

Everything runs locally against your own LAN: no cloud services, no
third-party APIs, nothing leaves your network.

## What it does

1. **Discovery** — finds live hosts via:
   - kernel ARP table + `arp-scan` L2 sweep of each detected subnet
   - `nmap -sn` ping discovery (ARP/ICMP/TCP probes)
   - `avahi-browse` mDNS/DNS-SD advertisements (AirPlay, Chromecasts,
     printers, HomeKit, ESPHome, Sonos, etc. announce themselves)
2. **Identification** —
   - MAC → vendor via the offline IEEE OUI/MAM/IAB database (`ieee-data`)
     with `nmap-mac-prefixes` as fallback.
   - **Reverse DNS (PTR)** — concurrent reverse lookups for every discovered
     IP via the system resolver (honours `/etc/resolv.conf` + `nsswitch`, so
     your router/DNS server's reverse zone resolves hostnames like
     `computer.domain.com`). Disable with `--no-dns`.
   - OS fingerprinting via `nmap -O` (TCP/IP stack analysis) with accuracy %.
3. **Service / endpoint enumeration** — `nmap -sS -sV` against a curated
   IoT port set (HTTP/HTTPS, RTSP, MQTT, CoAP, telnet, UPnP, mDNS, Modbus,
   BACnet, SMB, SSH, VNC, ...) plus NSE scripts (`http-title`, `ssl-cert`,
   `upnp-info`, `smb-os-discovery`, ...) to grab banners, TLS certs and
   device descriptions.
4. **Inventory & history** — every scan is stored in SQLite. Repeat scans
   update `first_seen`/`last_seen`, mark devices down, and `lan-hunter diff`
   shows what appeared, disappeared, or changed open ports.

## Prerequisites (Debian/Ubuntu)

One-time setup on any Debian/Ubuntu host — everything lan-hunter shells out
to, in one command:

```bash
sudo apt-get update
sudo apt-get install -y nmap arp-scan ieee-data avahi-utils avahi-daemon \
    python3 python3-venv python3-pip

# mDNS browsing talks to the Avahi daemon; servers often ship without it:
sudo systemctl enable --now avahi-daemon
```

| Requirement | Used for | Debian/Ubuntu package |
|---|---|---|
| Linux + `ip`, `ping` | subnet auto-detection, waking the ARP table | `iproute2`, `iputils-ping` (preinstalled on most systems) |
| Python ≥ 3.10 | runtime | `python3`, `python3-venv`, `python3-pip` |
| nmap | host discovery, OS + service scanning | `nmap` |
| arp-scan | L2 ARP sweep (with vendor column) | `arp-scan` |
| avahi-browse + daemon | mDNS/DNS-SD browsing | `avahi-utils`, `avahi-daemon` |
| IEEE OUI/MAM/IAB data | offline MAC → vendor lookup | `ieee-data` |
| rich (*optional*) | pretty terminal tables | `python3-rich`, or `pip install rich` in the venv (plain tables otherwise) |

Every external tool is probed at use time and its phase is skipped when
missing — except `nmap`, which is required for the service/OS scan phase
(use `--no-service-scan` to run discovery + identity only).

**Inventory location**: `~/.lan-hunter/inventory.db` by default. Override
with the `LAN_HUNTER_DB` environment variable or the global `--db PATH`
flag — which must precede the subcommand:
`lan-hunter --db /path/to/inventory.db scan`. When run under `sudo`, the
default path resolves through `SUDO_UID` to the *invoking user's* home, so
`sudo lan-hunter scan` and `lan-hunter devices` share one inventory.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
# system-wide launcher (so `sudo lan-hunter ...` works; sudo's secure_path
# includes /usr/local/bin but not ~/.local/bin):
sudo ln -sf "$PWD/.venv/bin/lan-hunter" /usr/local/bin/lan-hunter
```

`pip install -e .` installs the `lan-hunter` console script in editable mode,
so edits under `src/` take effect immediately.

### Where sudo is required (accuracy)

lan-hunter runs end-to-end without root, but **several results are less
accurate — or simply missing — without it**, because these techniques need
raw sockets:

| Capability | Why it needs root | Without sudo you lose |
|---|---|---|
| `nmap -sS` SYN scan | raw sockets | nmap silently falls back to TCP connect scans: slower, and some hosts misreport port state |
| `nmap -O` OS detection | crafted probe packets | the OS column stays empty — no fingerprinting at all |
| `nmap -sn` ARP ping | ARP requests | hosts that drop ICMP but answer ARP are missed |
| `arp-scan` L2 sweep | raw Ethernet frames | the sweep returns nothing; only the kernel ARP table and nmap discovery contribute |
| broadcast ping (wakes the kernel ARP table) | none — works unprivileged | — |

Two ways to get full-accuracy scans:

1. **Run the whole scan as root** (recommended — every capability above
   works):

   ```bash
   sudo lan-hunter scan
   ```

2. **Scoped passwordless sudo for nmap only.** The tool invokes `sudo nmap`
   itself whenever `sudo -n nmap --version` succeeds, so granting just nmap
   restores SYN scans and OS detection:

   ```bash
   echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/sbin/nmap" \
     | sudo tee /etc/sudoers.d/lan-hunter && sudo chmod 440 /etc/sudoers.d/lan-hunter
   ```

   The `arp-scan` phase still runs as your unprivileged user and yields
   nothing with this option — use option 1 when you need the full L2 sweep.

`scan` probes `sudo -n nmap --version` at startup; if that fails it warns
and falls back to an unprivileged scan (TCP connect, no OS detection).
Force unprivileged mode with `--no-sudo`. Inventory queries (`devices`,
`show`, `scans`, `diff`, `report`) never need sudo.

## Usage

```bash
# Scan all auto-detected LAN subnets (safe profile), print table, save to DB
lan-hunter scan

# Explicit targets (CIDR or single IP; max 65,536 addresses per target)
lan-hunter scan <network address>/<CIDR Block> # example lan-hunter scan 192.168.0.0/24

# Scan profiles
lan-hunter scan --profile safe        # default: gentle on flaky IoT firmware
lan-hunter scan --profile balanced    # wider port range, faster timing
lan-hunter scan --profile aggressive  # full port range + more scripts
                                      #   (may crash cheap embedded devices)

# Reports
lan-hunter scan --format json -o scan.json
lan-hunter scan --format csv  -o scan.csv
lan-hunter scan --format html -o scan.html   # shareable inventory page

# Inventory queries (no rescanning)
lan-hunter devices                  # current inventory table
lan-hunter devices -a               # include devices not currently up
lan-hunter devices --format json    # or csv
lan-hunter show <colon seperated MAC address>   # one device: MAC/IPs/OS/services/mDNS example: lan-hunter show 00:00:00:00:00:00
lan-hunter show <ip address> --format json # example lan-hunter show 192.168.0.2 --format json
lan-hunter scans                    # scan history (--limit N)
lan-hunter diff                     # diff the last two scans
lan-hunter diff 3 7                 # diff scan #3 -> #7
lan-hunter report --format html -o inventory.html
```

Discovery toggles: `--no-mdns`, `--no-arp`, `--no-dns`,
`--no-service-scan` (discovery + identity only), `--no-sudo`.
Global options: `--db PATH`, `--version`.

## Scan profiles

| profile | nmap flags | ports | timing | scripts | risk to IoT |
|---|---|---|---|---|---|
| safe (default) | `-sS -sV --version-light -O` | curated IoT TCP port set | T2, 800 ms max RTT, 1 retry, 8 m host-timeout | read-only banner scripts | minimal |
| balanced | `-sS -sV -O` | IoT set + `9-49151` TCP sweep | T3, 10 m host-timeout | read-only banner scripts | low |
| aggressive | `-sS -sU -sV -O -A` | all TCP `1-65535` + key UDP ports | T4, 15 m host-timeout | extended script set | **can crash cheap firmware** |

All profiles run nmap with `-n -Pn`: reverse DNS is done separately (so it
honours your own resolver and reverse zones) and hosts are already known-up
from discovery. Requested NSE scripts are filtered against the scripts
actually present in `/usr/share/nmap/scripts`, so a missing script can never
abort the scan.

The safe/balanced script set is strictly read-only banner grabbing
(`http-title`, `ssl-cert`, `upnp-info`, `smb-os-discovery`, ...). The
aggressive set adds a few known-insecure-configuration probes
(`x11-access`, `realvnc-auth-bypass`, `snmp-info`, `bacnet-info`, ...) —
still non-destructive, but they are active checks.

## Architecture

### Data flow

```
targets (CLI args, or auto-detected by netinfo.py)
        |
        v
cli.py --> pipeline.run_scan()
              |
              +- 1   discovery ----- discovery.py -- broadcast ping, kernel
              |                                     ARP table, arp-scan,
              |                                     nmap -sn
              +- 1b  reverse DNS --- discovery.py -- gethostbyaddr, 48 workers
              +- 2   mDNS ---------- discovery.py -- avahi-browse (12 s)
              +- 3   service/OS ---- nmapscan.py --- profile flags + XML parse
              +- 4   identity ------ oui.py -------- offline IEEE OUI/MAM/IAB
              |
              v
        store.py (SQLite inventory)
              |
              +--> diffing.py    (scan-to-scan change sets)
              +--> reporting.py  (rich table / JSON / CSV / HTML)
```

`models.py` holds the shared dataclasses (`Device`, `Service`, `OSMatch`,
`MDNSService`, `ScanResult`) that flow between all stages.

### Scan pipeline (`pipeline.run_scan`)

1. **Target resolution** (`netinfo.py`) — explicit CIDR/IP arguments are
   validated (IPv4 only, ≤ 65,536 addresses); otherwise directly-connected
   subnets are auto-detected via `ip -j addr`, skipping loopback, virtual
   interfaces (`docker*`, `br-*`, `veth*`, `lxd*`, `kube*`, `wg*`, `tun*`,
   `zt*`, ...) and prefixes outside /8–/28.
2. **Phase 1 — L2/L3 discovery** (`discovery.py`) — broadcast pings wake the
   kernel ARP table, which is then read from `/proc/net/arp`; `arp-scan`
   sweeps each subnet (its third column is the OUI *vendor*, never a
   hostname); `nmap -sn` adds hosts that ignore ARP but answer ICMP/TCP
   probes. The scanner's own addresses are filtered out.
3. **Phase 1b — reverse DNS** — concurrent `gethostbyaddr` (48 workers,
   2.5 s timeout) through the system resolver, so `nsswitch` plugins
   (mDNS/LLMNR) and the router's reverse zone work.
4. **Phase 2 — mDNS** — `avahi-browse -a -p -r -t` browses for 12 s and
   keeps resolved (`=`) records only, deduplicated on
   (name, type, address, port). Services whose address never matched a
   discovered host still get their own inventory entry — some IoT devices
   ignore ARP and pings but advertise.
5. **Phase 3 — service/OS scan** — one `nmap` invocation over all live IPs
   using the selected profile; the XML is parsed into OS matches (with
   accuracy), services (`open`/`filtered` states only) and NSE script
   output.
6. **Phase 4 — identity & correlation** — MACs still missing a vendor are
   resolved through the offline IEEE database (longest-prefix: 9 → 7 → 6
   hex chars); mDNS records are attached to devices by resolved address or
   hostname.

### Device model & correlation

A `Device` is keyed by its **MAC address** (canonical uppercase, colon
separated) or `ip:<address>` when no MAC is known. Every discovery source
feeds the same `ScanResult.devices` map through `add_device()`, which merges
by key — so a phone seen via ARP, ping and mDNS collapses into one entry
with `sources={arp, nmap-ping, mdns}`, and multi-homed devices (eth0 +
wlan0) become a single inventory row. Services merge by (port, protocol)
preferring richer fields; hostnames accumulate from PTR, nmap and mDNS.

### Storage & history (`store.py`)

SQLite (default `~/.lan-hunter/inventory.db`) with six tables: `scans`
(metadata, tool versions, warnings), `devices` (unique key, first/last seen,
up flag), `device_ips`, `services` (upserted per device+port+protocol,
keeping `first_seen`), and append-only `os_matches` / `mdns_services`
history tagged per scan. After each scan, devices **inside the scanned
subnets** that were not seen are marked down; devices outside the scan scope
keep their state. `diff` reconstructs per-scan snapshots from the
scan-tagged rows and reports new/gone devices, new/closed/changed services,
new OS matches and vendor changes.

### Output (`reporting.py`)

`rich` renders the terminal table when installed (plain-text fallback
otherwise); the JSON/CSV/HTML renderers are dependency-free. HTML output is
a single self-contained page (inline CSS, per-service `<details>` blocks
for NSE script output).

### Degradation

Every external tool is probed at use time: missing `arp-scan` or
`avahi-browse` skip their phase; missing passwordless sudo downgrades to
unprivileged connect scans with no OS detection; nmap failures become
warnings attached to the scan record rather than aborts.

## Companion tools

- `tools/dhcp-fingerprint.ps1` — read-only PowerShell helper for **Windows
  DHCP servers**: pulls the lease client identifier (DHCP option 61 — its
  format is itself a device fingerprint), the granted-lease policy, and
  historical hostname records from server logs for a client that never
  sends a hostname. Run it on the DHCP server; `-ForceRebind` triggers a
  fresh DISCOVER that a lan-hunter host can capture passively to see
  options 55/60 on the wire.

## Notes & caveats

- **OS detection on IoT is fuzzy.** A camera may fingerprint as "Linux 3.x"
  with 87% accuracy; store the confidence and treat it as a hint.
- Devices behind a different router/AP isolation won't answer ARP; mDNS
  records with a resolved address are matched to inventory devices by IP or
  hostname and stored per device.
- The safe/balanced profiles only grab read-only banners; the aggressive
  profile adds non-destructive security-configuration probes. Either way,
  scan your own network only.
- `lxdbr0`, `docker*`, `br-*`, `veth*` etc. are excluded from auto-detection;
  pass them explicitly if you want them scanned.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `nmap -sn discovery failed (permissions?)` | no passwordless sudo — run `sudo lan-hunter scan` or add the sudoers rule |
| mDNS phase finds nothing | `avahi-daemon` not running — `systemctl status avahi-daemon` |
| Vendor column empty | install `ieee-data`; check the MAC prefix is publicly assigned |
| Table empty but devices exist | they may be marked down by a later scan — `lan-hunter devices -a` |
| Two rows for one device | seen once without a MAC (`ip:` key) and once with — expected for hosts that answer ping but not ARP |

## Roadmap ideas

- scheduled scans (cron/systemd timer) + alerts on new MACs
- DHCP lease log parsing for extra hostname info
- SNMP walk enrichment for managed devices
- web dashboard over the SQLite inventory

## License

Distributed under the terms of the [MIT License](LICENSE).

All third-party dependencies — including but not limited to the Python
packages declared in `pyproject.toml` (`rich`, `ieee-data`) and the external
tools lan-hunter invokes at runtime (`nmap`, `arp-scan`, `avahi-utils`,
`iproute2`, `ieee-data`) — remain subject to their own license terms, which
must be complied with independently of this project's MIT license.
