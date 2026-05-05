# bbot-naabu

A [BBOT](https://github.com/blacklanternsecurity/bbot) scan module that integrates [Naabu](https://github.com/projectdiscovery/naabu) (ProjectDiscovery's fast port scanner).

## Features

- **TCP SYN scan** (default, requires root) with automatic fallback to connect scan
- **TCP connect scan** for unprivileged environments
- **UDP scan** support
- **CDN pre-filtering** — skips hosts already tagged as CDN/cloud by BBOT's `cloudcheck` module
- **Tunnel detection** — automatically falls back from SYN to connect on WireGuard/TUN/TAP interfaces
- **Batch processing** — accumulates up to 1M targets before a single naabu invocation
- **RadixTarget correlation** — emitted port events maintain correct parentage via IP-to-event radix tree

## Installation

```bash
pip install bbot-naabu
```

## Usage

```bash
# Default: top 100 ports, SYN scan
bbot -m naabu example.com

# Specific ports, connect scan
bbot -m naabu -o scan_type=connect -o ports=80,443,8080 example.com

# Top 1000 ports, custom rate
bbot -m naabu -o top_ports=1000 -o rate=5000 10.0.0.0/24

# UDP scan
bbot -m naabu -o scan_type=udp -o ports=53,123,161 target.example.com

# Disable CDN filtering, scan a CDN host
bbot -m naabu -o exclude_cdn=false cdn-host.example.com
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `scan_type` | `syn` | Scan type: `syn` (root), `connect`, or `udp` |
| `top_ports` | `100` | Top N ports to scan (min 100) |
| `ports` | `""` | Specific ports/ranges, e.g. `80,443,100-200` (overrides `top_ports`) |
| `rate` | `1000` | Packets per second |
| `timeout` | `5000` | Probe timeout in milliseconds |
| `retries` | `3` | Retries per probe |
| `verify` | `True` | Verify open ports with a TCP connection |
| `exclude_cdn` | `True` | Skip hosts tagged as CDN/cloud |
| `host_discovery` | `False` | Host discovery only (no port scan) |
| `passive` | `False` | Rely on SYN-ACK responses |
| `interface` | `""` | Network interface to bind |
| `exclude_ports` | `""` | Ports to exclude, e.g. `22,23` |
| `force_scan_type` | `False` | Prevent automatic SYN-to-connect fallback |
| `version` | `2.3.2` | Naabu binary version to download |

## Testing

### Unit tests

Unit tests mock the BBOT framework and naabu subprocess — no network or root required.

```bash
pip install -e ".[dev]"
pytest test_naabu.py -v
```

### Live integration test

Scan a real target to verify the module end-to-end. Requires network access; naabu binary is auto-installed on first run.

```bash
bbot -t scanme.nmap.org -m naabu -o ports=22,80,443 -o scan_type=connect
```

Expected: `OPEN_TCP_PORT` events for ports 22 and 80 on `scanme.nmap.org`.

## Development

```bash
pip install -e ".[dev]"
pytest test_naabu.py -v
```
