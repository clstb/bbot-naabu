# BBOT Naabu Module Design

## Overview

A BBOT scan module that integrates [Naabu](https://github.com/projectdiscovery/naabu) (ProjectDiscovery's fast port scanner) as an alternative to BBOT's built-in masscan-based `portscan` module. The module supports TCP SYN, TCP CONNECT, and UDP scanning modes with auto-detection and fallback for tunnel interfaces (WireGuard/TUN/TAP).

## Architecture

**Class**: `naabu` (extends `bbot.modules.base.BaseModule`)
**Module type**: `scan`
**Flags**: `["active", "portscan", "safe"]`

### Event Flow

```
IP_ADDRESS / IP_RANGE / DNS_NAME  (watched_events)
    → naabu module (batch accumulation via handle_batch)
    → OPEN_TCP_PORT / OPEN_UDP_PORT  (produced_events)
    → cloudcheck intercept module (auto-tags CDN/cloud)
    → portfilter intercept module (drops non-80/443 CDN ports)
```

### Pre-scan CDN Exclusion

Unlike the existing masscan `portscan` module (which scans everything and relies on post-scan filtering), this module offers an optional pre-scan CDN exclusion. Before invoking naabu, incoming events are checked for CDN/cloud tags already applied by BBOT's `cloudcheck` intercept module on `IP_ADDRESS` and `DNS_NAME` events. Tagged hosts are excluded from the scan target list, saving bandwidth. Controlled by the `exclude_cdn` option (default: `True`).

### Batch Processing

Events accumulate in a large batch (`batch_size = 1000000`) before a single naabu invocation. Targets are deduplicated via `RadixTarget` for IP-to-event correlation, ensuring emitted port events have correct parentage.

## Module Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scan_type` | str | `"syn"` | Scan type: `"syn"` (needs root), `"connect"` (no root), or `"udp"` |
| `top_ports` | int | `100` | Top N ports to scan (e.g., 100, 1000) |
| `ports` | str | `""` | Specific ports/ranges (e.g., "80,443,100-200"). Overrides `top_ports` when set |
| `rate` | int | `1000` | Packets per second |
| `timeout` | int | `5000` | Probe timeout in milliseconds |
| `retries` | int | `3` | Number of retries per probe |
| `verify` | bool | `True` | Verify open ports with a TCP connection |
| `exclude_cdn` | bool | `True` | Pre-filter CDN/cloud hosts by checking event tags before scanning |
| `stream` | bool | `False` | Stream mode — scan targets one-by-one instead of batching (slower, lower memory) |
| `host_discovery` | bool | `False` | Host discovery only — determine if hosts are up without scanning ports |
| `passive` | bool | `False` | Passive mode — rely on SYN-ACK responses without sending probes |
| `interface` | str | `""` | Network interface to use (e.g., eth0, wg0) |
| `exclude_ports` | str | `""` | Ports to exclude from scanning (e.g., "22,23") |
| `force_scan_type` | bool | `False` | Override automatic scan_type fallback (e.g., allow SYN on tunnel interfaces) |

## Dependencies

### Binary (auto-installed via `deps_ansible`)

Naabu binary downloaded from GitHub releases, matching OS platform and CPU architecture. Template variables used:

- `#{BBOT_OS_PLATFORM}` — linux, darwin
- `#{BBOT_CPU_ARCH_GOLANG}` — amd64, arm64
- `#{BBOT_TOOLS}` — BBOT tools directory
- `#{BBOT_MODULES_NAABU_VERSION}` — module version for release URL

### APT

- `libpcap-dev` — required for SYN scan mode (raw packet capture)

## Core Logic

### `setup()`

1. Check root privileges if `scan_type` is `"syn"` — fall back to `"connect"` with warning if not root
2. If `interface` is specified and `scan_type` is `"syn"`, check if interface is a tunnel (name matches `wg*`, `tun*`, `tap*`, `utun*`, or `tailscale*` pattern). If tunnel detected and `force_scan_type` is `False`, fall back to `"connect"` with warning
3. Validate options: if `ports` is set, use it instead of `top_ports`; warn if both are set
4. Naabu binary availability is handled by BBOT's dependency system (`deps_ansible`)
5. Verify naabu is working with a test invocation

### `handle_batch(*events)`

1. **Resolve events**: Convert `DNS_NAME` events to IPs via `event.resolved_hosts`. Collect `IP_ADDRESS` and `IP_RANGE` events. Expand `IP_RANGE` to individual IPs.
2. **CDN pre-filter**: If `exclude_cdn` is `True`, skip events where any tag starts with `"cdn-"`.
3. **Deduplicate**: Use `RadixTarget` from `radixtarget` package to map IPs to parent events and deduplicate.
4. **Write targets**: Write deduplicated IPs to a temp file via `self.helpers.tempfile()`.
5. **Build naabu command**: Construct CLI arguments from module options.
6. **Execute**: Run naabu via `self.run_process_live()` with `-json` and `-silent` flags. Parse JSON output line by line.
7. **Emit events**: For each `{"ip": "...", "port": N}` result, look up the parent event via `RadixTarget`, construct a host:port string, and emit `OPEN_TCP_PORT` or `OPEN_UDP_PORT` (depending on `scan_type`).

### `cleanup()`

Remove any temp files created during scanning.

### Tunnel Interface Detection

```python
TUNNEL_INTERFACE_PREFIXES = ("wg", "tun", "tap", "utun", "tailscale")
```

If the specified interface name starts with any of these prefixes, and `scan_type` is `"syn"`, and `force_scan_type` is `False`, the module falls back to `"connect"` mode and logs a warning explaining why.

## Error Handling

- **Naabu process failure**: Log error via `self.set_error_state()`, return without emitting events. Scan continues.
- **Malformed JSON output**: Skip bad lines, log warning at debug level.
- **Empty target list**: Return silently (nothing to scan).
- **Permission errors**: Caught in `setup()`, fall back to connect mode or disable module.
- **Temp file errors**: Caught and logged, scan continues without crashing.

## File Structure

```
bbot-naabu/
├── naabu.py               # The BBOT module (single file)
├── test_naabu.py          # Unit/integration tests
└── docs/
    └── superpowers/
        └── specs/
            └── 2026-05-04-naabu-module-design.md  # This file
```

Single-file module, consistent with BBOT's convention where each module is a single `.py` file.

## Testing Strategy

- **Command construction tests**: Verify naabu CLI args are built correctly from various option combinations
- **JSON output parsing tests**: Parse naabu's JSON format `{"ip":"x.x.x.x","port":N}` including edge cases
- **Tunnel detection tests**: Verify SYN-to-CONNECT fallback for `wg0`, `tun0`, `tap0`, etc.
- **CDN filtering tests**: Verify events with `cdn-*` tags are excluded when `exclude_cdn=True`
- **Integration test**: Mock naabu subprocess, feed known targets, verify correct `OPEN_TCP_PORT`/`OPEN_UDP_PORT` events are emitted with correct parents

## Naabu CLI Reference (Module's Command Construction)

Base command: `naabu -json -silent -l <targets_file>`

| Module Option | Naabu Flag | Notes |
|---------------|-----------|-------|
| `scan_type=syn` | `-s s` | Default |
| `scan_type=connect` | `-s c` | |
| `scan_type=udp` | `-s u` | |
| `top_ports` | `-top-ports N` | Only if `ports` is not set |
| `ports` | `-p PORTS` | |
| `rate` | `-rate N` | |
| `timeout` | `-timeout N` | |
| `retries` | `-retries N` | |
| `verify=True` | `-verify` | |
| `interface` | `-interface IFACE` | |
| `exclude_ports` | `-exclude-ports PORTS` | |
| `host_discovery=True` | `-sn` | |
| `passive=True` | `-passive` | |
| (always) | `-silent` | Suppress non-JSON output |
| (always) | `-json` | JSON output for parsing |
| (always) | `-l <file>` | Target list from temp file |
