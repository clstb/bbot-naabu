import json
import os
import ipaddress
import subprocess

from bbot.modules.base import BaseModule
from radixtarget import RadixTarget, host_size_key


class naabu(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS", "IP_RANGE", "DNS_NAME"]
    produced_events = ["OPEN_TCP_PORT", "OPEN_UDP_PORT"]
    batch_size = 1000000
    _shuffle_incoming_queue = False

    meta = {
        "description": "Port scan with naabu. By default, scans top 100 ports using SYN scan.",
        "created_date": "2026-05-04",
        "author": "@user",
    }

    options = {
        "version": "2.3.2",
        "scan_type": "syn",
        "top_ports": 100,
        "ports": "",
        "rate": 1000,
        "timeout": 5000,
        "retries": 3,
        "verify": True,
        "exclude_cdn": True,
        "stream": False,
        "host_discovery": False,
        "passive": False,
        "interface": "",
        "exclude_ports": "",
        "force_scan_type": False,
    }

    options_desc = {
        "version": "Naabu version to download",
        "scan_type": "Scan type: syn (needs root), connect, or udp",
        "top_ports": "Top N ports to scan (e.g., 100, 1000)",
        "ports": "Specific ports/ranges (e.g., '80,443,100-200'). Overrides top_ports",
        "rate": "Packets per second",
        "timeout": "Probe timeout in milliseconds",
        "retries": "Number of retries per probe",
        "verify": "Verify open ports with a TCP connection",
        "exclude_cdn": "Pre-filter CDN/cloud hosts by checking event tags",
        "stream": "Stream mode — scan targets one-by-one",
        "host_discovery": "Host discovery only — determine if hosts are up",
        "passive": "Passive mode — rely on SYN-ACK responses",
        "interface": "Network interface to use (e.g., eth0, wg0)",
        "exclude_ports": "Ports to exclude (e.g., '22,23')",
        "force_scan_type": "Override automatic scan_type fallback",
    }

    deps_ansible = [
        {
            "name": "Download naabu",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/naabu/releases/download/v#{BBOT_MODULES_NAABU_VERSION}/naabu_#{BBOT_MODULES_NAABU_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "naabu",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
        {
            "name": "Install libpcap-dev for SYN scan",
            "package": {
                "name": "libpcap-dev",
                "state": "present",
            },
            "become": True,
            "ignore_errors": True,
        },
    ]

    TUNNEL_INTERFACE_PREFIXES = ("wg", "tun", "tap", "utun", "tailscale")

    SCAN_TYPE_MAP = {
        "syn": "s",
        "connect": "c",
        "udp": "u",
    }

    def _is_tunnel_interface(self, interface):
        if not interface:
            return False
        return interface.startswith(self.TUNNEL_INTERFACE_PREFIXES)

    def _should_exclude(self, event):
        if not self._exclude_cdn:
            return False
        return any(tag.startswith("cdn-") for tag in event.tags)

    def _resolve_targets(self, events):
        correlator = RadixTarget()
        targets = set()
        for event in sorted(events, key=lambda e: host_size_key(e.host)):
            if self._should_exclude(event):
                continue
            ips = set()
            if event.type == "IP_RANGE":
                try:
                    network = ipaddress.ip_network(event.host, strict=False)
                    for ip in network:
                        ips.add(str(ip))
                except ValueError:
                    pass
            elif event.type == "IP_ADDRESS":
                try:
                    ipaddress.ip_address(event.host)
                    ips.add(event.host)
                except ValueError:
                    pass
            elif event.type == "DNS_NAME":
                for h in event.resolved_hosts:
                    try:
                        ipaddress.ip_address(h)
                        ips.add(h)
                    except ValueError:
                        continue
            for ip in ips:
                existing = correlator.search(ip)
                if existing is None:
                    correlator.insert(ip, {event})
                else:
                    existing.add(event)
                targets.add(ip)
        return correlator, targets

    def _build_command(self, target_file):
        cmd = ["naabu", "-json", "-silent"]
        cmd.extend(["-s", self.SCAN_TYPE_MAP[self._scan_type]])
        if self._host_discovery:
            cmd.append("-sn")
        else:
            cmd.extend(self._port_args)
        cmd.extend(["-rate", str(self._rate)])
        cmd.extend(["-timeout", str(self._timeout)])
        cmd.extend(["-retries", str(self._retries)])
        if self._verify:
            cmd.append("-verify")
        if self._interface:
            cmd.extend(["-interface", self._interface])
        if self._exclude_ports:
            cmd.extend(["-exclude-ports", self._exclude_ports])
        if self._passive:
            cmd.append("-passive")
        cmd.extend(["-l", target_file])
        return cmd

    @staticmethod
    def _resolve_port_args(ports, top_ports):
        if ports:
            return ["-p", ports]
        return ["-top-ports", str(top_ports)]

    async def _do_setup(self, scan_type, interface, force_scan_type):
        if scan_type == "syn" and os.getuid() != 0:
            self.warning("SYN scan requires root privileges, falling back to connect scan")
            scan_type = "connect"
        if scan_type == "syn" and interface and self._is_tunnel_interface(interface) and not force_scan_type:
            self.warning(
                f"Interface {interface} appears to be a tunnel; "
                f"SYN scans are unreliable on tunnels, falling back to connect scan"
            )
            scan_type = "connect"
        self._scan_type = scan_type
        return True

    async def setup(self):
        scan_type = self.config.get("scan_type", "syn")
        top_ports = self.config.get("top_ports", 100)
        ports = self.config.get("ports", "")
        self._rate = self.config.get("rate", 1000)
        self._timeout = self.config.get("timeout", 5000)
        self._retries = self.config.get("retries", 3)
        self._verify = self.config.get("verify", True)
        self._exclude_cdn = self.config.get("exclude_cdn", True)
        interface = self.config.get("interface", "")
        self._exclude_ports = self.config.get("exclude_ports", "")
        self._host_discovery = self.config.get("host_discovery", False)
        self._passive = self.config.get("passive", False)
        force_scan_type = self.config.get("force_scan_type", False)

        if ports and top_ports != 100:
            self.warning("Both 'ports' and 'top_ports' are set; 'ports' takes precedence")

        self._port_args = self._resolve_port_args(ports, top_ports)
        self._interface = interface
        self._temp_files = []

        return await self._do_setup(scan_type, interface, force_scan_type)

    async def handle_batch(self, *events):
        correlator, targets = self._resolve_targets(events)
        if not targets:
            return

        target_file = self.helpers.tempfile(sorted(targets), pipe=False)
        self._temp_files.append(target_file)
        command = self._build_command(target_file)

        try:
            async for line in self.run_process_live(command, stderr=subprocess.DEVNULL):
                result = self._parse_result(line)
                if result is None:
                    continue
                ip, port = result
                parent_events = correlator.search(ip)
                if parent_events is None:
                    continue
                emitted_hosts = set()
                for parent_event in parent_events:
                    host = parent_event.host if parent_event.type == "DNS_NAME" else ip
                    if host not in emitted_hosts:
                        event_data = self.helpers.make_netloc(host, port)
                        event_type = "OPEN_UDP_PORT" if self._scan_type == "udp" else "OPEN_TCP_PORT"
                        evt = self.make_event(
                            data=event_data,
                            event_type=event_type,
                            parent=parent_event,
                            context=f"{{module}} executed a {self._scan_type} scan against {parent_event.data} and found: {{event.type}}: {{event.data}}",
                        )
                        await self.emit_event(evt)
                        emitted_hosts.add(host)
        except Exception as e:
            self.set_error_state(f"naabu scan failed: {e}")

    @staticmethod
    def _parse_result(line):
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        ip = data.get("ip")
        port = data.get("port")
        if ip is None or port is None:
            return None
        return (ip, port)

    async def cleanup(self):
        for f in self._temp_files:
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
