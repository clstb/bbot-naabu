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

    async def setup(self):
        return True

    async def handle_batch(self, *events):
        pass

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
        pass
