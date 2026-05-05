import asyncio
import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naabu import naabu as NaabuModule


def _make_event(event_type, data, host=None, tags=None, resolved_hosts=None):
    event = MagicMock()
    event.type = event_type
    event.data = data
    event.host = host or data
    event.tags = set(tags) if tags else set()
    event.resolved_hosts = resolved_hosts or []
    return event


@pytest.fixture
def module():
    mock_helpers = MagicMock()
    mock_helpers.tempfile = MagicMock(side_effect=lambda targets, **kw: f"/tmp/test_targets_{id(targets)}")
    mock_helpers.make_netloc = lambda host, port: f"{host}:{port}"
    mock_helpers.depsinstaller = MagicMock()
    mock_log = MagicMock()
    with patch("naabu.naabu.__init__", return_value=None):
        m = NaabuModule()
    # Patch read-only properties from BaseModule
    patches = [
        patch.object(type(m), "helpers", new_callable=lambda: property(lambda self: mock_helpers)),
        patch.object(type(m), "log", mock_log),
        patch.object(type(m), "config", {}),
    ]
    for p in patches:
        p.start()
    try:
        m.make_event = MagicMock()
        m.emit_event = AsyncMock()
        m.run_process_live = MagicMock()
        m.set_error_state = MagicMock()
        m._temp_files = []
        yield m
    finally:
        for p in patches:
            p.stop()


@pytest.fixture
def ip_event():
    return _make_event("IP_ADDRESS", "192.168.1.1")


@pytest.fixture
def dns_event():
    return _make_event("DNS_NAME", "example.com", resolved_hosts=["93.184.216.34"])


@pytest.fixture
def cdn_event():
    return _make_event("IP_ADDRESS", "104.16.0.1", tags={"cdn-cloudflare"})


class TestTunnelDetection:
    @pytest.mark.parametrize("iface", ["wg0", "tun0", "tap0", "utun0", "tailscale0", "wg1", "tun42"])
    def test_tunnel_interfaces_detected(self, module, iface):
        assert module._is_tunnel_interface(iface) is True

    @pytest.mark.parametrize("iface", ["eth0", "ens192", "lo", "docker0", "br0", "wlan0"])
    def test_non_tunnel_interfaces(self, module, iface):
        assert module._is_tunnel_interface(iface) is False

    def test_empty_interface(self, module):
        assert module._is_tunnel_interface("") is False

    def test_none_interface(self, module):
        assert module._is_tunnel_interface(None) is False
