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
        m.warning = MagicMock()
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


def _cmd_module(module, **overrides):
    """Helper to set all command-related attributes on a module."""
    defaults = {
        "_scan_type": "syn",
        "_port_args": ["-top-ports", "100"],
        "_rate": 1000,
        "_timeout": 5000,
        "_retries": 3,
        "_verify": True,
        "_interface": "",
        "_exclude_ports": "",
        "_host_discovery": False,
        "_passive": False,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(module, k, v)
    return module


class TestCommandConstruction:
    def test_default_syn_command(self, module):
        _cmd_module(module)
        cmd = module._build_command("/tmp/targets.txt")
        assert cmd[0] == "naabu"
        s_idx = cmd.index("-s")
        assert cmd[s_idx + 1] == "s"
        assert "-json" in cmd
        assert "-silent" in cmd
        assert "-top-ports" in cmd
        assert "100" in cmd
        assert "-rate" in cmd
        assert "1000" in cmd
        assert "-timeout" in cmd
        assert "5000" in cmd
        assert "-retries" in cmd
        assert "3" in cmd
        assert "-verify" in cmd
        assert "-l" in cmd
        assert "/tmp/targets.txt" in cmd

    def test_connect_scan(self, module):
        _cmd_module(module, _scan_type="connect", _verify=False)
        cmd = module._build_command("/tmp/targets.txt")
        s_idx = cmd.index("-s")
        assert cmd[s_idx + 1] == "c"
        assert "-verify" not in cmd

    def test_udp_scan(self, module):
        _cmd_module(module, _scan_type="udp")
        cmd = module._build_command("/tmp/targets.txt")
        s_idx = cmd.index("-s")
        assert cmd[s_idx + 1] == "u"

    def test_custom_ports(self, module):
        _cmd_module(module, _port_args=["-p", "80,443,8080"])
        cmd = module._build_command("/tmp/targets.txt")
        assert "-p" in cmd
        assert "80,443,8080" in cmd
        assert "-top-ports" not in cmd

    def test_interface_and_exclude_ports(self, module):
        _cmd_module(module, _interface="eth0", _exclude_ports="22,23")
        cmd = module._build_command("/tmp/targets.txt")
        assert "-interface" in cmd
        assert "eth0" in cmd
        assert "-exclude-ports" in cmd
        assert "22,23" in cmd

    def test_host_discovery_omits_port_args(self, module):
        _cmd_module(module, _host_discovery=True, _port_args=[], _verify=False)
        cmd = module._build_command("/tmp/targets.txt")
        assert "-sn" in cmd
        assert "-top-ports" not in cmd
        assert "-p" not in cmd

    def test_passive_mode(self, module):
        _cmd_module(module, _passive=True, _verify=False)
        cmd = module._build_command("/tmp/targets.txt")
        assert "-passive" in cmd


class TestJSONParsing:
    def test_parse_valid_line(self, module):
        line = '{"ip":"192.168.1.1","port":80}'
        result = module._parse_result(line)
        assert result == ("192.168.1.1", 80)

    def test_parse_with_host_field(self, module):
        line = '{"ip":"192.168.1.1","port":443,"host":"example.com"}'
        result = module._parse_result(line)
        assert result == ("192.168.1.1", 443)

    def test_parse_malformed_json(self, module):
        line = "not json at all"
        result = module._parse_result(line)
        assert result is None

    def test_parse_missing_port(self, module):
        line = '{"ip":"192.168.1.1"}'
        result = module._parse_result(line)
        assert result is None

    def test_parse_empty_line(self, module):
        result = module._parse_result("")
        assert result is None

    def test_parse_non_dict_json(self, module):
        result = module._parse_result('"just a string"')
        assert result is None


class TestCDNFiltering:
    def test_cdn_event_excluded(self, module, cdn_event):
        module._exclude_cdn = True
        assert module._should_exclude(cdn_event) is True

    def test_non_cdn_event_included(self, module, ip_event):
        module._exclude_cdn = True
        assert module._should_exclude(ip_event) is False

    def test_cdn_filter_disabled(self, module, cdn_event):
        module._exclude_cdn = False
        assert module._should_exclude(cdn_event) is False

    def test_cdn_tag_variants(self, module):
        module._exclude_cdn = True
        for tag in ["cdn-cloudflare", "cdn-akamai", "cdn-aws", "cdn-something"]:
            event = _make_event("IP_ADDRESS", "1.2.3.4", tags={tag})
            assert module._should_exclude(event) is True

    def test_non_cdn_tags_not_matched(self, module):
        module._exclude_cdn = True
        event = _make_event("IP_ADDRESS", "1.2.3.4", tags={"cdn", "content-delivery"})
        assert module._should_exclude(event) is False


class TestSetupHelpers:
    @pytest.mark.asyncio
    async def test_syn_requires_root(self, module):
        with patch("os.getuid", return_value=1000):
            with patch.object(module, "warning") as mock_warn:
                result = await module._do_setup("syn", "", False)
                assert result is True
                mock_warn.assert_called_once()
                assert "root" in mock_warn.call_args[0][0].lower()

    @pytest.mark.asyncio
    async def test_syn_allowed_as_root(self, module):
        with patch("os.getuid", return_value=0):
            with patch.object(module, "warning") as mock_warn:
                result = await module._do_setup("syn", "", False)
                assert result is True
                assert module._scan_type == "syn"
                mock_warn.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_no_root_needed(self, module):
        with patch("os.getuid", return_value=1000):
            with patch.object(module, "warning") as mock_warn:
                result = await module._do_setup("connect", "", False)
                assert result is True
                assert module._scan_type == "connect"
                mock_warn.assert_not_called()

    @pytest.mark.asyncio
    async def test_tunnel_fallback(self, module):
        with patch("os.getuid", return_value=0):
            with patch.object(module, "warning") as mock_warn:
                result = await module._do_setup("syn", "wg0", False)
                assert result is True
                assert module._scan_type == "connect"
                mock_warn.assert_called_once()
                assert "tunnel" in mock_warn.call_args[0][0].lower()

    @pytest.mark.asyncio
    async def test_force_scan_type_prevents_tunnel_fallback(self, module):
        with patch("os.getuid", return_value=0):
            with patch.object(module, "warning") as mock_warn:
                result = await module._do_setup("syn", "wg0", True)
                assert result is True
                assert module._scan_type == "syn"
                mock_warn.assert_not_called()

    def test_ports_override_top_ports(self, module):
        port_args = module._resolve_port_args("80,443", 100)
        assert port_args == ["-p", "80,443"]

    def test_top_ports_default(self, module):
        port_args = module._resolve_port_args("", 100)
        assert port_args == ["-top-ports", "100"]

    def test_top_ports_zero(self, module):
        port_args = module._resolve_port_args("", 0)
        assert port_args == ["-top-ports", "0"]


class TestTargetResolution:
    def test_ip_address_target(self, module):
        event = _make_event("IP_ADDRESS", "192.168.1.1")
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([event])
        assert "192.168.1.1" in targets
        parents = correlator.search("192.168.1.1")
        assert event in parents

    def test_dns_name_resolved(self, module, dns_event):
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([dns_event])
        assert "93.184.216.34" in targets
        parents = correlator.search("93.184.216.34")
        assert dns_event in parents

    def test_ip_range_expanded(self, module):
        event = _make_event("IP_RANGE", "10.0.0.0/30")
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([event])
        assert len(targets) == 4
        parents = correlator.search("10.0.0.1")
        assert event in parents

    def test_cdn_exclusion(self, module, cdn_event):
        module._exclude_cdn = True
        correlator, targets = module._resolve_targets([cdn_event])
        assert len(targets) == 0

    def test_cdn_exclusion_disabled(self, module, cdn_event):
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([cdn_event])
        assert len(targets) > 0

    def test_empty_events(self, module):
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([])
        assert len(targets) == 0

    def test_deduplication(self, module):
        e1 = _make_event("IP_ADDRESS", "192.168.1.1")
        e2 = _make_event("IP_ADDRESS", "192.168.1.1")
        module._exclude_cdn = False
        correlator, targets = module._resolve_targets([e1, e2])
        assert len(targets) == 1
        parents = correlator.search("192.168.1.1")
        assert e1 in parents
        assert e2 in parents


class TestHandleBatch:
    @pytest.mark.asyncio
    async def test_basic_scan_emits_ports(self, module, ip_event):
        module._exclude_cdn = False
        module._scan_type = "syn"
        module._build_command = MagicMock(return_value=["naabu", "-json", "-silent", "-l", "/tmp/targets"])
        module.make_event = MagicMock(side_effect=lambda d=None, t=None, **kw: MagicMock(data=d, type=t))

        async def mock_run_process(*args, **kwargs):
            yield '{"ip":"192.168.1.1","port":80}'
            yield '{"ip":"192.168.1.1","port":443}'

        module.run_process_live = mock_run_process
        await module.handle_batch(ip_event)
        assert module.emit_event.call_count == 2

    @pytest.mark.asyncio
    async def test_udp_scan_emits_udp_ports(self, module, ip_event):
        module._exclude_cdn = False
        module._scan_type = "udp"
        module._build_command = MagicMock(return_value=["naabu", "-json", "-silent", "-l", "/tmp/targets"])
        module.make_event = MagicMock(side_effect=lambda d=None, t=None, **kw: MagicMock(data=d, type=t))

        async def mock_run_process(*args, **kwargs):
            yield '{"ip":"192.168.1.1","port":53}'

        module.run_process_live = mock_run_process
        await module.handle_batch(ip_event)
        call_kwargs = module.make_event.call_args[1]
        assert call_kwargs["event_type"] == "OPEN_UDP_PORT"

    @pytest.mark.asyncio
    async def test_empty_targets_no_scan(self, module, cdn_event):
        module._exclude_cdn = True
        module.run_process_live = MagicMock()
        await module.handle_batch(cdn_event)
        module.run_process_live.assert_not_called()

    @pytest.mark.asyncio
    async def test_malformed_json_skipped(self, module, ip_event):
        module._exclude_cdn = False
        module._scan_type = "syn"
        module._build_command = MagicMock(return_value=["naabu", "-json", "-silent", "-l", "/tmp/targets"])
        module.make_event = MagicMock(side_effect=lambda d=None, t=None, **kw: MagicMock(data=d, type=t))

        async def mock_run_process(*args, **kwargs):
            yield '{"ip":"192.168.1.1","port":80}'
            yield "not valid json"
            yield '{"ip":"192.168.1.1","port":443}'

        module.run_process_live = mock_run_process
        await module.handle_batch(ip_event)
        assert module.emit_event.call_count == 2

    @pytest.mark.asyncio
    async def test_process_failure_sets_error(self, module, ip_event):
        module._exclude_cdn = False
        module._build_command = MagicMock(return_value=["naabu", "-json", "-silent", "-l", "/tmp/targets"])

        async def mock_run_process(*args, **kwargs):
            raise Exception("naabu crashed")
            yield  # noqa: unreachable — makes this an async generator

        module.run_process_live = mock_run_process
        await module.handle_batch(ip_event)
        module.set_error_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_dns_name_event_uses_hostname(self, module, dns_event):
        module._exclude_cdn = False
        module._scan_type = "syn"
        module._build_command = MagicMock(return_value=["naabu", "-json", "-silent", "-l", "/tmp/targets"])
        module.make_event = MagicMock(side_effect=lambda d=None, t=None, **kw: MagicMock(data=d, type=t))

        async def mock_run_process(*args, **kwargs):
            yield '{"ip":"93.184.216.34","port":80}'

        module.run_process_live = mock_run_process
        await module.handle_batch(dns_event)
        call_kwargs = module.make_event.call_args[1]
        assert "example.com:80" == call_kwargs["data"]


class TestFullSetup:
    @pytest.mark.asyncio
    async def test_setup_initializes_all_attributes(self, module):
        module.config = {
            "scan_type": "syn",
            "top_ports": 100,
            "ports": "",
            "rate": 1000,
            "timeout": 5000,
            "retries": 3,
            "verify": True,
            "exclude_cdn": True,
            "interface": "",
            "exclude_ports": "",
            "host_discovery": False,
            "passive": False,
            "force_scan_type": False,
        }
        with patch("os.getuid", return_value=1000):
            result = await module.setup()
        assert result is True
        assert module._scan_type == "connect"
        assert module._exclude_cdn is True
        assert module._rate == 1000
        assert module._timeout == 5000
        assert module._retries == 3
        assert module._verify is True
        assert module._interface == ""
        assert module._exclude_ports == ""
        assert module._host_discovery is False
        assert module._passive is False
        assert module._port_args == ["-top-ports", "100"]
        assert module._temp_files == []

    @pytest.mark.asyncio
    async def test_setup_with_custom_ports(self, module):
        module.config = {
            "scan_type": "connect",
            "top_ports": 1000,
            "ports": "80,443",
            "rate": 500,
            "timeout": 3000,
            "retries": 2,
            "verify": False,
            "exclude_cdn": False,
            "interface": "eth0",
            "exclude_ports": "22",
            "host_discovery": False,
            "passive": False,
            "force_scan_type": False,
        }
        result = await module.setup()
        assert result is True
        assert module._scan_type == "connect"
        assert module._port_args == ["-p", "80,443"]
        assert module._rate == 500
        assert module._interface == "eth0"
        assert module._exclude_ports == "22"
        assert module._exclude_cdn is False

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_files(self, module):
        temp = MagicMock()
        module._temp_files = [temp]
        await module.cleanup()
        temp.unlink.assert_called_once_with(missing_ok=True)

    @pytest.mark.asyncio
    async def test_cleanup_handles_unlink_error(self, module):
        temp = MagicMock()
        temp.unlink.side_effect = OSError("permission denied")
        module._temp_files = [temp]
        await module.cleanup()
        temp.unlink.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_empty_list(self, module):
        module._temp_files = []
        await module.cleanup()


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_scan_flow(self):
        with patch("naabu.naabu.__init__", return_value=None):
            m = NaabuModule()

        mock_helpers = MagicMock()
        mock_helpers.tempfile = MagicMock(return_value="/tmp/test_integration_targets")
        mock_helpers.make_netloc = lambda host, port: f"{host}:{port}"
        mock_log = MagicMock()
        m.make_event = MagicMock(side_effect=lambda d=None, t=None, **kw: MagicMock(data=d, type=t))
        m.emit_event = AsyncMock()
        m.warning = MagicMock()
        m.debug = MagicMock()
        m.set_error_state = MagicMock()
        m._temp_files = []

        test_config = {
            "scan_type": "connect",
            "top_ports": 100,
            "ports": "80,443",
            "rate": 500,
            "timeout": 3000,
            "retries": 2,
            "verify": False,
            "exclude_cdn": True,
            "interface": "",
            "exclude_ports": "",
            "host_discovery": False,
            "passive": False,
            "force_scan_type": False,
        }

        patches = [
            patch.object(type(m), "helpers", new_callable=lambda: property(lambda self: mock_helpers)),
            patch.object(type(m), "log", mock_log),
            patch.object(type(m), "config", test_config),
        ]
        for p in patches:
            p.start()
        try:
            result = await m.setup()
            assert result is True
            assert m._scan_type == "connect"
            assert m._port_args == ["-p", "80,443"]

            events = [
                _make_event("IP_ADDRESS", "10.0.0.1"),
                _make_event("DNS_NAME", "example.com", resolved_hosts=["93.184.216.34"]),
                _make_event("IP_ADDRESS", "104.16.0.1", tags={"cdn-cloudflare"}),
            ]

            async def mock_run_process(*args, **kwargs):
                yield '{"ip":"10.0.0.1","port":80}'
                yield '{"ip":"93.184.216.34","port":443}'

            m.run_process_live = mock_run_process
            await m.handle_batch(*events)

            assert m.emit_event.call_count == 2
            emitted_data = [call[1].get("data") or call[0][0] for call in m.make_event.call_args_list]
            assert "10.0.0.1:80" in emitted_data
            assert "example.com:443" in emitted_data

            await m.cleanup()
        finally:
            for p in patches:
                p.stop()
