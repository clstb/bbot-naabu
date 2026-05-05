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
    with patch("naabu.naabu.__init__", return_value=None):
        m = NaabuModule()
    m.helpers = MagicMock()
    m.helpers.tempfile = MagicMock(side_effect=lambda targets, **kw: f"/tmp/test_targets_{id(targets)}")
    m.helpers.make_netloc = lambda host, port: f"{host}:{port}"
    m.helpers.depsinstaller = MagicMock()
    m.make_event = MagicMock()
    m.emit_event = AsyncMock()
    m.run_process_live = MagicMock()
    m.log = MagicMock()
    m.warning = MagicMock()
    m.debug = MagicMock()
    m.set_error_state = MagicMock()
    m.config = {}
    m._temp_files = []
    return m


@pytest.fixture
def ip_event():
    return _make_event("IP_ADDRESS", "192.168.1.1")


@pytest.fixture
def dns_event():
    return _make_event("DNS_NAME", "example.com", resolved_hosts=["93.184.216.34"])


@pytest.fixture
def cdn_event():
    return _make_event("IP_ADDRESS", "104.16.0.1", tags={"cdn-cloudflare"})
