"""
Tests for PortScan's structured-output parsers.

The fixtures in ``fixtures/`` are real tool output captured from the Nmap-sanctioned
scan target ``scanme.nmap.org`` (45.33.32.156):

* ``nmap_scanme.xml``    -- nmap ``-sV --script=banner -oX``
* ``masscan_scanme.json`` -- masscan ``-oJ``

so these tests pin the parsers against genuine output, not hand-rolled approximations.
"""
import os
from configparser import ConfigParser

import pytest

from iot_tools.port_scan import PortScan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
NMAP_XML = os.path.join(FIXTURES, "nmap_scanme.xml")
MASSCAN_JSON = os.path.join(FIXTURES, "masscan_scanme.json")


class RecordingLogger:
    """Minimal stand-in for SofahLogger that records warnings for assertions."""

    def __init__(self):
        self.warnings = []

    def info(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        self.warnings.append((args, kwargs))

    def error(self, *args, **kwargs):
        pass


@pytest.fixture
def port_scan():
    config = ConfigParser()
    config.add_section("Masscan")
    config.set("Masscan", "rate", "1000")
    return PortScan(config=config, logger=RecordingLogger())


# --------------------------------------------------------------------------- #
# nmap -oX parser
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "port, service, mode, banner",
    [
        (22, "ssh", "b", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"),  # raw banner script
        (80, "http", "h", "Apache/2.4.7 (Ubuntu)"),                       # http-server-header
    ],
)
def test_nmap_xml_service_and_banner(port_scan, port, service, mode, banner):
    service_version, found = port_scan._parse_nmap_xml(NMAP_XML, port)
    assert service_version == service
    assert found[0] == mode
    assert found[1:] == banner


def test_nmap_xml_binary_banner_uses_b_mode(port_scan):
    service_version, banner = port_scan._parse_nmap_xml(NMAP_XML, 9929)
    assert service_version == "nping-echo"
    assert banner[0] == "b"


def test_nmap_xml_tcpwrapped_has_no_banner(port_scan):
    service_version, banner = port_scan._parse_nmap_xml(NMAP_XML, 31337)
    assert service_version == "tcpwrapped"
    assert banner is None


def test_nmap_xml_ssl_tunnel_is_prefixed(port_scan, tmp_path):
    # No live HTTPS service in the fixture, so pin the tunnel-prefix behaviour with a
    # crafted snippet matching nmap's documented XML schema (service tunnel="ssl").
    xml = tmp_path / "ssl.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="http" product="nginx" tunnel="ssl"/>'
        '<script id="http-server-header" output="nginx/1.18.0"/></port>'
        "</ports></host></nmaprun>"
    )
    service_version, banner = port_scan._parse_nmap_xml(str(xml), 443)
    assert service_version == "ssl/http"  # downstream `"ssl" in service_version` then fires
    assert banner == "hnginx/1.18.0"


def test_nmap_xml_unknown_port_returns_none(port_scan):
    assert port_scan._parse_nmap_xml(NMAP_XML, 65000) == (None, None)


# --------------------------------------------------------------------------- #
# masscan -oJ parser
# --------------------------------------------------------------------------- #

def test_masscan_real_fixture(port_scan):
    result = port_scan._parse_masscan_output(MASSCAN_JSON)
    assert set(result) == {"45.33.32.156"}
    ports = result["45.33.32.156"]
    assert set(ports) == {22, 80, 9929, 31337}
    assert all(isinstance(key, int) for key in ports)
    assert ports[22] == {"protocol": "tcp", "timestamp": "1780301509"}


def test_masscan_tolerates_trailing_comma(port_scan):
    # Some masscan builds leave a trailing comma before the closing bracket (invalid JSON).
    raw = '[\n{ "ip":"1.2.3.4","timestamp":"9","ports":[{"port":443,"proto":"tcp","status":"open"}] }\n,\n]'
    records = port_scan._load_masscan_json(raw)
    assert len(records) == 1
    assert records[0]["ip"] == "1.2.3.4"


def test_masscan_filters_non_open_ports(port_scan, tmp_path):
    path = tmp_path / "m.json"
    path.write_text(
        '[{"ip":"5.5.5.5","timestamp":"1","ports":['
        '{"port":1,"proto":"tcp","status":"closed"},'
        '{"port":2,"proto":"tcp","status":"open"}]}]'
    )
    result = port_scan._parse_masscan_output(str(path))
    assert result == {"5.5.5.5": {2: {"protocol": "tcp", "timestamp": "1"}}}


def test_masscan_empty_output_warns(port_scan, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("")
    result = port_scan._parse_masscan_output(str(path))
    assert result == {}
    assert port_scan.log.warnings  # an empty scan result is logged as a warning


# --------------------------------------------------------------------------- #
# masscan -> nmap composition
# --------------------------------------------------------------------------- #

def test_masscan_then_nmap_pipeline(port_scan):
    masscan_result = port_scan._parse_masscan_output(MASSCAN_JSON)
    # Stub only the subprocess boundary; reuse the real nmap XML fixture for enrichment.
    port_scan._nmap = lambda ip_address, port: port_scan._parse_nmap_xml(NMAP_XML, port)
    enriched = port_scan._nmap_runner(masscan_result)

    row = enriched["45.33.32.156"]
    assert row[22]["service_version"] == "ssh"
    assert row[22]["mode"] == "banner"
    assert row[80]["service_version"] == "http"
    assert row[80]["mode"] == "http-header"
    assert row[9929]["mode"] == "banner"
    assert "mode" not in row[31337]  # tcpwrapped: no banner, no spoof mode
    # masscan-origin fields survive enrichment
    assert row[22]["protocol"] == "tcp"
    assert row[22]["timestamp"] == "1780301509"
