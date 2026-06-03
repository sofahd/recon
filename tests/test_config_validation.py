"""
Tests for IotRecon._validate_config -- the startup self-check that a stub or malformed
config fails loudly (naming every missing entry) instead of raising a confusing
NoSectionError partway through a scan.
"""
from configparser import ConfigParser

import pytest

from sofahutils import InvalidConfigException
from iot_recon import IotRecon


def _cfg(sections):
    cfg = ConfigParser()
    for section, options in sections.items():
        cfg.add_section(section)
        for key, value in options.items():
            cfg.set(section, key, value)
    return cfg


def _recon_with(cfg):
    # Bypass __init__, which builds a network-connected SofahLogger; we only exercise the
    # pure config validator here.
    recon = IotRecon.__new__(IotRecon)
    recon.config = cfg
    return recon


def test_validate_config_passes_on_complete_config():
    cfg = _cfg({
        "Masscan": {"rate": "1000"},
        "Scan": {"ip_addresses": "['0.0.0.0']", "crawl_ports": "[80]", "excl_ports": "[]"},
        "Utils": {"api_list": "['https://api.ipify.org/']"},
    })
    _recon_with(cfg)._validate_config()  # must not raise


def test_validate_config_reports_all_missing_entries():
    cfg = _cfg({"Masscan": {"rate": "1000"}})  # Scan.* and Utils.api_list absent
    with pytest.raises(InvalidConfigException) as excinfo:
        _recon_with(cfg)._validate_config()

    message = str(excinfo.value)
    # every miss is named in one error, not just the first
    assert "[Scan] ip_addresses" in message
    assert "[Scan] crawl_ports" in message
    assert "[Scan] excl_ports" in message
    assert "[Utils] api_list" in message
