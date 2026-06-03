"""
Bounds tests for ApiCrawler: a densely cross-linked target must not recurse unboundedly.

The crawler's network boundary (requests.get) is stubbed so these run offline and let us
manufacture pathological link graphs that would loop forever without the depth/endpoint caps.
"""
from configparser import ConfigParser

from iot_tools import api_crawler
from iot_tools.api_crawler import ApiCrawler, MAX_CRAWL_DEPTH, MAX_ENDPOINTS


class _Resp:
    def __init__(self, content=b"", status_code=200, headers=None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}


class _SilentLogger:
    def info(self, *a, **k):
        pass

    def warn(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


def _crawler():
    return ApiCrawler(config=ConfigParser(), logger=_SilentLogger())


def test_crawl_depth_is_bounded(monkeypatch, tmp_path):
    # Every page links to a brand-new child, so without MAX_CRAWL_DEPTH the crawl would
    # recurse forever (and the test would hang). The cap must stop it.
    counter = {"n": 0}

    def fake_get(url, **kwargs):
        counter["n"] += 1
        return _Resp(content=f'<a href="/child{counter["n"]}">x</a>'.encode())

    monkeypatch.setattr(api_crawler.requests, "get", fake_get)

    result = _crawler().crawl(
        ip_address="192.0.2.1", port=80,
        endpoints={"/": {"num": 0, "method": "GET", "expected_status_code": 200}},
        output_path=str(tmp_path), service_version="http",
    )

    # seed + at most one fresh child per level -> bounded by the depth cap, not unbounded.
    assert len(result) <= MAX_CRAWL_DEPTH + 2
    assert counter["n"] <= MAX_CRAWL_DEPTH + 2


def test_crawl_endpoint_count_is_capped(monkeypatch, tmp_path):
    # The seed page advertises far more children than the cap; discovery must stop at
    # MAX_ENDPOINTS rather than enqueueing all of them.
    big_html = "".join(f'<a href="/p{i}">x</a>' for i in range(MAX_ENDPOINTS * 2)).encode()

    def fake_get(url, **kwargs):
        return _Resp(content=big_html if url.endswith(":80/") else b"")

    monkeypatch.setattr(api_crawler.requests, "get", fake_get)

    result = _crawler().crawl(
        ip_address="192.0.2.1", port=80,
        endpoints={"/": {"num": 0, "method": "GET", "expected_status_code": 200}},
        output_path=str(tmp_path), service_version="http",
    )

    assert len(result) <= MAX_ENDPOINTS
