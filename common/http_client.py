"""
Shared HTTP client utilities for SecurityNexus modules.

Provides a hardened requests.Session with:
- Optional proxy support (env SECURITYNEXUS_PROXY or argument)
- Retry/backoff handling for flaky endpoints
- Default headers and user-agent management
- TLS verification toggling with warning suppression when disabled
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

DEFAULT_USER_AGENT = (
    "SecurityNexus/5.0 (+https://github.com/faizan/securitynexus)"
)


def _parse_extra_headers(raw: Optional[str]) -> Dict[str, str]:
    """
    Parse extra headers supplied via env (JSON or key:value;key2:value2).
    """
    if not raw:
        return {}

    # Try JSON first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    except json.JSONDecodeError:
        pass

    # Fallback to semi-colon separated key:value pairs
    headers: Dict[str, str] = {}
    for part in raw.split(";"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_session(
    timeout: int = 10,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = False,
    retries: int = 2,
    backoff_factor: float = 0.4,
) -> requests.Session:
    """
    Build a requests.Session with sane defaults for scanning.
    """
    session = requests.Session()

    resolved_proxy = proxy or os.getenv("SECURITYNEXUS_PROXY")
    if resolved_proxy:
        session.proxies.update({"http": resolved_proxy, "https": resolved_proxy})

    ua = user_agent or os.getenv("SECURITYNEXUS_UA") or DEFAULT_USER_AGENT
    session.headers.update(
        {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    )

    extra_headers = {}
    extra_headers.update(headers or {})
    extra_headers.update(_parse_extra_headers(os.getenv("SECURITYNEXUS_HEADERS")))
    if extra_headers:
        session.headers.update(extra_headers)

    if not verify:
        session.verify = False
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["HEAD", "GET", "OPTIONS", "POST"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Provide a default timeout if caller forgets
    _request = session.request

    def _request_with_timeout(method: str, url: str, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return _request(method, url, **kwargs)

    session.request = _request_with_timeout  # type: ignore[assignment]

    return session

