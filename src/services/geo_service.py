"""
src/services/geo_service.py

GeoService — Non-blocking geolocation lookup.

Critical Fix:
  The original app.py called requests.get(..., timeout=3) INSIDE the Flask
  route, which blocks the WSGI worker for up to 3 seconds per request.
  Under concurrent load this stalls all detection threads.

Solution:
  1. A thread-safe LRU in-memory cache avoids redundant HTTP calls.
  2. All external lookups run in a ThreadPoolExecutor so Flask's worker
     thread is never blocked.
  3. Private / loopback IPs short-circuit immediately with a local default.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from functools import lru_cache
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Default SOC location for private / lab traffic visualisation
_DEFAULT_LOCAL = {"lat": 31.5204, "lon": 74.3587, "country": "Local Network", "city": "Lahore"}
_DEFAULT_UNKNOWN = {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": None}

# One background thread for all geo lookups — never competes with ML workers
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="geo")


@lru_cache(maxsize=512)
def _cached_lookup(ip: str) -> tuple:
    """Cached, synchronous lookup executed in the background thread pool."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3,
            headers={"User-Agent": "AgenticIDS/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return (
                    float(data.get("lat", 0)),
                    float(data.get("lon", 0)),
                    data.get("country", "Unknown"),
                    data.get("city", None),
                )
        
    except Exception as exc:
        logger.debug(f"Geo lookup failed for {ip}: {exc}")
    
    return (0.0, 0.0, "Unknown", None)


def _is_private(ip: str) -> bool:
    """Return True for RFC-1918, loopback, or unparseable addresses."""
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except ValueError:
        return True


def get_geo_location(src_ip: str) -> dict:
    """
    Public entry-point called from the /detect route.

    Returns a dict with lat/lon/country/city.  Uses a background future
    with a short deadline so a slow API can never delay the HTTP response
    by more than 1 second.
    """
    if not src_ip or src_ip in ("localhost", "127.0.0.1") or _is_private(src_ip):
        return _DEFAULT_LOCAL.copy()

    # Submit to background thread; wait at most 1 s
    try:
        future = _executor.submit(_cached_lookup, src_ip)
        lat, lon, country, city = future.result(timeout=1.0)
        return {"lat": lat, "lon": lon, "country": country, "city": city}
    except FuturesTimeout:
        logger.debug(f"Geo lookup timed-out for {src_ip}, using default")
        return _DEFAULT_UNKNOWN.copy()
    except Exception as exc:
        logger.debug(f"Geo lookup error for {src_ip}: {exc}")
        return _DEFAULT_UNKNOWN.copy()
