"""
IP geolocation via the free ip-api.com batch endpoint (no API key required).

Private, loopback and non-IP values are skipped automatically.
Note: the free ip-api.com tier only offers HTTP, so the IPs travel unencrypted; use --no-geo
for sensitive logs.
Results are cached in-process to avoid redundant requests.
The batch API is limited to 100 IPs per request with a 45-req/min rate limit;
we add a short sleep between batches to stay within limits.
"""

import ipaddress
import time
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass


def is_private(ip: str) -> bool:
    """True for anything that is not a public, routable IP address: private ranges, loopback,
    link-local, reserved, multicast - and strings that are not IP addresses at all.
    Only public IPs are ever sent to the geolocation service."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return True
    return not addr.is_global or addr.is_multicast


@dataclass
class GeoInfo:
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    org: str
    lat: float
    lon: float
    is_proxy: bool

    def __str__(self) -> str:
        loc = ", ".join(p for p in (self.city, self.region, self.country) if p)
        return f"{loc} ({self.org})" if self.org else loc


class GeoIPLookup:
    _API = "http://ip-api.com/batch"
    _FIELDS = "status,country,countryCode,regionName,city,org,lat,lon,proxy,query"
    _BATCH = 100
    _SLEEP = 1.5   # ip-api.com free tier: 45 req/min, 100 IPs/batch

    def __init__(self):
        self._cache: Dict[str, Optional[GeoInfo]] = {}

    def lookup_batch(self, ips: List[str]) -> Dict[str, Optional[GeoInfo]]:
        unique = [ip for ip in dict.fromkeys(ips) if not is_private(ip) and ip not in self._cache]

        for start in range(0, len(unique), self._BATCH):
            batch = unique[start : start + self._BATCH]
            payload = [{"query": ip, "fields": self._FIELDS} for ip in batch]
            try:
                resp = requests.post(self._API, json=payload, timeout=15)
                resp.raise_for_status()
                for item in resp.json():
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        self._cache[ip] = GeoInfo(
                            ip=ip,
                            country=item.get("country", ""),
                            country_code=item.get("countryCode", ""),
                            region=item.get("regionName", ""),
                            city=item.get("city", ""),
                            org=item.get("org", ""),
                            lat=float(item.get("lat", 0)),
                            lon=float(item.get("lon", 0)),
                            is_proxy=bool(item.get("proxy", False)),
                        )
                    else:
                        self._cache[ip] = None
            except requests.Timeout:
                for ip in batch:
                    self._cache.setdefault(ip, None)
            except requests.ConnectionError:
                for ip in batch:
                    self._cache.setdefault(ip, None)
            except Exception:
                for ip in batch:
                    self._cache.setdefault(ip, None)

            if start + self._BATCH < len(unique):
                time.sleep(self._SLEEP)

        return {ip: self._cache.get(ip) for ip in ips}

    def lookup(self, ip: str) -> Optional[GeoInfo]:
        if ip not in self._cache:
            self.lookup_batch([ip])
        return self._cache.get(ip)
