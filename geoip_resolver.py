"""
Dynamic GeoIP Resolver with In-Memory Caching and Offline Fallback
Resolves real IP addresses to geographic coordinates (City, Country, Lat, Lon)
without slowing down the authentication pipeline.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any

# Fast local/offline preset dictionary
PRESET_LOCATIONS: Dict[str, Dict[str, Any]] = {
    "New York": {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    "London": {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "Tokyo": {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    "Frankfurt": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    "Sydney": {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    "San Francisco": {"country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    "Singapore": {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    "Moscow": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173}
}

# In-memory IP resolution cache
_GEO_CACHE: Dict[str, Dict[str, Any]] = {
    "127.0.0.1": PRESET_LOCATIONS["New York"],
    "::1": PRESET_LOCATIONS["New York"],
    "192.168.1.105": PRESET_LOCATIONS["New York"],
    "185.220.101.5": PRESET_LOCATIONS["Frankfurt"],
    "203.0.113.88": PRESET_LOCATIONS["Moscow"]
}

def is_private_ip(ip: str) -> bool:
    """Check if IP is loopback or RFC1918 private network."""
    if not ip:
        return True
    return (
        ip.startswith("127.") or
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip == "::1" or
        ip == "localhost"
    )

def resolve_ip_location(ip: str, city_hint: str = None) -> Dict[str, Any]:
    """
    Resolve IP to geographic coordinates with fallback cascade:
    1. Preset city hint
    2. Cached IP
    3. Loopback / Private IP baseline
    4. Fast public GeoIP HTTP resolution (1.2s timeout)
    5. Safe default (New York Corporate HQ)
    """
    # 1. Preset city hint match
    if city_hint and city_hint in PRESET_LOCATIONS:
        return PRESET_LOCATIONS[city_hint]

    clean_ip = (ip or "").strip()

    # 2. Cache hit
    if clean_ip in _GEO_CACHE:
        return _GEO_CACHE[clean_ip]

    # 3. Private / Local LAN IPs
    if is_private_ip(clean_ip):
        res = {
            "country": "Local Corporate LAN",
            "city": "Internal Office",
            "lat": 40.7128,
            "lon": -74.0060
        }
        _GEO_CACHE[clean_ip] = res
        return res

    # 4. Live external GeoIP lookup with fast timeout
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,country,city,lat,lon"
        req = urllib.request.Request(url, headers={"User-Agent": "LoginAfterDark-SOC/2.5"})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                geo = {
                    "country": data.get("country", "Unknown Country"),
                    "city": data.get("city", "Unknown City"),
                    "lat": float(data.get("lat", 40.7128)),
                    "lon": float(data.get("lon", -74.0060))
                }
                _GEO_CACHE[clean_ip] = geo
                return geo
    except Exception:
        pass # Offline or network timeout; cascade to fallback

    # 5. Default fallback
    return PRESET_LOCATIONS.get(city_hint, PRESET_LOCATIONS["New York"])
