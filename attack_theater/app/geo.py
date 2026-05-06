"""MaxMind GeoLite2 wrapper. Never raises — returns safe defaults on any failure."""
from dataclasses import dataclass
from pathlib import Path

import maxminddb

_UNKNOWN = "Unknown"
_db: maxminddb.Reader | None = None


@dataclass(frozen=True)
class GeoResult:
    country: str = _UNKNOWN
    country_code: str = ""
    asn_org: str = _UNKNOWN
    lat: float | None = None
    lon: float | None = None


_FALLBACK = GeoResult()


def init(mmdb_path: str | Path) -> None:
    global _db
    _db = maxminddb.open_database(str(mmdb_path))


def lookup(ip: str) -> GeoResult:
    if _db is None:
        return _FALLBACK
    try:
        record = _db.get(ip)
    except Exception:
        return _FALLBACK

    if not record:
        return _FALLBACK

    try:
        country = record.get("country", {}).get("names", {}).get("en", _UNKNOWN)
        country_code = record.get("country", {}).get("iso_code", "")
        location = record.get("location", {})
        lat = location.get("latitude")
        lon = location.get("longitude")
        asn_org = record.get("traits", {}).get("autonomous_system_organization", _UNKNOWN)
        return GeoResult(
            country=country or _UNKNOWN,
            country_code=country_code or "",
            asn_org=asn_org or _UNKNOWN,
            lat=lat,
            lon=lon,
        )
    except Exception:
        return _FALLBACK
