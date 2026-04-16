"""
GeoIP Resolver v6 — risolve automaticamente Country, ASN e ISP dall'IP.

Utilizza i database MaxMind GeoLite2 (City + ASN) se disponibili.
In assenza dei DB, ritorna metadati vuoti senza bloccare il flusso.

I path dei database sono configurabili via .env:
  MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb
  MAXMIND_ASN_DB=/path/to/GeoLite2-ASN.mmdb

Le reti Tor e ASN VPN note sono identificate tramite una lista statica
(estensibile). In produzione si può integrare un feed Tor/VPN dinamico.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from app.config import MAXMIND_CITY_DB, MAXMIND_ASN_DB

try:
    import geoip2.database  # type: ignore
    import geoip2.errors    # type: ignore
    _GEOIP2_AVAILABLE = True
except Exception:
    _GEOIP2_AVAILABLE = False


# ASN noti di provider VPN commerciali (sottoinsieme rappresentativo).
# Lista non esaustiva: copre i principali operatori ad alto volume.
_VPN_ASNS: frozenset[int] = frozenset({
    9009,     # M247 (molti provider VPN)
    20473,    # Choopa / Vultr (frequente per VPN)
    16276,    # OVH SAS
    14061,    # DigitalOcean
    16509,    # Amazon AWS
    15169,    # Google Cloud
    36351,    # SoftLayer / IBM Cloud
    60068,    # CDN77 / DataCamp (NordVPN infra)
    212238,   # Datacamp Limited
    8100,     # QuadraNet
    46844,    # Sharktech
})


class _Resolver:
    """Singleton che mantiene aperti i reader MaxMind tra le richieste."""

    def __init__(self) -> None:
        self._city = None
        self._asn  = None
        self._open()

    def _open(self) -> None:
        if not _GEOIP2_AVAILABLE:
            return
        if MAXMIND_CITY_DB and Path(MAXMIND_CITY_DB).is_file():
            try:
                self._city = geoip2.database.Reader(MAXMIND_CITY_DB)
            except Exception as e:
                print(f"[geoip] impossibile aprire CITY DB: {e}")
        if MAXMIND_ASN_DB and Path(MAXMIND_ASN_DB).is_file():
            try:
                self._asn = geoip2.database.Reader(MAXMIND_ASN_DB)
            except Exception as e:
                print(f"[geoip] impossibile aprire ASN DB: {e}")

    def close(self) -> None:
        for r in (self._city, self._asn):
            try:
                if r is not None:
                    r.close()
            except Exception:
                pass
        self._city = None
        self._asn  = None

    @property
    def enabled(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: str) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "ip":      ip,
            "country": None,
            "city":    None,
            "asn":     None,
            "isp":     None,
            "is_tor":  False,
            "is_vpn":  False,
            "private": False,
        }

        addr = _parse_ip(ip)
        if addr is None:
            return meta
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            meta["private"] = True
            return meta

        if self._city is not None:
            try:
                r = self._city.city(ip)
                meta["country"] = r.country.iso_code
                meta["city"]    = r.city.name
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                print(f"[geoip] city lookup fallito per {ip}: {e}")

        if self._asn is not None:
            try:
                r = self._asn.asn(ip)
                meta["asn"] = r.autonomous_system_number
                meta["isp"] = r.autonomous_system_organization
                if r.autonomous_system_number in _VPN_ASNS:
                    meta["is_vpn"] = True
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                print(f"[geoip] asn lookup fallito per {ip}: {e}")

        return meta


def _parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


_resolver: _Resolver | None = None


def get_resolver() -> _Resolver:
    global _resolver
    if _resolver is None:
        _resolver = _Resolver()
    return _resolver


def resolve(ip: str, hint: dict | None = None) -> dict[str, Any]:
    """
    Risolve i metadati di un IP. Un `hint` (es. override da header fidati
    o da test) può completare i campi che i DB MaxMind non coprono
    (tipicamente is_tor, che richiederebbe un feed esterno dedicato).
    """
    meta = get_resolver().lookup(ip)
    if hint:
        for k, v in hint.items():
            if v is None:
                continue
            if meta.get(k) in (None, False, ""):
                meta[k] = v
            elif k in ("is_tor", "is_vpn") and v:
                meta[k] = True
    return meta


def summary() -> str:
    r = get_resolver()
    if not _GEOIP2_AVAILABLE:
        return "geoip2 non installato (pip install geoip2)"
    if not r.enabled:
        return "MaxMind DB non configurati (MAXMIND_CITY_DB / MAXMIND_ASN_DB)"
    parts = []
    if r._city is not None: parts.append("city")
    if r._asn  is not None: parts.append("asn")
    return f"MaxMind attivo ({'+'.join(parts)})"
