"""Registry of scan modules."""

from __future__ import annotations

from ..core import Module
from .dns import CertTransparency, DNSResolve, EmailSecurity, HackerTargetHosts
from .identity import Accounts, EmailParse, Gravatar, PGPKey
from .network import IPGeo, RDAPDomain, RDAPNetwork, ShodanInternetDB, SSLCert
from .web import Wayback, WebPage

ALL_MODULES: list[type[Module]] = [
    DNSResolve, EmailSecurity, CertTransparency, HackerTargetHosts,
    RDAPDomain, RDAPNetwork, IPGeo, ShodanInternetDB, SSLCert,
    WebPage, Wayback,
    EmailParse, Gravatar, PGPKey, Accounts,
]


def get_modules(names: list[str] | None = None) -> list[Module]:
    """Instantiate modules; ``names`` selects a subset (default: all default modules)."""
    mods = [cls() for cls in ALL_MODULES]
    if names:
        wanted = {n.strip().lower() for n in names}
        unknown = wanted - {m.name for m in mods}
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(sorted(unknown))}")
        return [m for m in mods if m.name in wanted]
    return [m for m in mods if m.default]
