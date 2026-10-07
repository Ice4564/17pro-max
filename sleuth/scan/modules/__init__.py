"""Registry of scan modules, built in and plugins.

Modules are grouped the way an investigator thinks about sources::

    username/   accounts                 find accounts for a username
    social/     (plugins)                platform-specific lookups
    domain/     dns, rdap, ssl, web ...  infrastructure behind a domain / IP
    email/      email_parse, gravatar, pgp
    image/      (plugins)                profile pictures, reverse image search
    search/     websearch                search-engine dorks

Adding a source never needs a change here: drop a ``.py`` file that defines
a :class:`~sleuth.scan.core.Module` subclass into ``~/.sleuth/plugins/`` (or
a folder listed in the ``SLEUTH_PLUGINS`` environment variable, separated by
``os.pathsep``) and it is loaded at start-up. See README "เขียน plugin".
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from ..core import Module
from .dns import CertTransparency, DNSResolve, EmailSecurity, HackerTargetHosts
from .identity import Accounts, EmailParse, Gravatar, PGPKey
from .network import IPGeo, RDAPDomain, RDAPNetwork, ShodanInternetDB, SSLCert
from .search import WebSearch
from .web import Wayback, WebPage

GROUPS = ("username", "social", "domain", "email", "image", "search")

BUILTIN: list[type[Module]] = [
    DNSResolve, EmailSecurity, CertTransparency, HackerTargetHosts,
    RDAPDomain, RDAPNetwork, IPGeo, ShodanInternetDB, SSLCert,
    WebPage, Wayback,
    EmailParse, Gravatar, PGPKey, Accounts, WebSearch,
]
_BUILTIN_GROUP = {
    "dns": "domain", "emailsec": "domain", "crt": "domain", "hackertarget": "domain",
    "rdap_domain": "domain", "rdap_ip": "domain", "ipgeo": "domain", "internetdb": "domain", "sslcert": "domain",
    "webpage": "domain", "wayback": "domain",
    "email_parse": "email", "gravatar": "email", "pgp": "email", "accounts": "username", "websearch": "search",
}
for _cls in BUILTIN:
    if not getattr(_cls, "group", None):
        _cls.group = _BUILTIN_GROUP.get(_cls.name, "domain")  # type: ignore[attr-defined]


def plugin_dirs() -> list[Path]:
    dirs = [Path.home() / ".sleuth" / "plugins"]
    dirs += [Path(p) for p in os.environ.get("SLEUTH_PLUGINS", "").split(os.pathsep) if p.strip()]
    return dirs


def load_plugins(dirs: list[Path] | None = None) -> tuple[list[type[Module]], list[str]]:
    """Module classes defined in ``*.py`` files of the plugin folders (files starting with _ are skipped).

    Sub-folders are searched too, so plugins can be organised as
    ``plugins/social/mastodon.py``, ``plugins/image/tineye.py`` ...
    Returns ``(classes, errors)``; a broken plugin never stops Sleuth.
    """
    found: list[type[Module]] = []
    errors: list[str] = []
    taken = {cls.name for cls in BUILTIN}
    for d in dirs if dirs is not None else plugin_dirs():
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.py")):
            if f.name.startswith("_"):
                continue
            mod_name = "sleuth_plugin_" + "_".join(f.relative_to(d).with_suffix("").parts)
            try:
                spec = importlib.util.spec_from_file_location(mod_name, f)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot load")
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception as e:  # a plugin's bug is reported, not raised
                errors.append(f"{f}: {type(e).__name__}: {e}")
                continue
            for obj in vars(mod).values():
                if (isinstance(obj, type) and issubclass(obj, Module) and obj is not Module
                        and obj.__module__ == mod.__name__):
                    if obj.name in taken:
                        errors.append(f"{f}: module name {obj.name!r} is already used")
                        continue
                    if not getattr(obj, "group", None) or obj.group not in GROUPS:
                        # folder name as the group: plugins/social/x.py -> social
                        parent = f.parent.name if f.parent != d else ""
                        obj.group = parent if parent in GROUPS else "social"  # type: ignore[attr-defined]
                    obj.plugin = str(f)  # type: ignore[attr-defined]
                    taken.add(obj.name)
                    found.append(obj)
    return found, errors


PLUGINS, PLUGIN_ERRORS = load_plugins()
ALL_MODULES: list[type[Module]] = BUILTIN + PLUGINS


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
