"""Sleuth: find accounts by username across many sites.

Combines Sherlock-style existence checks with Maigret-style profile
parsing, recursive search and reports.

v2.0.0 adds account enrichment (profile language, bot heuristics, reverse
image-search links, crypto/ENS and Thai phone detection), regional search
engines (Baidu/Yandex/Naver/...), XLSX export and side-by-side run
comparison, Docker support, CI, and new data sources.
"""

__version__ = "2.0.0"
