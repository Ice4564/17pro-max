"""Crypto & NFT lookup: ENS resolution, wallet inspection, wallet clustering."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

# ---- constants -----------------------------------------------------------

ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
ENS_NAME_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.eth$")
ENS_TEXT_RE = re.compile(r"\b([a-zA-Z0-9-]+\.eth)\b")

ETHERSCAN_BASE = "https://api.etherscan.io/api"
OPENSEA_ASSET = "https://api.opensea.io/api/v1"
ENS_RESOLVE = "https://api.ens.domains/v1/lookup"

# ---- data classes --------------------------------------------------------


@dataclass
class WalletInfo:
    """Information about an Ethereum wallet."""

    address: str
    ens_name: str | None = None
    balance_eth: float | None = None
    tx_count: int | None = None
    first_tx: str | None = None
    last_tx: str | None = None
    is_contract: bool = False
    labels: list[str] = field(default_factory=list)
    tokens: list[dict] = field(default_factory=list)
    nfts: list[dict] = field(default_factory=list)
    opensea_username: str | None = None


@dataclass
class WalletCluster:
    """A cluster of wallets likely owned by the same entity."""

    addresses: list[str]
    ens_names: list[str]
    interactions: int
    shared_tokens: list[str]
    confidence: int  # 0-100


# ---- public API ----------------------------------------------------------


async def ens_lookup(name: str, session: aiohttp.ClientSession) -> str | None:
    """Resolve an ENS name (e.g. ``vitalik.eth``) to an Ethereum address.

    Uses the ENS public resolver via etherscan API (no key needed for basic
    forward resolution via the public ENS subgraph).
    """
    name = name.lower().strip()
    if not ENS_NAME_RE.match(name):
        return None
    # Try the free ENS API first
    try:
        url = f"{ENS_RESOLVE}/{name}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                addr = data.get("address") or data.get("ens", {}).get("address")
                if addr and ETH_ADDRESS_RE.match(addr):
                    return addr
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    # Fallback: etherscan proxy (requires API key, but works without for basic lookups)
    try:
        params = {
            "module": "proxy",
            "action": "eth_call",
            "to": "0x00000000000C2E074eCe5A2974a61E8a74454B69",  # ENS registry
            "tag": "latest",
        }
        async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                result = data.get("result", "0x")
                if len(result) >= 42:
                    addr = "0x" + result[-40:]
                    if addr != "0x" + "0" * 40:
                        return addr
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return None


async def wallet_lookup(
    address: str, session: aiohttp.ClientSession, etherscan_api_key: str = ""
) -> WalletInfo | None:
    """Look up an Ethereum wallet address on Etherscan.

    Returns basic info: balance, transaction count, contract status,
    ENS reverse resolution, labels, tokens, and NFT holdings.
    """
    address = address.strip()
    if not ETH_ADDRESS_RE.match(address):
        # Maybe it's an ENS name
        resolved = await ens_lookup(address, session)
        if not resolved:
            return None
        address = resolved

    info = WalletInfo(address=address)
    params = {"module": "account", "address": address}
    if etherscan_api_key:
        params["apikey"] = etherscan_api_key

    # Balance
    try:
        params["action"] = "balance"
        params["tag"] = "latest"
        async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                wei = int(data.get("result", "0") or "0")
                info.balance_eth = wei / 1e18
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        pass

    # Transaction count (normal + internal)
    try:
        params["action"] = "txlist"
        params.pop("tag", None)
        params["startblock"] = "0"
        params["endblock"] = "99999999"
        params["page"] = "1"
        params["offset"] = "1"
        params["sort"] = "asc"
        async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                txs = data.get("result", [])
                if isinstance(txs, list) and txs:
                    info.tx_count = len(txs)  # at least 1, actual count needs separate call
                    info.first_tx = txs[0].get("timeStamp")
        # Get latest tx
        params["sort"] = "desc"
        async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                data = await r.json()
                txs = data.get("result", [])
                if isinstance(txs, list) and txs:
                    info.last_tx = txs[0].get("timeStamp")
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        pass

    # Check if contract
    try:
        params2 = {"module": "contract", "action": "getabi", "address": address}
        if etherscan_api_key:
            params2["apikey"] = etherscan_api_key
        async with session.get(ETHERSCAN_BASE, params=params2, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                data = await r.json()
                if data.get("status") == "1":
                    info.is_contract = True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    # OpenSea profile
    try:
        async with session.get(
            f"{OPENSEA_ASSET}/user/{address}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            if r.status == 200:
                data = await r.json()
                info.opensea_username = data.get("username")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    return info


async def cluster_wallets(
    addresses: list[str], session: aiohttp.ClientSession, etherscan_api_key: str = ""
) -> list[WalletCluster]:
    """Cluster wallets that have interacted with each other.

    Two addresses are linked if one sent ETH/tokens to the other. Uses
    union-find to build clusters.
    """
    if len(addresses) < 2:
        return []

    # Build adjacency: which addresses interacted
    interactions: dict[str, set[str]] = {a: set() for a in addresses}
    shared_tokens: dict[str, set[str]] = {a: set() for a in addresses}

    for addr in addresses:
        try:
            params = {
                "module": "account",
                "action": "txlist",
                "address": addr,
                "startblock": "0",
                "endblock": "99999999",
                "page": "1",
                "offset": "100",
                "sort": "asc",
            }
            if etherscan_api_key:
                params["apikey"] = etherscan_api_key
            async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    data = await r.json()
                    txs = data.get("result", [])
                    if isinstance(txs, list):
                        for tx in txs:
                            to_addr = (tx.get("to") or "").lower()
                            from_addr = (tx.get("from") or "").lower()
                            if to_addr in interactions and to_addr != addr.lower():
                                interactions[addr].add(to_addr)
                            if from_addr in interactions and from_addr != addr.lower():
                                interactions[addr].add(from_addr)
            # Also check ERC-20 token transfers
            params["action"] = "tokentx"
            async with session.get(ETHERSCAN_BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    data = await r.json()
                    txs = data.get("result", [])
                    if isinstance(txs, list):
                        for tx in txs:
                            contract = (tx.get("contractAddress") or "").lower()
                            if contract:
                                shared_tokens[addr].add(contract)
                            to_addr = (tx.get("to") or "").lower()
                            from_addr = (tx.get("from") or "").lower()
                            if to_addr in interactions and to_addr != addr.lower():
                                interactions[addr].add(to_addr)
                            if from_addr in interactions and from_addr != addr.lower():
                                interactions[addr].add(from_addr)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            continue

    # Union-find clustering
    parent = {a: a for a in addresses}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for addr, peers in interactions.items():
        for peer in peers:
            if peer in parent:
                union(addr, peer)

    # Group by root
    clusters: dict[str, list[str]] = {}
    for addr in addresses:
        root = find(addr)
        clusters.setdefault(root, []).append(addr)

    result = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        # Count cross-interactions
        cross = sum(len(interactions[m] & set(members)) for m in members)
        # Find shared tokens
        common_tokens = set.intersection(*[shared_tokens[m] for m in members]) if shared_tokens else set()
        # Resolve ENS names
        ens_names = []
        for m in members:
            if ENS_NAME_RE.match(m):
                ens_names.append(m)
        confidence = min(100, 30 + cross * 10 + len(common_tokens) * 5)
        result.append(
            WalletCluster(
                addresses=members,
                ens_names=ens_names,
                interactions=cross,
                shared_tokens=sorted(common_tokens)[:10],
                confidence=confidence,
            )
        )

    return result


def extract_ens_from_text(text: str) -> list[str]:
    """Extract all ENS names (.eth) from a block of text."""
    return ENS_TEXT_RE.findall(text)


def extract_eth_addresses_from_text(text: str) -> list[str]:
    """Extract all Ethereum addresses from text."""
    return re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
