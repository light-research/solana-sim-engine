"""Token Registry: Maps token symbols to Solana mint addresses."""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TokenInfo:
    symbol: str
    name: str
    mint: str
    decimals: int


TOKEN_REGISTRY: Dict[str, TokenInfo] = {
    "SOL": TokenInfo("SOL", "Wrapped SOL", "So11111111111111111111111111111111111111112", 9),
    "USDC": TokenInfo("USDC", "USD Coin", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
    "USDT": TokenInfo("USDT", "Tether USD", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 6),
    "mSOL": TokenInfo("mSOL", "Marinade Staked SOL", "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So", 9),
    "JitoSOL": TokenInfo("JitoSOL", "Jito Staked SOL", "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", 9),
    "JUP": TokenInfo("JUP", "Jupiter", "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", 6),
    "BONK": TokenInfo("BONK", "Bonk", "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", 5),
    "RAY": TokenInfo("RAY", "Raydium", "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R", 6),
    "ORCA": TokenInfo("ORCA", "Orca", "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE", 6),
}


def get_token_info(symbol: str) -> Optional[TokenInfo]:
    return TOKEN_REGISTRY.get(symbol.upper())


def get_mint_address(symbol: str) -> Optional[str]:
    token = get_token_info(symbol)
    return token.mint if token else None


def get_decimals(symbol: str) -> Optional[int]:
    token = get_token_info(symbol)
    return token.decimals if token else None


def resolve_token(symbol_or_mint: str) -> Optional[TokenInfo]:
    token = get_token_info(symbol_or_mint)
    if token:
        return token
    for info in TOKEN_REGISTRY.values():
        if info.mint == symbol_or_mint:
            return info
    return None


def amount_to_raw(amount: float, symbol: str) -> int:
    decimals = get_decimals(symbol)
    if decimals is None:
        raise ValueError(f"Unknown token: {symbol}")
    return int(amount * (10 ** decimals))


def raw_to_amount(raw: int, symbol: str) -> float:
    decimals = get_decimals(symbol)
    if decimals is None:
        raise ValueError(f"Unknown token: {symbol}")
    return raw / (10 ** decimals)
