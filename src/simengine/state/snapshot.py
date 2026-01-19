"""State Snapshot and Diff Calculator."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class TokenBalance:
    mint: str
    symbol: str
    amount: float
    decimals: int


@dataclass
class StateSnapshot:
    timestamp: datetime
    slot: int
    wallet_address: str
    sol_balance: float
    token_balances: Dict[str, TokenBalance] = field(default_factory=dict)
    
    def get_balance(self, symbol: str) -> float:
        if symbol.upper() == "SOL":
            return self.sol_balance
        token = self.token_balances.get(symbol.upper())
        return token.amount if token else 0.0


@dataclass
class BalanceChange:
    token: str
    before: float
    after: float
    delta: float
    delta_pct: Optional[float] = None


@dataclass
class StateDiff:
    before: StateSnapshot
    after: StateSnapshot
    balance_changes: List[BalanceChange] = field(default_factory=list)
    total_tokens_changed: int = 0
    
    def has_changes(self) -> bool:
        return len(self.balance_changes) > 0


def calculate_diff(before: StateSnapshot, after: StateSnapshot) -> StateDiff:
    changes = []
    
    # SOL
    sol_delta = after.sol_balance - before.sol_balance
    if abs(sol_delta) > 0.000000001:
        changes.append(BalanceChange(
            token="SOL",
            before=before.sol_balance,
            after=after.sol_balance,
            delta=sol_delta
        ))
    
    # Tokens
    all_symbols = set(before.token_balances.keys()) | set(after.token_balances.keys())
    for symbol in all_symbols:
        before_bal = before.get_balance(symbol)
        after_bal = after.get_balance(symbol)
        delta = after_bal - before_bal
        if abs(delta) > 0.000000001:
            changes.append(BalanceChange(
                token=symbol,
                before=before_bal,
                after=after_bal,
                delta=delta
            ))
    
    return StateDiff(
        before=before,
        after=after,
        balance_changes=changes,
        total_tokens_changed=len(changes)
    )


def create_mock_snapshot(wallet_address: str, sol_balance: float, token_balances: Dict[str, float]) -> StateSnapshot:
    from ..parser.token_registry import get_token_info
    
    tokens = {}
    for symbol, amount in token_balances.items():
        info = get_token_info(symbol)
        if info:
            tokens[symbol] = TokenBalance(mint=info.mint, symbol=symbol, amount=amount, decimals=info.decimals)
    
    return StateSnapshot(
        timestamp=datetime.now(),
        slot=0,
        wallet_address=wallet_address,
        sol_balance=sol_balance,
        token_balances=tokens
    )


def format_diff_table(diff: StateDiff) -> str:
    if not diff.has_changes():
        return "No balance changes."
    lines = ["Token | Before | After | Change"]
    for c in diff.balance_changes:
        sign = "+" if c.delta >= 0 else ""
        lines.append(f"{c.token} | {c.before:.6f} | {c.after:.6f} | {sign}{c.delta:.6f}")
    return "\n".join(lines)
