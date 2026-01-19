"""
Real Simulator with Surfpool and devnet/mainnet support.

Fetches real balances, gets real quotes, and optionally simulates via Surfpool.
"""

import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

import httpx

from ..parser.prompt_parser import PromptParser, ParsedIntent
from ..parser.token_registry import get_token_info, get_mint_address, raw_to_amount
from ..adapters.base import get_adapter, AdapterResult
from ..state.snapshot import (
    StateSnapshot, 
    StateDiff, 
    TokenBalance,
    calculate_diff,
)


# RPC endpoints
DEVNET_RPC = "https://api.devnet.solana.com"
MAINNET_RPC = "https://api.mainnet-beta.solana.com"


@dataclass
class SimulationResult:
    """Result of a simulation run."""
    success: bool
    prompt: str
    parsed_intent: Optional[ParsedIntent] = None
    
    # Transaction results
    transactions: List[Dict[str, Any]] = field(default_factory=list)
    
    # State changes
    state_before: Optional[StateSnapshot] = None
    state_after: Optional[StateSnapshot] = None
    state_diff: Optional[StateDiff] = None
    
    # Quote info
    quote_info: Optional[Dict[str, Any]] = None
    
    # Metadata
    execution_time_ms: int = 0
    network: str = "devnet"
    wallet: str = ""
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


async def fetch_sol_balance(rpc_url: str, wallet: str) -> float:
    """Fetch SOL balance from RPC."""
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [wallet]
            }
        )
        result = response.json()
        lamports = result.get("result", {}).get("value", 0)
        return lamports / 1e9


async def fetch_token_balances(rpc_url: str, wallet: str) -> Dict[str, TokenBalance]:
    """Fetch all token balances for a wallet."""
    token_balances = {}
    
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTokenAccountsByOwner",
                "params": [
                    wallet,
                    {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                    {"encoding": "jsonParsed"}
                ]
            }
        )
        result = response.json()
        accounts = result.get("result", {}).get("value", [])
        
        for acc in accounts:
            try:
                info = acc["account"]["data"]["parsed"]["info"]
                mint = info["mint"]
                amount = float(info["tokenAmount"]["uiAmountString"])
                decimals = info["tokenAmount"]["decimals"]
                
                if amount > 0:
                    # Try to get symbol from our registry
                    token_info = None
                    for sym, ti in __import__('simengine.parser.token_registry', fromlist=['TOKEN_REGISTRY']).TOKEN_REGISTRY.items():
                        if ti.mint == mint:
                            token_info = ti
                            break
                    
                    symbol = token_info.symbol if token_info else mint[:8]
                    
                    token_balances[symbol] = TokenBalance(
                        mint=mint,
                        symbol=symbol,
                        amount=amount,
                        decimals=decimals
                    )
            except (KeyError, ValueError):
                continue
    
    return token_balances


async def capture_real_snapshot(
    wallet: str, 
    network: str = "devnet"
) -> StateSnapshot:
    """Capture real blockchain state for a wallet."""
    rpc_url = DEVNET_RPC if network == "devnet" else MAINNET_RPC
    
    sol_balance = await fetch_sol_balance(rpc_url, wallet)
    token_balances = await fetch_token_balances(rpc_url, wallet)
    
    return StateSnapshot(
        timestamp=datetime.now(),
        slot=0,  # Could fetch real slot if needed
        wallet_address=wallet,
        sol_balance=sol_balance,
        token_balances=token_balances
    )


class RealSimulator:
    """
    Real simulation with blockchain data.
    
    Uses devnet or mainnet RPC to fetch real balances,
    Jupiter API for real quotes, and optionally Surfpool for execution.
    """
    
    def __init__(
        self, 
        wallet_address: str,
        network: str = "devnet",
        openai_api_key: Optional[str] = None
    ):
        """
        Initialize simulator.
        
        Args:
            wallet_address: Solana wallet public key
            network: "devnet" or "mainnet" 
            openai_api_key: Optional OpenAI API key
        """
        self.wallet = wallet_address
        self.network = network
        self.rpc_url = DEVNET_RPC if network == "devnet" else MAINNET_RPC
        self.parser = PromptParser(api_key=openai_api_key)
    
    async def run(self, prompt: str) -> SimulationResult:
        """
        Run a simulation with real data and local execution.
        
        Args:
            prompt: Natural language prompt
            
        Returns:
            SimulationResult with real balances, quotes, and execution verification
        """
        # Lazy import to avoid circular dependency
        from .surfpool import SurfpoolManager, SurfpoolConfig, SolanaRpcClient
        
        start_time = datetime.now()
        warnings = []
        
        # Step 1: Parse prompt
        try:
            intent = self.parser.parse(prompt)
        except Exception as e:
            return SimulationResult(
                success=False,
                prompt=prompt,
                network=self.network,
                wallet=self.wallet,
                error=f"Parse error: {e}",
                execution_time_ms=self._elapsed_ms(start_time)
            )
        
        if not intent.is_valid:
            return SimulationResult(
                success=False,
                prompt=prompt,
                parsed_intent=intent,
                network=self.network,
                wallet=self.wallet,
                error=f"Invalid prompt: {', '.join(intent.errors)}",
                execution_time_ms=self._elapsed_ms(start_time)
            )
        
        if not intent.actions:
            return SimulationResult(
                success=False,
                prompt=prompt,
                parsed_intent=intent,
                network=self.network,
                wallet=self.wallet,
                error=f"No actions parsed from prompt",
                execution_time_ms=self._elapsed_ms(start_time)
            )
        
        # Step 2: Get REAL balance before
        try:
            state_before = await capture_real_snapshot(self.wallet, self.network)
        except Exception as e:
            return SimulationResult(
                success=False,
                prompt=prompt,
                parsed_intent=intent,
                network=self.network,
                wallet=self.wallet,
                error=f"Failed to fetch wallet state: {e}",
                execution_time_ms=self._elapsed_ms(start_time)
            )
        
        # Step 3: Get quote and build transactions
        transactions = []
        quote_info = None
        
        for action in intent.actions:
            adapter = get_adapter(action.protocol)
            if not adapter:
                warnings.append(f"No adapter for protocol: {action.protocol}")
                continue
            
            # Build transaction (gets real quote + serialized tx)
            result = await adapter.build_transaction(
                action={"type": action.type, "parameters": action.parameters},
                user_wallet=self.wallet
            )
            
            if not result.success:
                return SimulationResult(
                    success=False,
                    prompt=prompt,
                    parsed_intent=intent,
                    state_before=state_before,
                    network=self.network,
                    wallet=self.wallet,
                    error=f"Transaction build failed: {result.error}",
                    execution_time_ms=self._elapsed_ms(start_time)
                )
            
            transactions.append({
                "protocol": action.protocol,
                "type": action.type,
                "result": result
            })
            
            if result.metadata and "quote" in result.metadata:
                quote_info = result.metadata["quote"]
        
        # Step 4: Execute locally in Surfpool
        # Surfpool will lazy-load accounts from the network automatically
        # Jupiter only supports Mainnet, so we must fork Mainnet even if we are checking Devnet
        # (simulating execution of a Mainnet transaction on Devnet would fail due to wrong accounts/blockhash)
        
        # Prepare Surfpool config
        extra_args = []
        
        # Airdrop SOL to the user in the simulation so they can pay for gas
        # regardless of their real balance.
        extra_args.extend(["--airdrop", self.wallet])
        
        surfpool_config = SurfpoolConfig(
            rpc_port=9000,
            ws_port=9001,
            clone_from="mainnet",  # Force mainnet for Jupiter compatibility
            extra_args=extra_args
        )
        
        print(f"\n[Simulator] Starting Surfpool (forking Mainnet)...")
        
        try:
            async with SurfpoolManager(config=surfpool_config) as surfpool:
                rpc = SolanaRpcClient(surfpool.rpc_url)
                
                # Check simulation for each transaction
                for tx in transactions:
                    if "swapTransaction" in tx["result"].metadata:
                        tx_base64 = tx["result"].metadata["swapTransaction"]
                        
                        # Simulate transaction locally
                        # Must use base64 encoding for versioned TXs
                        # Must replace blockhash since Jupiter's blockhash relies on Mainnet tip 
                        # which might differ from our fork's tip
                        sim_result = await rpc.simulate_transaction(
                            tx_base64, 
                            {
                                "sigVerify": False, 
                                "encoding": "base64",
                                "replaceRecentBlockhash": True
                            }
                        )
                        
                        err = sim_result.get("value", {}).get("err")
                        
                        # Capture logs
                        logs = sim_result.get("value", {}).get("logs", [])
                        
                        if err:
                            return SimulationResult(
                                success=False,
                                prompt=prompt,
                                parsed_intent=intent,
                                state_before=state_before,
                                network=self.network,
                                wallet=self.wallet,
                                error=f"Simulation failed: {err}\nLogs: {logs[-3:] if logs else 'None'}",
                                execution_time_ms=self._elapsed_ms(start_time),
                                transactions=transactions
                            )
                        # Could parse logs for more info
        
        except RuntimeError as e:
            return SimulationResult(
                success=False,
                prompt=prompt,
                parsed_intent=intent,
                state_before=state_before,
                network=self.network,
                wallet=self.wallet,
                error=f"Surfpool error: {e}",
                execution_time_ms=self._elapsed_ms(start_time)
            )
        except Exception as e:
            return SimulationResult(
                success=False,
                prompt=prompt,
                parsed_intent=intent,
                state_before=state_before,
                network=self.network,
                wallet=self.wallet,
                error=f"Execution error: {e}",
                execution_time_ms=self._elapsed_ms(start_time)
            )

        # Step 5: Calculate expected state after (based on quote)
        # Note: We verified the TX works on the fork, so we trust the math.
        state_after = self._calculate_expected_state(
            state_before, 
            intent.actions, 
            transactions
        )
        
        state_diff = calculate_diff(state_before, state_after)
        
        return SimulationResult(
            success=True,
            prompt=prompt,
            parsed_intent=intent,
            transactions=transactions,
            state_before=state_before,
            state_after=state_after,
            state_diff=state_diff,
            quote_info=quote_info,
            network=self.network,
            wallet=self.wallet,
            execution_time_ms=self._elapsed_ms(start_time),
            warnings=warnings if warnings else None
        )
    
    def _calculate_expected_state(
        self,
        before: StateSnapshot,
        actions: List[Any],
        transactions: List[Dict]
    ) -> StateSnapshot:
        """Calculate expected state after based on quotes."""
        new_sol = before.sol_balance
        new_tokens = {k: v.amount for k, v in before.token_balances.items()}
        
        for i, action in enumerate(actions):
            if action.type == "swap":
                tx = transactions[i] if i < len(transactions) else None
                if tx and tx.get("result") and tx["result"].metadata:
                    quote = tx["result"].metadata.get("quote", {})
                    
                    input_token = quote.get("inputToken", "")
                    output_token = quote.get("outputToken", "")
                    input_amount = action.parameters.get("amount", 0)
                    
                    # Get output amount from quote
                    out_amount_raw = quote.get("outputAmount", 0)
                    output_info = get_token_info(output_token)
                    out_amount = raw_to_amount(out_amount_raw, output_token) if output_info else 0
                    
                    # Deduct input
                    if input_token.upper() == "SOL":
                        new_sol -= input_amount
                    else:
                        current = new_tokens.get(input_token.upper(), 0)
                        new_tokens[input_token.upper()] = current - input_amount
                    
                    # Add output
                    if output_token.upper() == "SOL":
                        new_sol += out_amount
                    else:
                        current = new_tokens.get(output_token.upper(), 0)
                        new_tokens[output_token.upper()] = current + out_amount
        
        # Create new snapshot
        new_token_balances = {}
        for symbol, amount in new_tokens.items():
            if amount != 0:
                info = get_token_info(symbol)
                if info:
                    new_token_balances[symbol] = TokenBalance(
                        mint=info.mint,
                        symbol=symbol,
                        amount=amount,
                        decimals=info.decimals
                    )
        
        return StateSnapshot(
            timestamp=datetime.now(),
            slot=0,
            wallet_address=before.wallet_address,
            sol_balance=new_sol,
            token_balances=new_token_balances
        )
    
    def _elapsed_ms(self, start: datetime) -> int:
        return int((datetime.now() - start).total_seconds() * 1000)


# Convenience function
async def simulate_real(
    prompt: str, 
    wallet: str,
    network: str = "devnet"
) -> SimulationResult:
    """Run a real simulation."""
    sim = RealSimulator(wallet_address=wallet, network=network)
    return await sim.run(prompt)
