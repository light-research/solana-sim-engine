"""Jupiter Protocol Adapter with public.jupiterapi.com."""

import httpx
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .base import ProtocolAdapter, AdapterResult, register_adapter
from ..parser.token_registry import get_mint_address, amount_to_raw

JUPITER_QUOTE_API = "https://public.jupiterapi.com/quote"


@dataclass
class SwapQuote:
    input_mint: str
    output_mint: str
    in_amount: int
    out_amount: int
    price_impact_pct: float
    route_plan: List[Dict] = field(default_factory=list)
    raw_response: Dict = field(default_factory=dict)


class JupiterAdapter(ProtocolAdapter):
    
    @property
    def name(self) -> str:
        return "jupiter"
    
    @property
    def supported_actions(self) -> List[str]:
        return ["swap"]
    
    def get_quote_sync(self, input_mint: str, output_mint: str, amount: int, slippage_bps: int = 50) -> SwapQuote:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(JUPITER_QUOTE_API, params={
                "inputMint": input_mint,
                "outputMint": output_mint,
                "amount": str(amount),
                "slippageBps": slippage_bps,
            })
            response.raise_for_status()
            data = response.json()
        
        return SwapQuote(
            input_mint=data["inputMint"],
            output_mint=data["outputMint"],
            in_amount=int(data["inAmount"]),
            out_amount=int(data["outAmount"]),
            price_impact_pct=float(data.get("priceImpactPct", 0)),
            route_plan=data.get("routePlan", []),
            raw_response=data
        )
    
    JUPITER_SWAP_API = "https://public.jupiterapi.com/swap"

    def get_swap_transaction_sync(self, quote: SwapQuote, user_wallet: str) -> str:
        """Get serialized swap transaction (base64) from Jupiter."""
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                self.JUPITER_SWAP_API,
                json={
                    "quoteResponse": quote.raw_response,
                    "userPublicKey": user_wallet,
                    "wrapAndUnwrapSol": True,
                    "dynamicComputeUnitLimit": True,
                    "prioritizationFeeLamports": "auto"
                }
            )
            response.raise_for_status()
            return response.json()["swapTransaction"]

    async def build_transaction(self, action: Dict[str, Any], user_wallet: str) -> AdapterResult:
        try:
            params = action.get("parameters", {})
            input_token = params.get("inputToken", "")
            output_token = params.get("outputToken", "")
            
            input_mint = get_mint_address(input_token)
            output_mint = get_mint_address(output_token)
            
            if not input_mint:
                return AdapterResult(success=False, error=f"Unknown input token: {input_token}")
            if not output_mint:
                return AdapterResult(success=False, error=f"Unknown output token: {output_token}")
            
            amount = params.get("amount", 0)
            raw_amount = amount_to_raw(amount, input_token)
            slippage_bps = params.get("slippageBps", 50)
            
            quote = self.get_quote_sync(input_mint, output_mint, raw_amount, slippage_bps)
            
            # Fetch the actual transaction for execution
            swap_tx = self.get_swap_transaction_sync(quote, user_wallet)
            
            return AdapterResult(
                success=True,
                accounts=self.get_affected_accounts(action, user_wallet),
                metadata={
                    "quote": {
                        "inputAmount": quote.in_amount,
                        "outputAmount": quote.out_amount,
                        "priceImpactPct": quote.price_impact_pct,
                        "inputToken": input_token,
                        "outputToken": output_token,
                    },
                    "route": quote.route_plan,
                    "swapTransaction": swap_tx  # Include the serialized TX
                }
            )
        except Exception as e:
            return AdapterResult(success=False, error=f"Jupiter error: {e}")
    
    def get_affected_accounts(self, action: Dict[str, Any], user_wallet: str) -> List[str]:
        return [user_wallet]
    
    def validate_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        params = action.get("parameters", {})
        
        if action.get("type") != "swap":
            errors.append(f"Jupiter only supports 'swap', got: {action.get('type')}")
        if not params.get("inputToken"):
            errors.append("Missing inputToken")
        if not params.get("outputToken"):
            errors.append("Missing outputToken")
        if not params.get("amount"):
            errors.append("Missing amount")
        
        return {"valid": len(errors) == 0, "errors": errors}


jupiter_adapter = JupiterAdapter()
register_adapter(jupiter_adapter)


def get_jupiter_quote_sync(input_token: str, output_token: str, amount: float, slippage_bps: int = 50):
    input_mint = get_mint_address(input_token)
    output_mint = get_mint_address(output_token)
    if not input_mint or not output_mint:
        return None
    raw_amount = amount_to_raw(amount, input_token)
    return jupiter_adapter.get_quote_sync(input_mint, output_mint, raw_amount, slippage_bps)
