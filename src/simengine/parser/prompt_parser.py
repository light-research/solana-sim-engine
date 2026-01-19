"""Natural Language Prompt Parser using OpenAI GPT-4o."""

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from openai import OpenAI


SYSTEM_PROMPT = """You are a Solana simulation parser. Convert user prompts to structured JSON.

Available protocols: Jupiter (swaps), Orca (LP, swaps), Solend (lending)
Available actions: swap, deposit, withdraw, borrow, repay
Token symbols: SOL, USDC, USDT, mSOL, JitoSOL, RAY, ORCA, JUP, BONK

Output JSON format:
{
  "actions": [{"protocol": "jupiter", "type": "swap", "parameters": {"inputToken": "...", "outputToken": "...", "amount": 100, "slippageBps": 50}}],
  "validation": {"isValid": true, "errors": []}
}

If prompt is ambiguous, set isValid: false and include errors array.
Default slippageBps to 50 if not specified.
"""


@dataclass
class Action:
    protocol: str
    type: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class ParsedIntent:
    actions: List[Action]
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class PromptParser:
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set")
        self.client = OpenAI(api_key=self.api_key)
    
    def parse(self, prompt: str) -> ParsedIntent:
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1000
            )
            raw = json.loads(response.choices[0].message.content)
            return self._parse_response(raw)
        except Exception as e:
            return ParsedIntent(actions=[], is_valid=False, errors=[f"Parser error: {e}"])
    
    def _parse_response(self, raw: dict) -> ParsedIntent:
        validation = raw.get("validation", {})
        actions = [
            Action(
                protocol=a.get("protocol", "jupiter"),
                type=a.get("type", "swap"),
                parameters=a.get("parameters", {})
            )
            for a in raw.get("actions", [])
        ]
        return ParsedIntent(
            actions=actions,
            is_valid=validation.get("isValid", False),
            errors=validation.get("errors", []),
            suggestions=raw.get("suggestions", [])
        )


def parse_prompt(prompt: str) -> ParsedIntent:
    return PromptParser().parse(prompt)
