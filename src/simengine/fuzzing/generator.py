"""
Scenario Generator: Uses LLM to generate test scenarios based on program analysis.
"""

import json
import os
from typing import List, Optional, Dict, Any

from openai import OpenAI

from ..analysis.models import ProgramAnalysis, InstructionSpec
from .models import (
    Scenario,
    ScenarioStep,
    ScenarioType,
    ExpectedOutcome,
    InitialState,
    FuzzingConfig,
)


class ScenarioGenerator:
    """
    LLM-powered scenario generator.
    
    Analyzes a program and generates meaningful test scenarios
    covering happy paths, edge cases, and potential vulnerabilities.
    """
    
    SYSTEM_PROMPT = """You are an expert Solana protocol security engineer and QA specialist.
Your task is to generate comprehensive test scenarios for a Solana program.

You understand:
- Solana's account model (signers, PDAs, ATAs)
- Common DeFi patterns (vaults, AMMs, lending)
- Security vulnerabilities (reentrancy, access control, integer overflow)
- Edge cases (boundary values, race conditions, state corruption)

When generating scenarios, you should:
1. Cover all instruction paths
2. Test boundary conditions (0, max, off-by-one)
3. Verify access controls (can unauthorized users call privileged functions?)
4. Check state transitions (what happens if called in wrong order?)
5. Look for fund extraction opportunities

Output your scenarios as a JSON array."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the generator with OpenAI API key."""
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY environment variable.")
        
        self.client = OpenAI(api_key=self.api_key)
    
    def generate(
        self,
        analysis: ProgramAnalysis,
        config: FuzzingConfig,
        user_prompt: Optional[str] = None,
    ) -> List[Scenario]:
        """
        Generate test scenarios for the given program.
        
        Args:
            analysis: Parsed program analysis
            config: Fuzzing configuration
            user_prompt: Optional user guidance (e.g., "focus on honeypot detection")
            
        Returns:
            List of generated scenarios
        """
        # Build the prompt
        prompt = self._build_prompt(analysis, config, user_prompt)
        
        # Call LLM
        response = self._call_llm(prompt)
        
        # Parse response into Scenario objects
        scenarios = self._parse_response(response, analysis)
        
        return scenarios[:config.num_scenarios]
    
    def _build_prompt(
        self,
        analysis: ProgramAnalysis,
        config: FuzzingConfig,
        user_prompt: Optional[str] = None,
    ) -> str:
        """Build the prompt for the LLM."""
        
        # Format program information
        instructions_desc = []
        for ix in analysis.instructions:
            acc_list = ", ".join([
                f"{a.name}{'(signer)' if a.is_signer else ''}{'(mut)' if a.is_writable else ''}"
                for a in ix.accounts
            ])
            arg_list = ", ".join([f"{a.name}: {a.arg_type}" for a in ix.arguments])
            
            flags = []
            if ix.is_privileged:
                flags.append("PRIVILEGED")
            if ix.modifies_funds:
                flags.append("MOVES_FUNDS")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            
            instructions_desc.append(
                f"- {ix.name}{flag_str}\n"
                f"  Accounts: [{acc_list}]\n"
                f"  Args: [{arg_list}]"
            )
        
        # Format invariants
        invariants_desc = "\n".join([
            f"- {inv.name}: {inv.description}"
            for inv in analysis.invariants
        ]) or "No explicit invariants detected."
        
        # Mode-specific instructions
        if config.mode == "attack":
            mode_instructions = """
ADVERSARIAL MODE: Your goal is to EXPLOIT the protocol.
- Generate scenarios that attempt to extract funds illegally
- Try to bypass access controls
- Look for ways to corrupt state or cause DoS
- Each scenario should have a clear attack objective"""
        else:
            mode_instructions = """
EXPLORATION MODE: Your goal is to thoroughly TEST the protocol.
- Generate scenarios covering all instruction paths
- Test happy paths and error cases
- Check boundary conditions
- Verify expected behavior under various states"""
        
        # Focus areas
        focus_str = ""
        if config.focus_areas:
            focus_str = f"\nFocus especially on: {', '.join(config.focus_areas)}"
        
        # User guidance
        user_guidance = ""
        if user_prompt:
            user_guidance = f"\nUser Request: {user_prompt}"
        
        prompt = f"""## Program Analysis

Program: {analysis.name}
{analysis.program_id or "Program ID: Unknown"}

### Instructions
{chr(10).join(instructions_desc)}

### Detected Invariants
{invariants_desc}

### Fund Flows
{chr(10).join([f"- {ff.instruction}: {ff.source} -> {ff.destination}" for ff in analysis.fund_flows]) or "None detected"}

---

{mode_instructions}
{focus_str}
{user_guidance}

Generate {config.num_scenarios} test scenarios.

For each scenario provide:
1. name: Short descriptive name
2. description: What this tests and why
3. type: One of [happy_path, boundary, negative, permutation, adversarial]
4. steps: Array of instruction calls with:
   - instruction: Name of instruction
   - arguments: Dict of argument values
   - signer: Which wallet signs (e.g., "user", "attacker", "authority")
5. expected_outcome: "success" or "failure"
6. expected_error: If failure expected, what error message?

Output as JSON array. Example:
```json
[
  {{
    "name": "Normal deposit flow",
    "description": "Verify basic deposit works with valid inputs",
    "type": "happy_path",
    "steps": [
      {{"instruction": "initialize", "arguments": {{}}, "signer": "authority"}},
      {{"instruction": "deposit", "arguments": {{"amount": 1000}}, "signer": "user"}}
    ],
    "expected_outcome": "success",
    "expected_error": null
  }},
  {{
    "name": "Deposit without initialization",
    "description": "Deposit should fail if vault not initialized",
    "type": "negative",
    "steps": [
      {{"instruction": "deposit", "arguments": {{"amount": 1000}}, "signer": "user"}}
    ],
    "expected_outcome": "failure",
    "expected_error": "AccountNotInitialized"
  }}
]
```

Generate {config.num_scenarios} scenarios now:"""

        return prompt
    
    def _call_llm(self, prompt: str) -> str:
        """Call the LLM and get response."""
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=4000,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"LLM call failed: {e}")
    
    def _parse_response(self, response: str, analysis: ProgramAnalysis) -> List[Scenario]:
        """Parse LLM response into Scenario objects."""
        scenarios = []
        
        # Extract JSON from response (handle markdown code blocks)
        json_str = response
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            json_str = response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            json_str = response[start:end].strip()
        
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse LLM response as JSON: {e}")
            print(f"Response: {response[:500]}...")
            return []
        
        if not isinstance(data, list):
            data = [data]
        
        for item in data:
            try:
                scenario = self._item_to_scenario(item)
                scenarios.append(scenario)
            except Exception as e:
                print(f"Warning: Failed to convert item to scenario: {e}")
                continue
        
        return scenarios
    
    def _item_to_scenario(self, item: Dict) -> Scenario:
        """Convert a dictionary item to a Scenario object."""
        # Parse type
        type_str = item.get("type", "happy_path").lower()
        type_map = {
            "happy_path": ScenarioType.HAPPY_PATH,
            "boundary": ScenarioType.BOUNDARY,
            "negative": ScenarioType.NEGATIVE,
            "permutation": ScenarioType.PERMUTATION,
            "adversarial": ScenarioType.ADVERSARIAL,
        }
        scenario_type = type_map.get(type_str, ScenarioType.HAPPY_PATH)
        
        # Parse expected outcome
        outcome_str = item.get("expected_outcome", "observe").lower()
        outcome_map = {
            "success": ExpectedOutcome.SUCCESS,
            "failure": ExpectedOutcome.FAILURE,
            "observe": ExpectedOutcome.OBSERVE,
        }
        expected_outcome = outcome_map.get(outcome_str, ExpectedOutcome.OBSERVE)
        
        # Parse steps
        steps = []
        for step_data in item.get("steps", []):
            step = ScenarioStep(
                instruction=step_data.get("instruction", "unknown"),
                arguments=step_data.get("arguments", {}),
                signer=step_data.get("signer"),
                accounts=step_data.get("accounts", {}),
            )
            steps.append(step)
        
        return Scenario(
            name=item.get("name", "Unnamed Scenario"),
            description=item.get("description", "No description"),
            scenario_type=scenario_type,
            steps=steps,
            expected_outcome=expected_outcome,
            expected_error=item.get("expected_error"),
            tags=item.get("tags", []),
        )
    
    def generate_for_instruction(
        self,
        analysis: ProgramAnalysis,
        instruction_name: str,
        num_scenarios: int = 5,
    ) -> List[Scenario]:
        """Generate scenarios focused on a specific instruction."""
        config = FuzzingConfig(
            num_scenarios=num_scenarios,
            focus_areas=[f"instruction:{instruction_name}"],
        )
        return self.generate(
            analysis,
            config,
            user_prompt=f"Focus on testing the '{instruction_name}' instruction comprehensively.",
        )
