"""
Adversarial Agent: LLM-powered attacker that reasons about exploits.
"""

import json
import os
from typing import List, Optional, Dict, Any

from openai import OpenAI

from ..analysis.models import ProgramAnalysis
from ..fuzzing.models import Scenario, ScenarioStep, ScenarioType, ExpectedOutcome
from .playbook import AttackPlaybook, AttackVector, AttackCategory


class AdversarialAgent:
    """
    LLM-powered adversarial agent that attempts to exploit protocols.
    
    Unlike the ScenarioGenerator which explores broadly, this agent
    has explicit malicious intent and reasons step-by-step about
    how to break the protocol.
    """
    
    SYSTEM_PROMPT = """You are a highly skilled Solana security researcher with adversarial intent.
Your goal is to find vulnerabilities and exploits in Solana programs.

You think like an attacker:
- What valuable assets does this protocol control?
- How can I extract those assets without authorization?
- What access controls exist and how can they be bypassed?
- What assumptions does the protocol make that I can violate?

You are methodical:
1. Analyze the attack surface
2. Identify high-value targets
3. Select attack vectors
4. Craft exploitation steps
5. Verify success conditions

You output concrete, executable attack scenarios."""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the adversarial agent."""
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required.")
        
        self.client = OpenAI(api_key=self.api_key)
        self.playbook = AttackPlaybook()
    
    def analyze_attack_surface(self, analysis: ProgramAnalysis) -> Dict[str, Any]:
        """Analyze the program for potential attack surface."""
        surface = {
            "high_value_targets": [],
            "privileged_functions": [],
            "fund_flows": [],
            "applicable_attacks": [],
        }
        
        # Identify high-value targets (vaults, treasuries, etc.)
        for ix in analysis.instructions:
            if ix.modifies_funds:
                for acc in ix.accounts:
                    if any(kw in acc.name.lower() for kw in ["vault", "treasury", "pool", "reserve"]):
                        surface["high_value_targets"].append({
                            "account": acc.name,
                            "instruction": ix.name,
                        })
        
        # Identify privileged functions
        for ix in analysis.instructions:
            if ix.is_privileged:
                surface["privileged_functions"].append({
                    "name": ix.name,
                    "authority_account": next(
                        (a.name for a in ix.accounts if a.is_signer and "authority" in a.name.lower()),
                        "unknown"
                    ),
                })
        
        # Map fund flows
        surface["fund_flows"] = [
            {"instruction": ff.instruction, "from": ff.source, "to": ff.destination}
            for ff in analysis.fund_flows
        ]
        
        # Get applicable attacks from playbook
        applicable = self.playbook.get_applicable(analysis)
        surface["applicable_attacks"] = [
            {"name": v.name, "category": v.category.value, "severity": v.severity.value}
            for v in applicable
        ]
        
        return surface
    
    def generate_attack_scenarios(
        self,
        analysis: ProgramAnalysis,
        focus: Optional[str] = None,
        num_scenarios: int = 5,
    ) -> List[Scenario]:
        """
        Generate attack scenarios for the program.
        
        Args:
            analysis: Program analysis
            focus: Optional focus area (e.g., "fund-extraction", "access-control")
            num_scenarios: Number of scenarios to generate
            
        Returns:
            List of attack scenarios
        """
        # Analyze attack surface
        surface = self.analyze_attack_surface(analysis)
        
        # Get relevant attack vectors
        if focus:
            category_map = {
                "fund-extraction": AttackCategory.FUND_EXTRACTION,
                "funds": AttackCategory.FUND_EXTRACTION,
                "privilege": AttackCategory.PRIVILEGE_ESCALATION,
                "access-control": AttackCategory.PRIVILEGE_ESCALATION,
                "dos": AttackCategory.DENIAL_OF_SERVICE,
                "state": AttackCategory.STATE_CORRUPTION,
                "oracle": AttackCategory.ORACLE_MANIPULATION,
                "reentrancy": AttackCategory.REENTRANCY,
            }
            category = category_map.get(focus.lower())
            if category:
                vectors = self.playbook.get_by_category(category)
            else:
                vectors = self.playbook.vectors[:5]
        else:
            vectors = self.playbook.get_by_severity(self.playbook.vectors[0].severity)[:5]
        
        # Build prompt
        prompt = self._build_attack_prompt(analysis, surface, vectors, num_scenarios)
        
        # Call LLM
        response = self._call_llm(prompt)
        
        # Parse into scenarios
        scenarios = self._parse_attack_response(response)
        
        return scenarios[:num_scenarios]
    
    def _build_attack_prompt(
        self,
        analysis: ProgramAnalysis,
        surface: Dict,
        vectors: List[AttackVector],
        num_scenarios: int,
    ) -> str:
        """Build the prompt for attack generation."""
        
        # Format instructions
        instructions_desc = []
        for ix in analysis.instructions:
            acc_list = ", ".join([
                f"{a.name}{'(signer)' if a.is_signer else ''}"
                for a in ix.accounts
            ])
            instructions_desc.append(f"- {ix.name}: [{acc_list}]")
        
        # Format attack surface
        targets_desc = "\n".join([
            f"- {t['account']} (accessed by {t['instruction']})"
            for t in surface["high_value_targets"]
        ]) or "No obvious high-value targets"
        
        privileged_desc = "\n".join([
            f"- {p['name']} (requires {p['authority_account']})"
            for p in surface["privileged_functions"]
        ]) or "No privileged functions"
        
        # Format attack vectors to try
        vectors_desc = "\n".join([
            f"- {v.name}: {v.description}"
            for v in vectors
        ])
        
        prompt = f"""## TARGET ANALYSIS

Program: {analysis.name}

### Instructions
{chr(10).join(instructions_desc)}

### High-Value Targets
{targets_desc}

### Privileged Functions
{privileged_desc}

### Fund Flows
{chr(10).join([f"- {ff.instruction}: {ff.source} -> {ff.destination}" for ff in analysis.fund_flows]) or "None detected"}

---

## ATTACK MISSION

You are attempting to exploit this protocol. Your objectives (in order of priority):
1. Extract funds without authorization
2. Gain admin/authority access
3. Corrupt protocol state
4. Render protocol unusable

### Available Attack Vectors
{vectors_desc}

---

## YOUR TASK

Generate {num_scenarios} concrete attack scenarios. Each scenario should:
1. Have a clear exploitation objective
2. Include specific transaction steps
3. Explain the attack logic
4. Define what constitutes successful exploitation

Output as JSON array:
```json
[
  {{
    "name": "Attack Name",
    "description": "What this attack does and why it might work",
    "objective": "Extract funds / Gain access / Corrupt state / etc.",
    "attack_vector": "Which attack type this is",
    "steps": [
      {{"instruction": "...", "arguments": {{}}, "signer": "attacker", "note": "Why this step"}}
    ],
    "success_condition": "What indicates successful exploitation"
  }}
]
```

Think step by step about how to exploit this protocol. Be creative but realistic.
Generate {num_scenarios} attack scenarios now:"""

        return prompt
    
    def _call_llm(self, prompt: str) -> str:
        """Call the LLM."""
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.8,  # Higher temperature for creative attacks
                max_tokens=4000,
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"LLM call failed: {e}")
    
    def _parse_attack_response(self, response: str) -> List[Scenario]:
        """Parse LLM response into attack scenarios."""
        scenarios = []
        
        # Extract JSON
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
            print(f"Warning: Failed to parse attack response: {e}")
            return []
        
        if not isinstance(data, list):
            data = [data]
        
        for item in data:
            try:
                steps = []
                for step_data in item.get("steps", []):
                    step = ScenarioStep(
                        instruction=step_data.get("instruction", "unknown"),
                        arguments=step_data.get("arguments", {}),
                        signer=step_data.get("signer", "attacker"),
                        description=step_data.get("note"),
                    )
                    steps.append(step)
                
                scenario = Scenario(
                    name=item.get("name", "Unnamed Attack"),
                    description=item.get("description", ""),
                    scenario_type=ScenarioType.ADVERSARIAL,
                    steps=steps,
                    expected_outcome=ExpectedOutcome.SUCCESS,  # Attacker wants success
                    tags=[
                        item.get("attack_vector", "unknown"),
                        item.get("objective", "unknown"),
                    ],
                )
                scenarios.append(scenario)
            except Exception as e:
                print(f"Warning: Failed to parse attack scenario: {e}")
                continue
        
        return scenarios
