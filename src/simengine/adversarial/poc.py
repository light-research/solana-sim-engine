"""
PoC Generator: Creates reproducible Proof-of-Concept exploits.
"""

import json
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class PoCTransaction:
    """A single transaction in a PoC exploit."""
    instruction_name: str
    program_id: Optional[str] = None
    accounts: List[Dict[str, Any]] = field(default_factory=list)
    data: Optional[bytes] = None
    data_base64: Optional[str] = None
    signers: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class ProofOfConcept:
    """A complete Proof-of-Concept exploit."""
    name: str
    vulnerability: str
    severity: str
    description: str
    
    # Setup requirements
    required_accounts: List[Dict[str, str]] = field(default_factory=list)
    required_balance: Dict[str, float] = field(default_factory=dict)  # token -> amount
    
    # Exploit steps
    transactions: List[PoCTransaction] = field(default_factory=list)
    
    # Expected outcome
    expected_result: str = ""
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tested_on: Optional[str] = None  # Network/environment
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export."""
        return {
            "name": self.name,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "description": self.description,
            "setup": {
                "accounts": self.required_accounts,
                "balance": self.required_balance,
            },
            "transactions": [
                {
                    "instruction": tx.instruction_name,
                    "program_id": tx.program_id,
                    "accounts": tx.accounts,
                    "data_base64": tx.data_base64,
                    "signers": tx.signers,
                    "description": tx.description,
                }
                for tx in self.transactions
            ],
            "expected_result": self.expected_result,
            "metadata": {
                "created_at": self.created_at,
                "tested_on": self.tested_on,
            },
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_replay_script(self) -> str:
        """Generate a TypeScript replay script."""
        script = f'''// PoC Replay Script: {self.name}
// Vulnerability: {self.vulnerability}
// Severity: {self.severity}
// Generated: {self.created_at}

import {{ Connection, Keypair, Transaction, TransactionInstruction, PublicKey }} from "@solana/web3.js";

async function executePoC() {{
    // DANGER: This is a proof-of-concept exploit
    // DO NOT run against mainnet with real funds
    
    const connection = new Connection("http://127.0.0.1:8899", "confirmed");
    
    // Setup accounts (replace with actual keypairs)
'''
        
        for i, acc in enumerate(self.required_accounts):
            script += f'    const account{i} = Keypair.generate(); // {acc.get("name", "unknown")}\n'
        
        script += '\n    // Execute exploit transactions\n'
        
        for i, tx in enumerate(self.transactions):
            script += f'''
    // Step {i + 1}: {tx.description or tx.instruction_name}
    const ix{i} = new TransactionInstruction({{
        programId: new PublicKey("{tx.program_id or 'PROGRAM_ID'}"),
        keys: {json.dumps(tx.accounts)},
        data: Buffer.from("{tx.data_base64 or ''}", "base64"),
    }});
    
    const tx{i} = new Transaction().add(ix{i});
    const sig{i} = await connection.sendTransaction(tx{i}, [{', '.join(tx.signers) or 'payer'}]);
    console.log("Step {i + 1} signature:", sig{i});
'''
        
        script += '''
    console.log("\\n✅ PoC execution complete");
}

executePoC().catch(console.error);
'''
        return script


class PoCGenerator:
    """
    Generates Proof-of-Concept exploits from vulnerability findings.
    """
    
    def __init__(self):
        self.pocs: List[ProofOfConcept] = []
    
    def generate_from_scenario(
        self,
        scenario,
        result,
        vulnerability_name: str,
        severity: str,
    ) -> ProofOfConcept:
        """
        Generate a PoC from a scenario and its execution result.
        
        Args:
            scenario: The attack scenario
            result: The execution result
            vulnerability_name: Name of the vulnerability
            severity: Severity level
            
        Returns:
            ProofOfConcept object
        """
        # Build transaction list from scenario steps
        transactions = []
        for i, step in enumerate(scenario.steps):
            tx = PoCTransaction(
                instruction_name=step.instruction,
                accounts=[
                    {"name": k, "value": v}
                    for k, v in step.accounts.items()
                ],
                signers=[step.signer] if step.signer else ["attacker"],
                description=step.description or f"Step {i + 1}: {step.instruction}",
            )
            
            # Add argument data
            if step.arguments:
                tx.data_base64 = base64.b64encode(
                    json.dumps(step.arguments).encode()
                ).decode()
            
            transactions.append(tx)
        
        # Build required accounts
        required_accounts = []
        seen_accounts = set()
        for step in scenario.steps:
            for name, value in step.accounts.items():
                if name not in seen_accounts:
                    required_accounts.append({
                        "name": name,
                        "type": "generated" if value == "generate" else "provided",
                        "value": value,
                    })
                    seen_accounts.add(name)
        
        poc = ProofOfConcept(
            name=f"PoC: {scenario.name}",
            vulnerability=vulnerability_name,
            severity=severity,
            description=scenario.description,
            required_accounts=required_accounts,
            transactions=transactions,
            expected_result="Successful exploitation" if result.passed else "Attack blocked",
            tested_on="Surfpool (local fork)",
        )
        
        self.pocs.append(poc)
        return poc
    
    def export_all(self, output_dir: str):
        """Export all PoCs to files."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        for i, poc in enumerate(self.pocs):
            # Export JSON
            json_path = os.path.join(output_dir, f"poc_{i + 1}.json")
            with open(json_path, "w") as f:
                f.write(poc.to_json())
            
            # Export TypeScript replay script
            ts_path = os.path.join(output_dir, f"poc_{i + 1}_replay.ts")
            with open(ts_path, "w") as f:
                f.write(poc.to_replay_script())
        
        # Export summary
        summary = {
            "total_pocs": len(self.pocs),
            "pocs": [
                {
                    "name": poc.name,
                    "vulnerability": poc.vulnerability,
                    "severity": poc.severity,
                    "file": f"poc_{i + 1}.json",
                }
                for i, poc in enumerate(self.pocs)
            ],
        }
        
        summary_path = os.path.join(output_dir, "poc_summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        
        return output_dir
