"""
IDL Parser for Anchor programs.

Parses Anchor IDL JSON files to extract program structure and semantics.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .models import (
    ProgramAnalysis,
    InstructionSpec,
    AccountSpec,
    ArgumentSpec,
    Constraint,
    Invariant,
    FundFlow,
)


class IDLParser:
    """
    Parser for Anchor IDL files.
    
    Extracts program structure, instruction signatures, account requirements,
    and attempts to infer semantic information (privileged ops, fund flows).
    """
    
    # Keywords that suggest privileged operations
    PRIVILEGED_KEYWORDS = ["admin", "authority", "owner", "governance", "emergency"]
    
    # Keywords that suggest fund movement
    FUND_KEYWORDS = ["deposit", "withdraw", "transfer", "swap", "claim", "stake", "unstake"]
    
    # Keywords that suggest account creation
    CREATE_KEYWORDS = ["initialize", "create", "open", "init"]
    
    # Keywords that suggest account closing
    CLOSE_KEYWORDS = ["close", "delete", "remove", "destroy"]
    
    def __init__(self):
        self.idl: Optional[Dict] = None
        
    def parse_file(self, path: Union[str, Path]) -> ProgramAnalysis:
        """Parse an IDL file from disk."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"IDL file not found: {path}")
        
        with open(path, "r") as f:
            idl_data = json.load(f)
        
        return self.parse(idl_data)
    
    def parse(self, idl: Dict) -> ProgramAnalysis:
        """Parse an IDL dictionary."""
        self.idl = idl
        
        analysis = ProgramAnalysis(
            program_id=idl.get("address") or idl.get("metadata", {}).get("address"),
            name=idl.get("name", "Unknown"),
            version=idl.get("version"),
            raw_idl=idl,
        )
        
        # Parse instructions
        instructions = idl.get("instructions", [])
        for ix_data in instructions:
            ix = self._parse_instruction(ix_data)
            analysis.instructions.append(ix)
        
        # Parse account types (if present)
        accounts = idl.get("accounts", [])
        for acc_data in accounts:
            acc = self._parse_global_account(acc_data)
            analysis.accounts.append(acc)
        
        # Infer invariants
        analysis.invariants = self._infer_invariants(analysis)
        
        # Infer fund flows
        analysis.fund_flows = self._infer_fund_flows(analysis)
        
        return analysis
    
    def _parse_instruction(self, ix_data: Dict) -> InstructionSpec:
        """Parse a single instruction from IDL."""
        name = ix_data.get("name", "unknown")
        
        # Parse accounts
        accounts = []
        for acc_data in ix_data.get("accounts", []):
            acc = self._parse_instruction_account(acc_data)
            accounts.append(acc)
        
        # Parse arguments
        arguments = []
        for arg_data in ix_data.get("args", []):
            arg = self._parse_argument(arg_data)
            arguments.append(arg)
        
        # Extract discriminator if present
        discriminator = None
        if "discriminator" in ix_data:
            disc = ix_data["discriminator"]
            if isinstance(disc, list):
                discriminator = bytes(disc)
        
        # Infer semantic properties
        name_lower = name.lower()
        is_privileged = any(kw in name_lower for kw in self.PRIVILEGED_KEYWORDS)
        modifies_funds = any(kw in name_lower for kw in self.FUND_KEYWORDS)
        can_create = any(kw in name_lower for kw in self.CREATE_KEYWORDS)
        can_close = any(kw in name_lower for kw in self.CLOSE_KEYWORDS)
        
        # Check if any account is an "authority" type
        for acc in accounts:
            if acc.is_signer and any(kw in acc.name.lower() for kw in self.PRIVILEGED_KEYWORDS):
                is_privileged = True
                break
        
        # Extract constraints from docs or other metadata
        constraints = self._extract_constraints(ix_data)
        
        return InstructionSpec(
            name=name,
            discriminator=discriminator,
            accounts=accounts,
            arguments=arguments,
            description=ix_data.get("docs", [""])[0] if ix_data.get("docs") else None,
            constraints=constraints,
            is_privileged=is_privileged,
            modifies_funds=modifies_funds,
            can_create_accounts=can_create,
            can_close_accounts=can_close,
        )
    
    def _parse_instruction_account(self, acc_data: Dict) -> AccountSpec:
        """Parse an account from an instruction's account list."""
        # Handle both old and new IDL formats
        name = acc_data.get("name", "unknown")
        
        # Old format: isMut, isSigner
        # New format: writable, signer (or nested in 'account')
        is_writable = acc_data.get("writable", acc_data.get("isMut", False))
        is_signer = acc_data.get("signer", acc_data.get("isSigner", False))
        is_optional = acc_data.get("optional", False)
        
        # Extract PDA seeds if present
        pda_seeds = None
        if "pda" in acc_data:
            pda = acc_data["pda"]
            if "seeds" in pda:
                pda_seeds = [str(s) for s in pda["seeds"]]
        
        return AccountSpec(
            name=name,
            is_signer=is_signer,
            is_writable=is_writable,
            is_optional=is_optional,
            pda_seeds=pda_seeds,
            description=acc_data.get("docs", [""])[0] if acc_data.get("docs") else None,
        )
    
    def _parse_argument(self, arg_data: Dict) -> ArgumentSpec:
        """Parse an instruction argument."""
        name = arg_data.get("name", "arg")
        
        # Type can be simple string or complex object
        arg_type = arg_data.get("type", "unknown")
        if isinstance(arg_type, dict):
            # Complex type like {defined: "MyStruct"} or {vec: "u8"}
            arg_type = json.dumps(arg_type)
        
        # Set reasonable bounds for numeric types
        min_val, max_val = None, None
        type_lower = str(arg_type).lower()
        if "u64" in type_lower:
            min_val, max_val = 0, 2**64 - 1
        elif "u32" in type_lower:
            min_val, max_val = 0, 2**32 - 1
        elif "u8" in type_lower:
            min_val, max_val = 0, 255
        
        return ArgumentSpec(
            name=name,
            arg_type=str(arg_type),
            min_value=min_val,
            max_value=max_val,
        )
    
    def _parse_global_account(self, acc_data: Dict) -> AccountSpec:
        """Parse a global account type definition."""
        return AccountSpec(
            name=acc_data.get("name", "unknown"),
            description=acc_data.get("docs", [""])[0] if acc_data.get("docs") else None,
        )
    
    def _extract_constraints(self, ix_data: Dict) -> List[Constraint]:
        """Extract constraints from instruction definition."""
        constraints = []
        
        # Look for constraint requirements in accounts
        for acc in ix_data.get("accounts", []):
            if acc.get("signer") or acc.get("isSigner"):
                constraints.append(Constraint(
                    description=f"{acc.get('name')} must be a signer",
                    constraint_type="signer",
                ))
        
        return constraints
    
    def _infer_invariants(self, analysis: ProgramAnalysis) -> List[Invariant]:
        """Infer protocol invariants from structure."""
        invariants = []
        
        # If there's a deposit and withdraw, balance should be preserved
        has_deposit = any("deposit" in ix.name.lower() for ix in analysis.instructions)
        has_withdraw = any("withdraw" in ix.name.lower() for ix in analysis.instructions)
        
        if has_deposit and has_withdraw:
            invariants.append(Invariant(
                name="Balance Conservation",
                description="Total deposits should be >= total withdrawals",
                severity="critical",
            ))
        
        # If there's initialize and close, lifecycle should be enforced
        has_init = any(kw in ix.name.lower() for ix in analysis.instructions for kw in self.CREATE_KEYWORDS)
        has_close = any(kw in ix.name.lower() for ix in analysis.instructions for kw in self.CLOSE_KEYWORDS)
        
        if has_init and has_close:
            invariants.append(Invariant(
                name="Lifecycle Integrity",
                description="Account must be initialized before use and not used after close",
                severity="high",
            ))
        
        return invariants
    
    def _infer_fund_flows(self, analysis: ProgramAnalysis) -> List[FundFlow]:
        """Infer how funds move based on instruction structure."""
        flows = []
        
        for ix in analysis.instructions:
            if ix.modifies_funds:
                # Try to identify source and destination from accounts
                source, dest = None, None
                for acc in ix.accounts:
                    name_lower = acc.name.lower()
                    if any(kw in name_lower for kw in ["from", "source", "user", "sender"]):
                        source = acc.name
                    elif any(kw in name_lower for kw in ["to", "dest", "vault", "recipient", "pool"]):
                        dest = acc.name
                
                if source or dest:
                    flows.append(FundFlow(
                        instruction=ix.name,
                        source=source or "unknown",
                        destination=dest or "unknown",
                        token="unknown",
                    ))
        
        return flows
