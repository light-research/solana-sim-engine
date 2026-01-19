"""
Invariant Extraction: Automatically identifies protocol invariants.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from .models import ProgramAnalysis, InstructionSpec, Invariant


class InvariantType:
    """Types of invariants."""
    BALANCE = "balance"
    ACCESS_CONTROL = "access_control"
    STATE = "state"
    ARITHMETIC = "arithmetic"
    LIFECYCLE = "lifecycle"


@dataclass
class ExtractedInvariant(Invariant):
    """An invariant extracted from program analysis."""
    invariant_type: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    source: str = ""  # Where this was inferred from


class InvariantExtractor:
    """
    Extracts protocol invariants from program analysis.
    
    Uses heuristics and patterns to identify:
    - Balance conservation rules
    - Access control requirements
    - State machine constraints
    - Arithmetic bounds
    """
    
    def extract(self, analysis: ProgramAnalysis) -> List[ExtractedInvariant]:
        """
        Extract all invariants from program analysis.
        
        Args:
            analysis: Parsed program analysis
            
        Returns:
            List of extracted invariants
        """
        invariants = []
        
        # Extract different types of invariants
        invariants.extend(self._extract_balance_invariants(analysis))
        invariants.extend(self._extract_access_invariants(analysis))
        invariants.extend(self._extract_lifecycle_invariants(analysis))
        invariants.extend(self._extract_arithmetic_invariants(analysis))
        
        return invariants
    
    def _extract_balance_invariants(self, analysis: ProgramAnalysis) -> List[ExtractedInvariant]:
        """Extract balance-related invariants."""
        invariants = []
        
        # Check for deposit/withdraw pattern
        has_deposit = any("deposit" in ix.name.lower() for ix in analysis.instructions)
        has_withdraw = any("withdraw" in ix.name.lower() for ix in analysis.instructions)
        
        if has_deposit and has_withdraw:
            invariants.append(ExtractedInvariant(
                name="Balance Conservation",
                description="Total deposits must be greater than or equal to total withdrawals",
                check_expression="sum(deposits) >= sum(withdrawals)",
                severity="critical",
                invariant_type=InvariantType.BALANCE,
                confidence=0.95,
                source="deposit/withdraw instruction pair",
            ))
            
            invariants.append(ExtractedInvariant(
                name="No Negative Balance",
                description="Vault balance can never be negative",
                check_expression="vault_balance >= 0",
                severity="critical",
                invariant_type=InvariantType.BALANCE,
                confidence=0.99,
                source="implicit from balance type",
            ))
        
        # Check for vault accounts
        vault_accounts = []
        for ix in analysis.instructions:
            for acc in ix.accounts:
                if any(kw in acc.name.lower() for kw in ["vault", "treasury", "pool"]):
                    vault_accounts.append(acc.name)
        
        if vault_accounts:
            invariants.append(ExtractedInvariant(
                name="Vault Integrity",
                description=f"Vault accounts ({', '.join(set(vault_accounts))}) should only be modified through authorized instructions",
                severity="critical",
                invariant_type=InvariantType.BALANCE,
                confidence=0.85,
                source="vault account pattern",
            ))
        
        return invariants
    
    def _extract_access_invariants(self, analysis: ProgramAnalysis) -> List[ExtractedInvariant]:
        """Extract access control invariants."""
        invariants = []
        
        # Find privileged instructions
        privileged = analysis.get_privileged_instructions()
        
        for ix in privileged:
            # Find the authority account
            authority = None
            for acc in ix.accounts:
                if acc.is_signer and any(kw in acc.name.lower() for kw in ["authority", "admin", "owner"]):
                    authority = acc.name
                    break
            
            if authority:
                invariants.append(ExtractedInvariant(
                    name=f"Authority Check: {ix.name}",
                    description=f"Instruction '{ix.name}' must only be callable by {authority}",
                    check_expression=f"signer == {authority}",
                    severity="critical",
                    invariant_type=InvariantType.ACCESS_CONTROL,
                    confidence=0.9,
                    source=f"signer requirement on {authority}",
                ))
        
        # Check for ownership patterns
        for ix in analysis.instructions:
            for acc in ix.accounts:
                if "owner" in acc.name.lower() and acc.is_signer:
                    invariants.append(ExtractedInvariant(
                        name=f"Ownership: {ix.name}",
                        description=f"Only the owner can execute {ix.name}",
                        severity="high",
                        invariant_type=InvariantType.ACCESS_CONTROL,
                        confidence=0.85,
                        source="owner signer pattern",
                    ))
                    break
        
        return invariants
    
    def _extract_lifecycle_invariants(self, analysis: ProgramAnalysis) -> List[ExtractedInvariant]:
        """Extract lifecycle-related invariants."""
        invariants = []
        
        # Check for init/close pattern
        has_init = any(
            any(kw in ix.name.lower() for kw in ["initialize", "create", "init"])
            for ix in analysis.instructions
        )
        has_close = any(
            any(kw in ix.name.lower() for kw in ["close", "delete"])
            for ix in analysis.instructions
        )
        
        if has_init:
            invariants.append(ExtractedInvariant(
                name="Initialize Before Use",
                description="Accounts must be initialized before any other operation",
                check_expression="is_initialized == true before any operation",
                severity="high",
                invariant_type=InvariantType.LIFECYCLE,
                confidence=0.9,
                source="initialize instruction pattern",
            ))
        
        if has_close:
            invariants.append(ExtractedInvariant(
                name="No Use After Close",
                description="Accounts cannot be used after being closed",
                check_expression="is_closed == false for all operations",
                severity="high",
                invariant_type=InvariantType.LIFECYCLE,
                confidence=0.9,
                source="close instruction pattern",
            ))
        
        if has_init and has_close:
            invariants.append(ExtractedInvariant(
                name="Single Initialization",
                description="Accounts should only be initialized once",
                check_expression="initialize called exactly once per account",
                severity="medium",
                invariant_type=InvariantType.LIFECYCLE,
                confidence=0.85,
                source="init/close lifecycle",
            ))
        
        return invariants
    
    def _extract_arithmetic_invariants(self, analysis: ProgramAnalysis) -> List[ExtractedInvariant]:
        """Extract arithmetic-related invariants."""
        invariants = []
        
        # Check for instructions with numeric arguments
        for ix in analysis.instructions:
            for arg in ix.arguments:
                if "u64" in arg.arg_type.lower() or "u128" in arg.arg_type.lower():
                    # Amount-like arguments
                    if any(kw in arg.name.lower() for kw in ["amount", "quantity", "value"]):
                        invariants.append(ExtractedInvariant(
                            name=f"Non-Zero {arg.name}",
                            description=f"Argument '{arg.name}' in {ix.name} should typically be > 0",
                            check_expression=f"{arg.name} > 0",
                            severity="low",
                            invariant_type=InvariantType.ARITHMETIC,
                            confidence=0.7,
                            source=f"amount argument pattern in {ix.name}",
                        ))
        
        # Check for fee-related invariants
        has_fee = any(
            any("fee" in arg.name.lower() for arg in ix.arguments)
            for ix in analysis.instructions
        )
        
        if has_fee:
            invariants.append(ExtractedInvariant(
                name="Fee Bounds",
                description="Protocol fees should be within reasonable bounds (e.g., < 100%)",
                check_expression="fee_bps < 10000",  # 100% in basis points
                severity="high",
                invariant_type=InvariantType.ARITHMETIC,
                confidence=0.8,
                source="fee argument pattern",
            ))
        
        return invariants
    
    def generate_test_cases(self, invariants: List[ExtractedInvariant]) -> List[Dict]:
        """
        Generate test case suggestions for each invariant.
        
        Args:
            invariants: List of extracted invariants
            
        Returns:
            List of test case suggestions
        """
        test_cases = []
        
        for inv in invariants:
            case = {
                "invariant": inv.name,
                "type": inv.invariant_type,
                "tests": [],
            }
            
            if inv.invariant_type == InvariantType.BALANCE:
                case["tests"].extend([
                    "Withdraw more than deposited",
                    "Withdraw when balance is zero",
                    "Multiple concurrent withdrawals",
                ])
            
            elif inv.invariant_type == InvariantType.ACCESS_CONTROL:
                case["tests"].extend([
                    "Call with wrong authority",
                    "Call without any signer",
                    "Call with valid signer but wrong account",
                ])
            
            elif inv.invariant_type == InvariantType.LIFECYCLE:
                case["tests"].extend([
                    "Use before initialization",
                    "Double initialization",
                    "Use after close",
                ])
            
            elif inv.invariant_type == InvariantType.ARITHMETIC:
                case["tests"].extend([
                    "Zero value input",
                    "Maximum value input (u64::MAX)",
                    "Boundary value input",
                ])
            
            test_cases.append(case)
        
        return test_cases
