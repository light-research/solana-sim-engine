"""
Attack Playbook: Collection of known attack vectors for Solana programs.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class AttackCategory(Enum):
    """Categories of attacks."""
    FUND_EXTRACTION = "fund_extraction"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    STATE_CORRUPTION = "state_corruption"
    ORACLE_MANIPULATION = "oracle_manipulation"
    REENTRANCY = "reentrancy"


class Severity(Enum):
    """Attack severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackVector:
    """A specific attack technique."""
    name: str
    category: AttackCategory
    description: str
    severity: Severity
    
    # How to detect if this attack is applicable
    preconditions: List[str] = field(default_factory=list)
    
    # Attack methodology
    attack_strategy: str = ""
    
    # Example exploitation steps
    example_steps: List[Dict[str, Any]] = field(default_factory=list)
    
    # What constitutes success
    success_indicators: List[str] = field(default_factory=list)


class AttackPlaybook:
    """
    Collection of known Solana attack vectors.
    
    Used by the AdversarialAgent to select and execute attacks.
    """
    
    def __init__(self):
        self.vectors: List[AttackVector] = self._load_vectors()
    
    def _load_vectors(self) -> List[AttackVector]:
        """Load the standard attack playbook."""
        return [
            # FUND EXTRACTION ATTACKS
            AttackVector(
                name="Unauthorized Withdrawal",
                category=AttackCategory.FUND_EXTRACTION,
                description="Attempt to withdraw funds without proper authorization",
                severity=Severity.CRITICAL,
                preconditions=[
                    "Program has withdraw instruction",
                    "Funds are held in program-controlled account",
                ],
                attack_strategy="""
1. Identify the withdraw instruction signature
2. Create transaction with attacker as beneficiary
3. Sign with attacker's keypair (not the legitimate owner)
4. Submit transaction and observe result
                """,
                success_indicators=[
                    "Transaction succeeds",
                    "Funds transferred to attacker",
                ],
            ),
            
            AttackVector(
                name="Account Substitution",
                category=AttackCategory.FUND_EXTRACTION,
                description="Replace legitimate accounts with attacker-controlled ones",
                severity=Severity.CRITICAL,
                preconditions=[
                    "Program accepts account addresses as instruction input",
                    "Insufficient validation of account ownership",
                ],
                attack_strategy="""
1. Create attacker-controlled account with similar structure
2. Pass attacker's account where legitimate account expected
3. Trigger action that moves funds to the substituted account
                """,
                success_indicators=[
                    "Funds sent to attacker's account instead of intended destination",
                ],
            ),
            
            AttackVector(
                name="Rent Drain",
                category=AttackCategory.FUND_EXTRACTION,
                description="Extract SOL by closing accounts and receiving rent",
                severity=Severity.MEDIUM,
                preconditions=[
                    "Program has close/delete instruction",
                    "Accounts hold rent-exempt SOL",
                ],
                attack_strategy="""
1. Identify closeable accounts
2. Close accounts receiving rent as attacker
3. Accumulate small amounts from many accounts
                """,
                success_indicators=[
                    "Successfully closed accounts",
                    "Rent transferred to attacker",
                ],
            ),
            
            # PRIVILEGE ESCALATION ATTACKS
            AttackVector(
                name="Authority Bypass",
                category=AttackCategory.PRIVILEGE_ESCALATION,
                description="Execute admin functions without proper authority",
                severity=Severity.CRITICAL,
                preconditions=[
                    "Program has privileged instructions",
                    "Authority check may be bypassable",
                ],
                attack_strategy="""
1. Identify admin-only instructions
2. Create transaction calling admin instruction with attacker signer
3. Test if authority check can be bypassed
                """,
                success_indicators=[
                    "Admin instruction executes for non-admin",
                ],
            ),
            
            AttackVector(
                name="PDA Authority Override",
                category=AttackCategory.PRIVILEGE_ESCALATION,
                description="Manipulate PDA derivation to gain unauthorized access",
                severity=Severity.HIGH,
                preconditions=[
                    "Program uses PDAs for access control",
                    "PDA seeds may be predictable or controllable",
                ],
                attack_strategy="""
1. Analyze PDA seed derivation
2. Find seed combination that grants attacker authority
3. Call instruction with crafted PDA
                """,
                success_indicators=[
                    "PDA validates for attacker-controlled input",
                    "Action executes with attacker's authority",
                ],
            ),
            
            # DENIAL OF SERVICE ATTACKS
            AttackVector(
                name="Storage Exhaustion",
                category=AttackCategory.DENIAL_OF_SERVICE,
                description="Fill storage to prevent legitimate operations",
                severity=Severity.MEDIUM,
                preconditions=[
                    "Program allows creating accounts",
                    "No limit on number of accounts per user",
                ],
                attack_strategy="""
1. Create maximum number of accounts allowed
2. Fill all storage capacity
3. Legitimate users cannot create new accounts
                """,
                success_indicators=[
                    "Subsequent legitimate operations fail",
                    "Protocol becomes unusable",
                ],
            ),
            
            AttackVector(
                name="Compute Exhaustion",
                category=AttackCategory.DENIAL_OF_SERVICE,
                description="Craft inputs that consume maximum compute units",
                severity=Severity.LOW,
                preconditions=[
                    "Instruction has variable compute cost",
                    "Input affects loop iterations or recursion",
                ],
                attack_strategy="""
1. Find instruction with variable compute
2. Craft input that maximizes computation
3. Transaction fails or blocks other transactions
                """,
                success_indicators=[
                    "Transaction hits compute limit",
                    "Blocks/delays other transactions",
                ],
            ),
            
            # STATE CORRUPTION ATTACKS
            AttackVector(
                name="Integer Overflow",
                category=AttackCategory.STATE_CORRUPTION,
                description="Cause arithmetic overflow in balance or counter",
                severity=Severity.HIGH,
                preconditions=[
                    "Program performs unchecked arithmetic",
                    "Values can approach type boundaries",
                ],
                attack_strategy="""
1. Identify arithmetic operations
2. Craft inputs near u64::MAX or 0
3. Trigger overflow/underflow
4. Observe corrupted state
                """,
                success_indicators=[
                    "Balance becomes unexpectedly large or small",
                    "Counter wraps around",
                ],
            ),
            
            AttackVector(
                name="State Machine Violation",
                category=AttackCategory.STATE_CORRUPTION,
                description="Execute instructions in invalid order",
                severity=Severity.MEDIUM,
                preconditions=[
                    "Program has state-dependent logic",
                    "State transitions not fully enforced",
                ],
                attack_strategy="""
1. Map out expected state machine
2. Attempt instructions in wrong order
3. Skip required initialization
4. Double-execute non-idempotent actions
                """,
                success_indicators=[
                    "Instruction succeeds in invalid state",
                    "State becomes inconsistent",
                ],
            ),
            
            # ORACLE MANIPULATION (for DeFi)
            AttackVector(
                name="Price Oracle Manipulation",
                category=AttackCategory.ORACLE_MANIPULATION,
                description="Provide false price data to manipulate protocol behavior",
                severity=Severity.CRITICAL,
                preconditions=[
                    "Protocol relies on external price feed",
                    "Oracle can be manipulated or spoofed",
                ],
                attack_strategy="""
1. Identify oracle account
2. Push false price (if writable)
3. Or sandwich legitimate price update
4. Extract value during price discrepancy
                """,
                success_indicators=[
                    "Protocol acts on false price",
                    "Liquidation or swap at manipulated rate",
                ],
            ),
            
            # REENTRANCY
            AttackVector(
                name="Cross-Program Reentrancy",
                category=AttackCategory.REENTRANCY,
                description="Re-enter protocol during CPI before state update",
                severity=Severity.CRITICAL,
                preconditions=[
                    "Protocol makes CPI calls",
                    "State updated after CPI",
                ],
                attack_strategy="""
1. Create malicious program that calls back
2. Trigger CPI from target protocol
3. Re-enter target before state update
4. Double-spend or double-withdraw
                """,
                success_indicators=[
                    "Callback executed before state finalized",
                    "Funds extracted multiple times",
                ],
            ),
        ]
    
    def get_by_category(self, category: AttackCategory) -> List[AttackVector]:
        """Get all attacks in a category."""
        return [v for v in self.vectors if v.category == category]
    
    def get_by_severity(self, severity: Severity) -> List[AttackVector]:
        """Get all attacks of a severity level."""
        return [v for v in self.vectors if v.severity == severity]
    
    def get_applicable(self, analysis) -> List[AttackVector]:
        """
        Get attacks applicable to a specific program.
        
        Args:
            analysis: ProgramAnalysis object
            
        Returns:
            List of applicable attack vectors
        """
        applicable = []
        
        for vector in self.vectors:
            # Check if preconditions might be met
            if self._check_applicability(vector, analysis):
                applicable.append(vector)
        
        return applicable
    
    def _check_applicability(self, vector: AttackVector, analysis) -> bool:
        """Check if an attack might be applicable to a program."""
        # Basic heuristics based on instruction names and properties
        
        instructions = analysis.instructions if hasattr(analysis, 'instructions') else []
        
        # Check for withdraw instructions (fund extraction)
        if vector.category == AttackCategory.FUND_EXTRACTION:
            for ix in instructions:
                if ix.modifies_funds:
                    return True
        
        # Check for admin instructions (privilege escalation)
        if vector.category == AttackCategory.PRIVILEGE_ESCALATION:
            for ix in instructions:
                if ix.is_privileged:
                    return True
        
        # Check for account creation (DoS via storage)
        if vector.category == AttackCategory.DENIAL_OF_SERVICE:
            for ix in instructions:
                if ix.can_create_accounts or ix.can_close_accounts:
                    return True
        
        # Assume state corruption and arithmetic issues are always worth testing
        if vector.category in [AttackCategory.STATE_CORRUPTION, AttackCategory.REENTRANCY]:
            return True
        
        return False
