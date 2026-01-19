"""
Data models for program analysis.

These models represent the structure and semantics of a Solana program
extracted from its IDL or source code.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class AccountType(Enum):
    """Type of account in an instruction."""
    SIGNER = "signer"
    WRITABLE = "writable"
    READONLY = "readonly"
    PROGRAM = "program"
    SYSTEM = "system"


class ArgumentType(Enum):
    """Primitive types for instruction arguments."""
    U8 = "u8"
    U16 = "u16"
    U32 = "u32"
    U64 = "u64"
    U128 = "u128"
    I8 = "i8"
    I16 = "i16"
    I32 = "i32"
    I64 = "i64"
    I128 = "i128"
    BOOL = "bool"
    STRING = "string"
    PUBKEY = "publicKey"
    BYTES = "bytes"
    STRUCT = "struct"
    VEC = "vec"
    OPTION = "option"


@dataclass
class ArgumentSpec:
    """Specification for an instruction argument."""
    name: str
    arg_type: str  # Raw type string from IDL
    description: Optional[str] = None
    
    # For fuzzing
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    example_values: List[Any] = field(default_factory=list)


@dataclass
class AccountSpec:
    """Specification for an account in an instruction."""
    name: str
    is_signer: bool = False
    is_writable: bool = False
    is_optional: bool = False
    description: Optional[str] = None
    
    # Constraints extracted from IDL
    pda_seeds: Optional[List[str]] = None  # PDA derivation seeds
    owner: Optional[str] = None  # Expected owner program
    

@dataclass
class Constraint:
    """A constraint on instruction execution."""
    description: str
    constraint_type: str  # "signer", "owner", "has_balance", "custom"
    expression: Optional[str] = None  # Raw constraint expression if available


@dataclass
class InstructionSpec:
    """Specification for a single instruction in the program."""
    name: str
    discriminator: Optional[bytes] = None  # 8-byte discriminator for Anchor
    accounts: List[AccountSpec] = field(default_factory=list)
    arguments: List[ArgumentSpec] = field(default_factory=list)
    description: Optional[str] = None
    constraints: List[Constraint] = field(default_factory=list)
    
    # Semantic information
    is_privileged: bool = False  # Requires admin/authority
    modifies_funds: bool = False  # Transfers tokens/SOL
    can_create_accounts: bool = False
    can_close_accounts: bool = False


@dataclass
class Invariant:
    """A protocol invariant that should always hold."""
    name: str
    description: str
    check_expression: Optional[str] = None  # How to verify
    severity: str = "high"  # critical, high, medium, low


@dataclass
class FundFlow:
    """Describes how funds move in the protocol."""
    instruction: str
    source: str  # Account that loses funds
    destination: str  # Account that gains funds
    token: str  # "SOL" or token mint


@dataclass
class ProgramAnalysis:
    """Complete analysis of a Solana program."""
    program_id: Optional[str] = None
    name: str = "Unknown"
    version: Optional[str] = None
    
    # Extracted structure
    instructions: List[InstructionSpec] = field(default_factory=list)
    accounts: List[AccountSpec] = field(default_factory=list)  # Global account types
    
    # Semantic analysis
    invariants: List[Invariant] = field(default_factory=list)
    fund_flows: List[FundFlow] = field(default_factory=list)
    
    # Metadata
    raw_idl: Optional[Dict] = None
    
    def get_instruction(self, name: str) -> Optional[InstructionSpec]:
        """Get instruction by name."""
        for ix in self.instructions:
            if ix.name.lower() == name.lower():
                return ix
        return None
    
    def get_privileged_instructions(self) -> List[InstructionSpec]:
        """Get all instructions that require elevated privileges."""
        return [ix for ix in self.instructions if ix.is_privileged]
    
    def get_fund_modifying_instructions(self) -> List[InstructionSpec]:
        """Get all instructions that move funds."""
        return [ix for ix in self.instructions if ix.modifies_funds]
    
    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Program: {self.name}",
            f"Instructions: {len(self.instructions)}",
        ]
        for ix in self.instructions:
            flags = []
            if ix.is_privileged:
                flags.append("🔒")
            if ix.modifies_funds:
                flags.append("💰")
            flag_str = " ".join(flags) if flags else ""
            lines.append(f"  • {ix.name} {flag_str}")
        return "\n".join(lines)
