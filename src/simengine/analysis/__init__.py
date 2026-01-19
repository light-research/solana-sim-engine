"""
Analysis module for parsing and understanding Solana programs.
"""

from .models import (
    ProgramAnalysis,
    InstructionSpec,
    AccountSpec,
    ArgumentSpec,
    Constraint,
    Invariant,
)
from .idl_parser import IDLParser
from .program_loader import ProgramLoader, ProgramInfo
from .state_graph import StateGraph, StateGraphBuilder, StateNode, StateTransition
from .invariants import InvariantExtractor, ExtractedInvariant

__all__ = [
    "ProgramAnalysis",
    "InstructionSpec",
    "AccountSpec",
    "ArgumentSpec",
    "Constraint",
    "Invariant",
    "IDLParser",
    "ProgramLoader",
    "ProgramInfo",
    "StateGraph",
    "StateGraphBuilder",
    "StateNode",
    "StateTransition",
    "InvariantExtractor",
    "ExtractedInvariant",
]

