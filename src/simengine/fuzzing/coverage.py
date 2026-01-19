"""
Coverage Tracking: Tracks which parts of the program have been tested.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from datetime import datetime

from ..analysis.models import ProgramAnalysis
from ..analysis.state_graph import StateGraph, StateTransition
from .models import ScenarioResult


@dataclass
class InstructionCoverage:
    """Coverage data for a single instruction."""
    name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    
    # Argument coverage
    argument_values_tested: Dict[str, List[Any]] = field(default_factory=dict)
    
    # Account coverage
    accounts_tested: Set[str] = field(default_factory=set)
    
    @property
    def coverage_percentage(self) -> float:
        """Calculate a rough coverage score."""
        if self.total_calls == 0:
            return 0.0
        
        # Base score from being called
        score = 50.0
        
        # Bonus for testing both success and failure
        if self.successful_calls > 0 and self.failed_calls > 0:
            score += 25.0
        
        # Bonus for testing multiple argument values
        if len(self.argument_values_tested) > 0:
            avg_values = sum(len(v) for v in self.argument_values_tested.values()) / len(self.argument_values_tested)
            score += min(25.0, avg_values * 5)
        
        return min(100.0, score)


@dataclass
class TransitionCoverage:
    """Coverage data for a state transition."""
    transition: StateTransition
    times_traversed: int = 0


@dataclass
class CoverageReport:
    """Complete coverage report for a fuzzing run."""
    program_name: str
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Instruction coverage
    instruction_coverage: Dict[str, InstructionCoverage] = field(default_factory=dict)
    
    # State transition coverage
    transition_coverage: List[TransitionCoverage] = field(default_factory=list)
    
    # Summary stats
    total_instructions: int = 0
    covered_instructions: int = 0
    total_transitions: int = 0
    covered_transitions: int = 0
    
    # Scenario stats
    total_scenarios: int = 0
    total_steps_executed: int = 0
    
    @property
    def instruction_coverage_percentage(self) -> float:
        if self.total_instructions == 0:
            return 0.0
        return (self.covered_instructions / self.total_instructions) * 100
    
    @property
    def transition_coverage_percentage(self) -> float:
        if self.total_transitions == 0:
            return 0.0
        return (self.covered_transitions / self.total_transitions) * 100
    
    def to_dict(self) -> Dict:
        return {
            "program": self.program_name,
            "generated_at": self.generated_at,
            "summary": {
                "instruction_coverage": f"{self.instruction_coverage_percentage:.1f}%",
                "covered_instructions": f"{self.covered_instructions}/{self.total_instructions}",
                "transition_coverage": f"{self.transition_coverage_percentage:.1f}%",
                "covered_transitions": f"{self.covered_transitions}/{self.total_transitions}",
                "total_scenarios": self.total_scenarios,
                "total_steps": self.total_steps_executed,
            },
            "instructions": {
                name: {
                    "calls": cov.total_calls,
                    "success": cov.successful_calls,
                    "failure": cov.failed_calls,
                    "coverage": f"{cov.coverage_percentage:.1f}%",
                }
                for name, cov in self.instruction_coverage.items()
            },
            "uncovered_instructions": [
                name for name, cov in self.instruction_coverage.items()
                if cov.total_calls == 0
            ],
        }
    
    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "=" * 60,
            "COVERAGE REPORT",
            "=" * 60,
            f"Program: {self.program_name}",
            "",
            "Instruction Coverage:",
            f"  {self.covered_instructions}/{self.total_instructions} instructions tested ({self.instruction_coverage_percentage:.1f}%)",
            "",
        ]
        
        # Show per-instruction coverage
        for name, cov in sorted(self.instruction_coverage.items(), key=lambda x: x[1].total_calls, reverse=True):
            status = "✓" if cov.total_calls > 0 else "✗"
            lines.append(f"  {status} {name}: {cov.total_calls} calls ({cov.coverage_percentage:.0f}%)")
        
        # Show uncovered
        uncovered = [name for name, cov in self.instruction_coverage.items() if cov.total_calls == 0]
        if uncovered:
            lines.append("")
            lines.append(f"⚠️ Uncovered instructions: {', '.join(uncovered)}")
        
        lines.append("")
        lines.append(f"State Transitions: {self.covered_transitions}/{self.total_transitions} tested")
        lines.append("=" * 60)
        
        return "\n".join(lines)


class CoverageTracker:
    """
    Tracks test coverage during fuzzing.
    
    Monitors:
    - Which instructions have been called
    - What argument values have been tested
    - Which state transitions have been exercised
    """
    
    def __init__(self, analysis: ProgramAnalysis, state_graph: Optional[StateGraph] = None):
        """
        Initialize coverage tracker.
        
        Args:
            analysis: Program analysis
            state_graph: Optional state graph for transition tracking
        """
        self.analysis = analysis
        self.state_graph = state_graph
        
        # Initialize instruction coverage
        self.instruction_coverage: Dict[str, InstructionCoverage] = {}
        for ix in analysis.instructions:
            self.instruction_coverage[ix.name] = InstructionCoverage(name=ix.name)
        
        # Initialize transition coverage
        self.transition_coverage: List[TransitionCoverage] = []
        if state_graph:
            for t in state_graph.transitions:
                self.transition_coverage.append(TransitionCoverage(transition=t))
        
        # Counters
        self.total_scenarios = 0
        self.total_steps = 0
    
    def record_scenario(self, result: ScenarioResult):
        """Record coverage from a scenario execution."""
        self.total_scenarios += 1
        
        for step_result in result.step_results:
            self.total_steps += 1
            instruction = step_result.step.instruction
            
            if instruction in self.instruction_coverage:
                cov = self.instruction_coverage[instruction]
                cov.total_calls += 1
                
                if step_result.success:
                    cov.successful_calls += 1
                else:
                    cov.failed_calls += 1
                
                # Record argument values
                for arg_name, arg_value in step_result.step.arguments.items():
                    if arg_name not in cov.argument_values_tested:
                        cov.argument_values_tested[arg_name] = []
                    if arg_value not in cov.argument_values_tested[arg_name]:
                        cov.argument_values_tested[arg_name].append(arg_value)
    
    def generate_report(self) -> CoverageReport:
        """Generate a coverage report."""
        covered = sum(1 for cov in self.instruction_coverage.values() if cov.total_calls > 0)
        covered_transitions = sum(1 for tc in self.transition_coverage if tc.times_traversed > 0)
        
        return CoverageReport(
            program_name=self.analysis.name,
            instruction_coverage=self.instruction_coverage,
            transition_coverage=self.transition_coverage,
            total_instructions=len(self.instruction_coverage),
            covered_instructions=covered,
            total_transitions=len(self.transition_coverage),
            covered_transitions=covered_transitions,
            total_scenarios=self.total_scenarios,
            total_steps_executed=self.total_steps,
        )
    
    def get_uncovered_instructions(self) -> List[str]:
        """Get list of instructions that haven't been tested."""
        return [
            name for name, cov in self.instruction_coverage.items()
            if cov.total_calls == 0
        ]
    
    def suggest_next_tests(self) -> List[str]:
        """Suggest what to test next based on coverage gaps."""
        suggestions = []
        
        # Suggest uncovered instructions
        uncovered = self.get_uncovered_instructions()
        for name in uncovered[:3]:
            suggestions.append(f"Test instruction '{name}' (never executed)")
        
        # Suggest undertested instructions
        for name, cov in self.instruction_coverage.items():
            if cov.total_calls > 0:
                if cov.successful_calls == 0:
                    suggestions.append(f"Test '{name}' with valid inputs (all calls failed)")
                elif cov.failed_calls == 0:
                    suggestions.append(f"Test '{name}' with invalid inputs (all calls succeeded)")
        
        return suggestions[:5]
