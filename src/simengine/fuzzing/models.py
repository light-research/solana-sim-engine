"""
Data models for fuzzing scenarios.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class ExpectedOutcome(Enum):
    """Expected result of a scenario."""
    SUCCESS = "success"
    FAILURE = "failure"
    OBSERVE = "observe"  # No expectation, just observe


class ScenarioType(Enum):
    """Type of fuzzing scenario."""
    HAPPY_PATH = "happy_path"
    BOUNDARY = "boundary"
    NEGATIVE = "negative"
    PERMUTATION = "permutation"
    ADVERSARIAL = "adversarial"


@dataclass
class ScenarioStep:
    """A single step in a scenario."""
    instruction: str
    accounts: Dict[str, str] = field(default_factory=dict)  # account_name -> pubkey or "generate"
    arguments: Dict[str, Any] = field(default_factory=dict)
    signer: Optional[str] = None  # Which wallet signs this
    description: Optional[str] = None


@dataclass
class InitialState:
    """Initial state configuration for a scenario."""
    wallets: Dict[str, Dict[str, float]] = field(default_factory=dict)  # wallet_name -> {token: amount}
    accounts: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # account_name -> data
    deploy_programs: List[str] = field(default_factory=list)  # .so files to deploy


@dataclass
class Scenario:
    """A complete test scenario."""
    name: str
    description: str
    scenario_type: ScenarioType
    
    # State setup
    initial_state: InitialState = field(default_factory=InitialState)
    
    # Execution steps
    steps: List[ScenarioStep] = field(default_factory=list)
    
    # Expectations
    expected_outcome: ExpectedOutcome = ExpectedOutcome.OBSERVE
    expected_error: Optional[str] = None  # If expecting failure, what error?
    invariants_to_check: List[str] = field(default_factory=list)
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    priority: int = 1  # 1 = highest priority
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "type": self.scenario_type.value,
            "steps": [
                {
                    "instruction": s.instruction,
                    "accounts": s.accounts,
                    "arguments": s.arguments,
                    "signer": s.signer,
                }
                for s in self.steps
            ],
            "expected_outcome": self.expected_outcome.value,
            "expected_error": self.expected_error,
        }


@dataclass
class StepResult:
    """Result of executing a single step."""
    step: ScenarioStep
    success: bool
    error: Optional[str] = None
    logs: List[str] = field(default_factory=list)
    compute_units: int = 0
    state_changes: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None  # Transaction signature if submitted



@dataclass
class ScenarioResult:
    """Result of executing a complete scenario."""
    scenario: Scenario
    passed: bool
    
    # Execution details
    step_results: List[StepResult] = field(default_factory=list)
    execution_time_ms: float = 0
    
    # State
    final_state: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis
    vulnerabilities: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        """Human-readable summary."""
        status = "✓ PASSED" if self.passed else "✗ FAILED"
        lines = [
            f"{status}: {self.scenario.name}",
            f"  Steps: {len(self.step_results)} executed",
            f"  Time: {self.execution_time_ms:.0f}ms",
        ]
        if self.vulnerabilities:
            lines.append(f"  🚨 Vulnerabilities: {len(self.vulnerabilities)}")
        if self.anomalies:
            lines.append(f"  ⚠️ Anomalies: {len(self.anomalies)}")
        return "\n".join(lines)


@dataclass
class FuzzingConfig:
    """Configuration for a fuzzing run."""
    num_scenarios: int = 10
    focus_areas: List[str] = field(default_factory=list)  # e.g., ["boundaries", "permissions"]
    timeout_per_scenario_ms: int = 60000
    parallel_runs: int = 1
    
    # Mode selection
    mode: str = "explore"  # "explore" or "attack"
    
    # Seed for reproducibility
    seed: Optional[int] = None


@dataclass
class FuzzingReport:
    """Complete report from a fuzzing run."""
    config: FuzzingConfig
    results: List[ScenarioResult] = field(default_factory=list)
    
    # Aggregates
    total_scenarios: int = 0
    passed: int = 0
    failed: int = 0
    
    # Findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    anomalies: List[Dict] = field(default_factory=list)
    
    # Coverage
    coverage: Optional[Dict] = None  # Coverage report data
    
    # Timing
    total_time_ms: float = 0
    
    def summary(self) -> str:
        """Generate summary report."""
        lines = [
            "=" * 60,
            "FUZZING REPORT",
            "=" * 60,
            f"Mode: {self.config.mode}",
            f"Scenarios: {self.total_scenarios}",
            f"  ✓ Passed: {self.passed}",
            f"  ✗ Failed: {self.failed}",
            f"Time: {self.total_time_ms/1000:.1f}s",
            "",
        ]
        
        # Coverage section
        if self.coverage:
            lines.append("COVERAGE:")
            lines.append(f"  Instructions: {self.coverage.get('instruction_coverage', 'N/A')}")
            lines.append(f"  Transitions: {self.coverage.get('transition_coverage', 'N/A')}")
            uncovered = self.coverage.get('uncovered_instructions', [])
            if uncovered:
                lines.append(f"  ⚠️ Uncovered: {', '.join(uncovered)}")
            lines.append("")
        
        if self.vulnerabilities:
            lines.append(f"🚨 VULNERABILITIES FOUND: {len(self.vulnerabilities)}")
            for vuln in self.vulnerabilities:
                lines.append(f"  • {vuln.get('name', 'Unknown')}: {vuln.get('description', '')}")
        
        if self.anomalies:
            lines.append(f"\n⚠️ ANOMALIES DETECTED: {len(self.anomalies)}")
            for anom in self.anomalies:
                lines.append(f"  • {anom.get('name', 'Unknown')}: {anom.get('description', '')}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
    
    def to_dict(self) -> Dict:
        """Convert report to dictionary for JSON export."""
        return {
            "mode": self.config.mode,
            "total_scenarios": self.total_scenarios,
            "passed": self.passed,
            "failed": self.failed,
            "vulnerabilities": self.vulnerabilities,
            "anomalies": self.anomalies,
            "coverage": self.coverage,
            "total_time_ms": self.total_time_ms,
            "results": [
                {
                    "name": r.scenario.name,
                    "description": r.scenario.description,
                    "type": r.scenario.scenario_type.value,
                    "passed": r.passed,
                    "steps": [
                        {
                            "instruction": s.instruction,
                            "accounts": s.accounts,
                            "arguments": s.arguments,
                            "signer": s.signer,
                        }
                        for s in r.scenario.steps
                    ],
                    "execution_time_ms": r.execution_time_ms,
                }
                for r in self.results
            ],
        }

