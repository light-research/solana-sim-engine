"""
Vulnerability Detector: Heuristics for identifying security issues.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

from ..fuzzing.models import ScenarioResult, StepResult, ExpectedOutcome


class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """A detected vulnerability."""
    name: str
    severity: VulnerabilitySeverity
    description: str
    scenario_name: str
    
    # Evidence
    affected_instruction: Optional[str] = None
    affected_accounts: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    
    # Exploitation info
    exploit_steps: List[str] = field(default_factory=list)
    poc_transaction: Optional[str] = None  # Base64 encoded
    
    # Remediation
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None  # Common Weakness Enumeration
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "scenario": self.scenario_name,
            "instruction": self.affected_instruction,
            "accounts": self.affected_accounts,
            "exploit_steps": self.exploit_steps,
            "poc": self.poc_transaction,
            "recommendation": self.recommendation,
            "cwe": self.cwe_id,
        }


class VulnerabilityDetector:
    """
    Detects vulnerabilities from scenario execution results.
    
    Uses heuristics to identify common Solana security issues.
    """
    
    # Patterns that indicate vulnerabilities
    CRITICAL_PATTERNS = [
        ("unauthorized", "access control bypass"),
        ("permission denied", None),  # Should fail but didn't
        ("invalid authority", None),
        ("transfer", "unexpected fund movement"),
    ]
    
    def __init__(self):
        self.findings: List[Vulnerability] = []
    
    def analyze(self, results: List[ScenarioResult]) -> List[Vulnerability]:
        """
        Analyze scenario results for vulnerabilities.
        
        Args:
            results: List of executed scenario results
            
        Returns:
            List of detected vulnerabilities
        """
        self.findings = []
        
        for result in results:
            # Check for access control bypass
            self._check_access_control(result)
            
            # Check for unexpected success in negative tests
            self._check_unexpected_success(result)
            
            # Check for fund-related anomalies
            self._check_fund_anomalies(result)
            
            # Check for state corruption indicators
            self._check_state_corruption(result)
            
            # Check logs for error patterns
            self._check_log_patterns(result)
        
        return self.findings
    
    def _check_access_control(self, result: ScenarioResult):
        """Check for access control bypass vulnerabilities."""
        scenario = result.scenario
        
        # If scenario tests unauthorized access and it succeeded
        keywords = ["unauthorized", "admin", "authority", "privilege", "permission"]
        is_access_test = any(kw in scenario.name.lower() for kw in keywords)
        
        if is_access_test and result.passed:
            # Check if it was supposed to fail
            if scenario.expected_outcome == ExpectedOutcome.FAILURE:
                self.findings.append(Vulnerability(
                    name="Access Control Bypass",
                    severity=VulnerabilitySeverity.CRITICAL,
                    description=(
                        f"Scenario '{scenario.name}' was expected to fail due to access control, "
                        f"but it succeeded. An attacker may be able to execute privileged operations."
                    ),
                    scenario_name=scenario.name,
                    affected_instruction=self._get_last_instruction(result),
                    recommendation="Verify that all privileged instructions check signer authority.",
                    cwe_id="CWE-284",  # Improper Access Control
                ))
    
    def _check_unexpected_success(self, result: ScenarioResult):
        """Check for scenarios that succeeded when they should have failed."""
        scenario = result.scenario
        
        if scenario.expected_outcome == ExpectedOutcome.FAILURE:
            # Check if all steps succeeded
            all_succeeded = all(sr.success for sr in result.step_results)
            
            if all_succeeded:
                self.findings.append(Vulnerability(
                    name="Missing Validation",
                    severity=VulnerabilitySeverity.MEDIUM,
                    description=(
                        f"Scenario '{scenario.name}' was expected to fail but all steps succeeded. "
                        f"This may indicate missing input validation or constraint checking."
                    ),
                    scenario_name=scenario.name,
                    affected_instruction=self._get_last_instruction(result),
                    recommendation="Add proper input validation and constraint checks.",
                    cwe_id="CWE-20",  # Improper Input Validation
                ))
    
    def _check_fund_anomalies(self, result: ScenarioResult):
        """Check for unexpected fund movements."""
        scenario = result.scenario
        
        # Look for fund-related keywords in adversarial scenarios
        fund_keywords = ["withdraw", "drain", "extract", "steal", "transfer"]
        is_fund_attack = any(kw in scenario.name.lower() for kw in fund_keywords)
        
        if is_fund_attack and scenario.expected_outcome == ExpectedOutcome.SUCCESS:
            # Attacker expected to succeed - this is a vulnerability if they did
            if result.passed:
                self.findings.append(Vulnerability(
                    name="Unauthorized Fund Extraction",
                    severity=VulnerabilitySeverity.CRITICAL,
                    description=(
                        f"Attack scenario '{scenario.name}' succeeded in extracting funds. "
                        f"An attacker can drain protocol assets."
                    ),
                    scenario_name=scenario.name,
                    affected_instruction=self._get_last_instruction(result),
                    exploit_steps=[s.instruction for s in scenario.steps],
                    recommendation="Implement proper fund custody controls and withdrawal validation.",
                    cwe_id="CWE-862",  # Missing Authorization
                ))
    
    def _check_state_corruption(self, result: ScenarioResult):
        """Check for state corruption indicators."""
        scenario = result.scenario
        
        # Look for state-related keywords
        state_keywords = ["corrupt", "overflow", "underflow", "invalid state", "double"]
        is_state_test = any(kw in scenario.name.lower() for kw in state_keywords)
        
        if is_state_test and result.passed:
            self.findings.append(Vulnerability(
                name="State Corruption",
                severity=VulnerabilitySeverity.HIGH,
                description=(
                    f"Scenario '{scenario.name}' may have corrupted protocol state. "
                    f"This could lead to unexpected behavior or exploitable conditions."
                ),
                scenario_name=scenario.name,
                recommendation="Add state invariant checks and use checked arithmetic.",
                cwe_id="CWE-190",  # Integer Overflow
            ))
    
    def _check_log_patterns(self, result: ScenarioResult):
        """Check execution logs for vulnerability patterns."""
        for step_result in result.step_results:
            if not step_result.logs:
                continue
            
            log_text = " ".join(step_result.logs).lower()
            
            # Check for arithmetic errors
            if "overflow" in log_text or "underflow" in log_text:
                self.findings.append(Vulnerability(
                    name="Arithmetic Error",
                    severity=VulnerabilitySeverity.HIGH,
                    description="Arithmetic overflow/underflow detected in execution logs.",
                    scenario_name=result.scenario.name,
                    affected_instruction=step_result.step.instruction,
                    logs=step_result.logs[:5],
                    recommendation="Use checked arithmetic operations.",
                    cwe_id="CWE-190",
                ))
            
            # Check for reentrancy patterns
            if "reentrant" in log_text or "already borrowed" in log_text:
                self.findings.append(Vulnerability(
                    name="Reentrancy Vulnerability",
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="Possible reentrancy detected in execution.",
                    scenario_name=result.scenario.name,
                    affected_instruction=step_result.step.instruction,
                    logs=step_result.logs[:5],
                    recommendation="Use reentrancy guards and update state before external calls.",
                    cwe_id="CWE-841",
                ))
    
    def _get_last_instruction(self, result: ScenarioResult) -> Optional[str]:
        """Get the last executed instruction name."""
        if result.step_results:
            return result.step_results[-1].step.instruction
        return None
    
    def generate_report(self) -> Dict:
        """Generate a structured vulnerability report."""
        # Group by severity
        by_severity = {}
        for vuln in self.findings:
            sev = vuln.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(vuln.to_dict())
        
        # Count by severity
        counts = {
            "critical": len(by_severity.get("critical", [])),
            "high": len(by_severity.get("high", [])),
            "medium": len(by_severity.get("medium", [])),
            "low": len(by_severity.get("low", [])),
            "info": len(by_severity.get("info", [])),
        }
        
        return {
            "total_findings": len(self.findings),
            "counts": counts,
            "findings": by_severity,
            "summary": self._generate_summary(counts),
        }
    
    def _generate_summary(self, counts: Dict) -> str:
        """Generate a human-readable summary."""
        if counts["critical"] > 0:
            return f"🚨 CRITICAL: {counts['critical']} critical vulnerabilities require immediate attention"
        elif counts["high"] > 0:
            return f"⚠️ HIGH: {counts['high']} high-severity issues found"
        elif counts["medium"] > 0:
            return f"⚠️ MEDIUM: {counts['medium']} medium-severity issues to review"
        elif counts["low"] > 0:
            return f"ℹ️ LOW: {counts['low']} low-severity issues noted"
        else:
            return "✅ No significant vulnerabilities detected"
