# Solana Simulation Engine

**Agentic Fuzzing & Adversarial Testing for Solana Programs**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Solana Gauntlet is an LLM-powered security testing framework that combines **agentic fuzzing** with **adversarial testing** to find vulnerabilities in Solana programs. It generates intelligent test scenarios, builds real transactions, executes them on [Surfpool](https://github.com/txtx/surfpool), and reports findings with CWE classifications.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [analyze](#analyze---static-analysis)
  - [fuzz](#fuzz---agentic-fuzzing)
  - [attack](#attack---adversarial-testing)
  - [deploy](#deploy---custom-program-testing)
  - [replay](#replay---poc-execution)
- [Architecture](#architecture)
- [Output Formats](#output-formats)
- [Attack Vectors](#attack-vectors)
- [CWE Classifications](#cwe-classifications)
- [Configuration](#configuration)
- [Examples](#examples)

---

## Features

### 🤖 Agentic Fuzzing
LLM-powered scenario generation that understands your program's semantics:
- Parses Anchor IDL to understand instructions, accounts, and arguments
- Generates intelligent test scenarios (happy path, boundary, negative, adversarial)
- Builds state graphs to explore all reachable program states
- Tracks coverage to identify untested code paths

### ⚔️ Adversarial Testing
Focused attack simulation using a curated playbook of Solana exploits:
- 10+ attack vectors including fund extraction, privilege escalation, reentrancy
- LLM-powered reasoning about attack viability
- Automatic PoC generation for successful exploits
- CWE-classified vulnerability reports

### 🔧 Real Transaction Building
Actual Solana transaction construction, not simulation:
- Anchor discriminator computation
- Proper argument encoding (u64, u32, u8, bool, publickey)
- Account resolution (PDAs, ATAs, system programs)
- Transaction serialization using `solders`

### 📊 Comprehensive Reporting
Detailed output with actionable insights:
- Coverage reports (instruction + transition coverage)
- Severity-classified vulnerabilities (Critical/High/Medium/Low)
- CWE IDs for industry-standard classification
- JSON export for CI/CD integration

---

## Installation

### Prerequisites

- Python 3.10+
- [Surfpool](https://github.com/txtx/surfpool) (local Solana validator)
- OpenAI API key (for LLM-powered features)

### Install Surfpool

```bash
# macOS
brew install txtx/taps/surfpool

# Verify installation
surfpool --version
```

### Install Solana Gauntlet

```bash
# Clone the repository
git clone https://github.com/your-org/solana-gauntlet.git
cd solana-gauntlet/solana-sim-engine

# Install with pip
pip install -e .

# Verify installation
simengine --help
```

### Set Environment Variables

```bash
# Required for LLM features
export OPENAI_API_KEY="sk-..."

# Optional: specify model
export OPENAI_MODEL="gpt-4o"
```

---

## Quick Start

### 1. Analyze a Program

```bash
simengine analyze examples/simple_vault.json --mermaid
```

Output:
```
Program Information
  Name: simple_vault
  Instructions: 5

Instructions
┌────────────┬──────────┬──────┬────────────────────┐
│ Name       │ Accounts │ Args │ Flags              │
├────────────┼──────────┼──────┼────────────────────┤
│ initialize │ 4        │ 1    │ 🔒 Privileged      │
│ deposit    │ 5        │ 1    │ 💰 Funds           │
│ withdraw   │ 5        │ 1    │ 💰 Funds           │
│ setFee     │ 2        │ 1    │ 🔒 Privileged      │
│ close      │ 3        │ 0    │ 🔒 Privileged      │
└────────────┴──────────┴──────┴────────────────────┘
```

### 2. Run Fuzzing

```bash
simengine fuzz examples/simple_vault.json -n 10 -o fuzz_report.json
```

Output:
```
✓ Generated 10 scenarios
  • Normal vault lifecycle
  • Boundary deposit (max u64)
  • Unauthorized withdrawal
  ...

FUZZING REPORT
==============
Scenarios: 10
  ✓ Passed: 7
  ✗ Failed: 3

COVERAGE:
  Instructions: 100.0%
  Transitions: 60.0%
  ⚠️ Uncovered: close
```

### 3. Run Adversarial Testing

```bash
simengine attack examples/simple_vault.json --focus fund-extraction -o attack_report.json
```

Output:
```
🚨 VULNERABILITIES FOUND 🚨

CRITICAL: Unauthorized Fund Extraction
  Scenario: Account Substitution Attack
  CWE: CWE-862
  Fix: Implement proper fund custody controls
```

---

## Commands

### `analyze` - Static Analysis

Analyze a program's structure without execution.

```bash
simengine analyze <idl> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `idl` | Path to Anchor IDL JSON file |

**Options:**
| Option | Description |
|--------|-------------|
| `--output`, `-o` | Export analysis to JSON file |
| `--mermaid` | Output state graph as Mermaid diagram |

**Example:**
```bash
simengine analyze my_program.json --mermaid -o analysis.json
```

**Output includes:**
- Instruction list with accounts, arguments, and semantic flags
- State graph showing valid program state transitions
- Detected invariants (balance conservation, access control, lifecycle)

---

### `fuzz` - Agentic Fuzzing

Generate and execute intelligent test scenarios using LLM.

```bash
simengine fuzz <idl> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `idl` | Path to Anchor IDL JSON file |

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-n`, `--num-scenarios` | Number of scenarios to generate | 10 |
| `-p`, `--prompt` | Custom focus prompt for LLM | None |
| `-o`, `--output` | Export report to JSON file | None |
| `--mock` | Run without Surfpool (for testing) | False |

**Example:**
```bash
# Generate 20 scenarios focused on edge cases
simengine fuzz my_program.json -n 20 -p "Focus on integer overflow scenarios"

# Quick test with mock mode
simengine fuzz my_program.json -n 5 --mock
```

**How it works:**
1. Parses IDL to understand program structure
2. LLM generates diverse test scenarios
3. TransactionBuilder creates real Solana transactions
4. Surfpool executes transactions
5. CoverageTracker records which paths were tested
6. Results analyzed for anomalies

---

### `attack` - Adversarial Testing

Focused exploitation attempts using curated attack playbook.

```bash
simengine attack <idl> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `idl` | Path to Anchor IDL JSON file |

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-n`, `--num-scenarios` | Number of attack scenarios | 5 |
| `--focus` | Attack category to focus on | all |
| `-o`, `--output` | Export report to JSON file | None |

**Focus categories:**
- `fund-extraction` - Unauthorized fund movement
- `privilege` - Access control bypass
- `dos` - Denial of service
- `state` - State corruption
- `reentrancy` - Cross-program reentrancy

**Example:**
```bash
# Focus on fund extraction attacks
simengine attack my_program.json --focus fund-extraction -n 10

# Full adversarial scan
simengine attack my_program.json -o security_report.json
```

**Exit codes:**
| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | High severity findings |
| 2 | Critical severity findings |

---

### `deploy` - Custom Program Testing

Deploy your compiled program to Surfpool and run tests.

```bash
simengine deploy <program.so> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `program` | Path to compiled .so file |

**Options:**
| Option | Description |
|--------|-------------|
| `--idl`, `-i` | Path to Anchor IDL (required for testing) |
| `--fuzz` | Run fuzzing after deployment |
| `--attack` | Run adversarial testing after deployment |
| `-o`, `--output` | Export report to JSON file |

**Example:**
```bash
# Deploy and run full security audit
simengine deploy target/deploy/my_program.so \
  --idl target/idl/my_program.json \
  --fuzz --attack \
  -o full_report.json
```

**Validation performed:**
- ELF format verification
- BPF architecture check
- File size limits (max 10MB)
- Associated keypair discovery

---

### `replay` - PoC Execution

Replay a proof-of-concept exploit.

```bash
simengine replay <poc.json> [options]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `poc` | Path to PoC JSON file |

**Options:**
| Option | Description |
|--------|-------------|
| `-y`, `--yes` | Skip confirmation prompt |

**PoC JSON format:**
```json
{
  "name": "Account Substitution Attack",
  "vulnerability": "Unauthorized Fund Extraction",
  "severity": "critical",
  "transactions": [
    {
      "instruction_name": "withdraw",
      "accounts": [
        {"name": "vault", "value": "..."},
        {"name": "userTokenAccount", "value": "attacker_ata"}
      ],
      "signers": ["attacker"]
    }
  ]
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI LAYER                                │
│  simengine fuzz | attack | analyze | deploy | replay            │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYSIS MODULE                             │
│  ┌─────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  IDLParser  │  │ StateGraph    │  │ InvariantExtractor   │  │
│  │             │→ │ Builder       │→ │                      │  │
│  └─────────────┘  └───────────────┘  └──────────────────────┘  │
│                           │                                      │
│  ┌─────────────┐          ▼                                     │
│  │ ProgramInfo │   ProgramAnalysis                               │
│  │ (.so loader)│                                                 │
│  └─────────────┘                                                 │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                   ┌──────────────┴──────────────┐
                   ▼                              ▼
┌───────────────────────────┐  ┌────────────────────────────────┐
│     FUZZING MODULE        │  │    ADVERSARIAL MODULE          │
│                           │  │                                │
│  ScenarioGenerator (LLM)  │  │  AttackPlaybook (10+ vectors)  │
│           │               │  │           │                    │
│           ▼               │  │           ▼                    │
│  List[Scenario]           │  │  AdversarialAgent (LLM)        │
│           │               │  │           │                    │
│           ▼               │  │           ▼                    │
│  CoverageTracker          │  │  VulnerabilityDetector (CWE)   │
│                           │  │           │                    │
│                           │  │           ▼                    │
│                           │  │  PoCGenerator                  │
└───────────────┬───────────┘  └────────────────┬───────────────┘
                │                                │
                └──────────────┬─────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CORE MODULE                                  │
│  ┌──────────────────────┐  ┌────────────────────────────────┐  │
│  │  TransactionBuilder  │  │  SurfpoolManager               │  │
│  │                      │  │                                │  │
│  │  • Discriminator     │  │  • Start/stop Surfpool         │  │
│  │  • Arg encoding      │  │  • Program deployment          │  │
│  │  • Account resolve   │  │  • RPC client                  │  │
│  │  • Wallet management │  │  • Transaction simulation      │  │
│  └──────────────────────┘  └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SURFPOOL                                  │
│  Local Solana validator with mainnet fork capabilities          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Output Formats

### CLI Output

```
============================================================
FUZZING REPORT
============================================================
Mode: explore
Scenarios: 10
  ✓ Passed: 7
  ✗ Failed: 3
Time: 45.2s

COVERAGE:
  Instructions: 100.0%
  Transitions: 60.0%
  ⚠️ Uncovered: close, setFee

🚨 VULNERABILITIES FOUND: 1
  • Security Issue: Unexpected success in unauthorized withdrawal

⚠️ ANOMALIES DETECTED: 2
  • Anomaly: Missing error for overflow input
============================================================
```

### JSON Export

```json
{
  "mode": "explore",
  "total_scenarios": 10,
  "passed": 7,
  "failed": 3,
  "coverage": {
    "instruction_coverage": "100.0%",
    "covered_instructions": 5,
    "total_instructions": 5,
    "transition_coverage": "60.0%",
    "covered_transitions": 6,
    "total_transitions": 10,
    "uncovered_instructions": ["close"],
    "total_scenarios": 10,
    "total_steps": 32
  },
  "vulnerabilities": [
    {
      "name": "Access Control Bypass",
      "severity": "critical",
      "scenario": "Unauthorized Admin Action",
      "cwe": "CWE-284",
      "recommendation": "Verify signer authority"
    }
  ],
  "results": [
    {
      "name": "Normal Deposit Flow",
      "type": "happy_path",
      "passed": true,
      "steps": [
        {"instruction": "initialize", ...},
        {"instruction": "deposit", ...}
      ]
    }
  ]
}
```

---

## Attack Vectors

| Category | Vectors | Description |
|----------|---------|-------------|
| **Fund Extraction** | Unauthorized Withdrawal, Account Substitution, Rent Drain | Attempts to steal funds |
| **Privilege Escalation** | Authority Bypass, PDA Override | Gain admin access |
| **Denial of Service** | Storage Exhaustion, Compute Exhaustion | Make program unusable |
| **State Corruption** | Integer Overflow, State Machine Violation | Corrupt program state |
| **Reentrancy** | Cross-Program Reentrancy | Exploit callback patterns |

---

## CWE Classifications

All vulnerabilities are classified using the Common Weakness Enumeration (CWE) standard:

| CWE ID | Name | Triggers |
|--------|------|----------|
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper Access Control | Authority bypass in privileged functions |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | Missing validation in boundary tests |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | Successful fund extraction attacks |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow | Arithmetic errors in logs |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Behavioral Workflow Violation | Reentrancy patterns detected |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key (required) | - |
| `OPENAI_MODEL` | Model to use | `gpt-4o` |
| `DEFAULT_NETWORK` | Network for Surfpool | `mainnet` |

### Project Structure

```
solana-sim-engine/
├── src/simengine/
│   ├── analysis/           # IDL parsing, state graphs, invariants
│   │   ├── idl_parser.py
│   │   ├── models.py
│   │   ├── state_graph.py
│   │   ├── invariants.py
│   │   └── program_loader.py
│   ├── fuzzing/            # Scenario generation, execution, coverage
│   │   ├── generator.py
│   │   ├── runner.py
│   │   ├── models.py
│   │   └── coverage.py
│   ├── adversarial/        # Attack playbook, agent, detection
│   │   ├── playbook.py
│   │   ├── agent.py
│   │   ├── detector.py
│   │   └── poc.py
│   ├── core/               # Transaction building, Surfpool management
│   │   ├── tx_builder.py
│   │   └── surfpool.py
│   └── cli.py              # Command-line interface
├── examples/
│   └── simple_vault.json   # Example IDL for testing
├── pyproject.toml
└── README.md
```

---

## Examples

### Example 1: Full Security Audit

```bash
# Step 1: Analyze program structure
simengine analyze target/idl/my_defi.json --mermaid > state_graph.md

# Step 2: Run fuzzing for coverage
simengine fuzz target/idl/my_defi.json -n 20 -o fuzz_report.json

# Step 3: Run targeted attacks
simengine attack target/idl/my_defi.json --focus fund-extraction -o attack_report.json

# Step 4: Check exit code for CI/CD
if [ $? -eq 2 ]; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

### Example 2: Custom Focus

```bash
# Focus on integer overflow scenarios
simengine fuzz my_program.json \
  -n 15 \
  -p "Generate scenarios that test integer overflow in deposit and withdrawal amounts" \
  -o overflow_test.json
```

### Example 3: Deploy and Test

```bash
# Build your program
anchor build

# Deploy and run full test suite
simengine deploy target/deploy/my_program.so \
  --idl target/idl/my_program.json \
  --fuzz --attack \
  -o full_audit.json
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built with ❤️ for the Solana ecosystem**
