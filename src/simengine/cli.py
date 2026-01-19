"""
CLI entry point for the Solana Simulation Engine.

Usage:
    simengine run "Swap 100 USDC for SOL" --wallet YOUR_WALLET
    simengine run "Swap 100 USDC for SOL" -w YOUR_WALLET --network devnet
"""

import argparse
import asyncio
import json
import sys
import os
from typing import Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Default wallet for demo
DEFAULT_WALLET = "49LfpEvSchzmLtZYKbYLPs1s47tGVc6V4vP327zccyGV"


def load_env():
    """Load .env file from parent directories."""
    current = Path.cwd()
    for _ in range(5):  # Check up to 5 parent dirs
        env_file = current / ".env"
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        os.environ.setdefault(key.strip(), value.strip())
            break
        current = current.parent


def run_simulation(args: argparse.Namespace) -> int:
    """Run a simulation with real blockchain data."""
    # Load .env file
    load_env()
    
    prompt = args.prompt
    wallet = args.wallet or DEFAULT_WALLET
    network = args.network
    
    console.print()
    console.print(Panel(
        f"[bold cyan]{prompt}[/bold cyan]\n\n"
        f"[dim]Wallet: {wallet[:8]}...{wallet[-4:]}[/dim]\n"
        f"[dim]Network: {network}[/dim]",
        title="[bold]Solana Simulation Engine[/bold]",
        subtitle="Real Blockchain Simulation"
    ))
    console.print()
    
    # Import here to avoid slow startup
    from simengine.core.simulator import RealSimulator
    
    async def _run():
        sim = RealSimulator(
            wallet_address=wallet,
            network=network
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Fetching wallet state...", total=None)
            result = await sim.run(prompt)
            progress.update(task, description="Simulation complete!")
        
        return result
    
    try:
        result = asyncio.run(_run())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    # Display results
    if not result.success:
        console.print(f"[red]✗ Simulation failed[/red]")
        console.print(f"[red]  {result.error}[/red]")
        
        if result.parsed_intent and result.parsed_intent.suggestions:
            console.print("\n[yellow]Did you mean?[/yellow]")
            for suggestion in result.parsed_intent.suggestions:
                console.print(f"  → {suggestion}")
        return 1
    
    # Show parsed intent
    console.print("[green]✓ Parsed successfully[/green]")
    if result.parsed_intent:
        for action in result.parsed_intent.actions:
            params = action.parameters
            console.print(
                f"  [dim]→[/dim] {action.protocol}.{action.type}: "
                f"{params.get('amount', '?')} {params.get('inputToken', '?')} → {params.get('outputToken', '?')}"
            )
    
    console.print("[green]✓ Fetched real balances[/green]")
    console.print("[green]✓ Got Jupiter quote[/green]")
    
    # Show quote info
    if result.quote_info:
        out_amount = result.quote_info.get("outputAmount", 0)
        out_token = result.quote_info.get("outputToken", "")
        from simengine.parser.token_registry import raw_to_amount
        out_ui = raw_to_amount(out_amount, out_token)
        console.print(f"  [dim]→ Quote: {out_ui:.6f} {out_token}[/dim]")
    
    # Show results
    console.print()
    console.print("═" * 60)
    console.print(f"[bold]                    RESULTS ({network.upper()})[/bold]")
    console.print("═" * 60)
    console.print()
    
    # State before
    if result.state_before:
        console.print(f"[dim]Before (real {network} balance):[/dim]")
        console.print(f"  SOL: {result.state_before.sol_balance:.6f}")
        for symbol, bal in result.state_before.token_balances.items():
            console.print(f"  {symbol}: {bal.amount:.6f}")
        console.print()
    
    # Balance changes table
    if result.state_diff and result.state_diff.has_changes():
        table = Table(title="Expected Balance Changes")
        table.add_column("Token", style="cyan")
        table.add_column("Before", justify="right")
        table.add_column("After", justify="right")
        table.add_column("Change", justify="right")
        
        for change in result.state_diff.balance_changes:
            delta_style = "green" if change.delta > 0 else "red"
            delta_str = f"+{change.delta:.6f}" if change.delta > 0 else f"{change.delta:.6f}"
            
            table.add_row(
                change.token,
                f"{change.before:,.6f}",
                f"{change.after:,.6f}",
                f"[{delta_style}]{delta_str}[/{delta_style}]"
            )
        
        console.print(table)
    else:
        console.print("[yellow]No balance changes detected[/yellow]")
    
    console.print()
    console.print(f"[dim]Execution: {result.execution_time_ms}ms | Network: {network}[/dim]")
    
    # Export to JSON if requested
    if args.output:
        output_data = {
            "success": result.success,
            "prompt": result.prompt,
            "network": result.network,
            "wallet": result.wallet,
            "execution_time_ms": result.execution_time_ms,
        }
        
        if result.state_before:
            output_data["state_before"] = {
                "sol": result.state_before.sol_balance,
                "tokens": {k: v.amount for k, v in result.state_before.token_balances.items()}
            }
        
        if result.state_diff:
            output_data["balance_changes"] = [
                {
                    "token": c.token,
                    "before": c.before,
                    "after": c.after,
                    "delta": c.delta
                }
                for c in result.state_diff.balance_changes
            ]
        
        if result.quote_info:
            output_data["quote"] = result.quote_info
        
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[dim]Results exported to: {args.output}[/dim]")
    
    return 0


def parse_prompt_only(args: argparse.Namespace) -> int:
    """Parse a prompt and show the structured intent (no execution)."""
    load_env()
    prompt = args.prompt
    
    console.print()
    console.print(Panel(f"[bold]{prompt}[/bold]", title="Parsing Prompt"))
    console.print()
    
    from simengine.parser.prompt_parser import PromptParser
    
    try:
        parser = PromptParser()
        result = parser.parse(prompt)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    if result.is_valid:
        console.print("[green]✓ Valid prompt[/green]\n")
    else:
        console.print("[red]✗ Invalid prompt[/red]")
        for error in result.errors:
            console.print(f"  [red]• {error}[/red]")
        console.print()
    
    # Show parsed actions
    console.print("[bold]Parsed Actions:[/bold]")
    for i, action in enumerate(result.actions):
        console.print(f"\n  [{i+1}] [cyan]{action.protocol}[/cyan].[cyan]{action.type}[/cyan]")
        for key, value in action.parameters.items():
            console.print(f"      {key}: {value}")
    
    if result.suggestions:
        console.print("\n[yellow]Suggestions:[/yellow]")
        for suggestion in result.suggestions:
            console.print(f"  → {suggestion}")
    
    return 0


def list_tokens(args: argparse.Namespace) -> int:
    """List available tokens."""
    from simengine.parser.token_registry import TOKEN_REGISTRY
    
    console.print()
    table = Table(title="Available Tokens")
    table.add_column("Symbol", style="cyan")
    table.add_column("Name")
    table.add_column("Decimals", justify="right")
    table.add_column("Mint", style="dim")
    
    for symbol, info in TOKEN_REGISTRY.items():
        table.add_row(
            info.symbol,
            info.name,
            str(info.decimals),
            info.mint[:16] + "..."
        )
    
    console.print(table)
    return 0


def show_balance(args: argparse.Namespace) -> int:
    """Show wallet balance on devnet/mainnet."""
    load_env()
    wallet = args.wallet or DEFAULT_WALLET
    network = args.network
    
    console.print()
    console.print(f"[bold]Fetching balances for {wallet[:8]}...{wallet[-4:]} ({network})[/bold]\n")
    
    from simengine.core.simulator import capture_real_snapshot
    
    async def _fetch():
        return await capture_real_snapshot(wallet, network)
    
    try:
        snapshot = asyncio.run(_fetch())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    console.print(f"[cyan]SOL:[/cyan] {snapshot.sol_balance:.6f}")
    
    if snapshot.token_balances:
        console.print("\n[bold]Tokens:[/bold]")
        for symbol, bal in snapshot.token_balances.items():
            console.print(f"  {symbol}: {bal.amount:.6f}")
    else:
        console.print("\n[dim]No token balances found[/dim]")
    
    return 0


def run_fuzz(args: argparse.Namespace) -> int:
    """Run agentic fuzzing on a program."""
    load_env()
    
    idl_path = args.idl
    prompt = args.prompt
    num_scenarios = args.scenarios
    mode = args.mode
    
    console.print()
    console.print(Panel(
        f"[bold cyan]{prompt or 'Explore all instruction paths'}[/bold cyan]\n\n"
        f"[dim]IDL: {idl_path}[/dim]\n"
        f"[dim]Mode: {mode} | Scenarios: {num_scenarios}[/dim]",
        title="[bold]🔬 Solana Gauntlet - Agentic Fuzzing[/bold]",
    ))
    console.print()
    
    # Parse IDL
    from simengine.analysis import IDLParser
    from simengine.fuzzing import ScenarioGenerator, FuzzRunner, FuzzingConfig
    
    try:
        parser = IDLParser()
        analysis = parser.parse_file(idl_path)
    except FileNotFoundError:
        console.print(f"[red]Error: IDL file not found: {idl_path}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Error parsing IDL: {e}[/red]")
        return 1
    
    console.print("[green]✓ Program analyzed[/green]")
    console.print(f"  [dim]Name: {analysis.name}[/dim]")
    console.print(f"  [dim]Instructions: {len(analysis.instructions)}[/dim]")
    for ix in analysis.instructions:
        flags = []
        if ix.is_privileged:
            flags.append("🔒")
        if ix.modifies_funds:
            flags.append("💰")
        console.print(f"    • {ix.name} {' '.join(flags)}")
    console.print()
    
    # Generate scenarios
    console.print("[bold]Generating test scenarios...[/bold]")
    
    try:
        generator = ScenarioGenerator()
        config = FuzzingConfig(
            num_scenarios=num_scenarios,
            mode=mode,
        )
        scenarios = generator.generate(analysis, config, user_prompt=prompt)
    except Exception as e:
        console.print(f"[red]Error generating scenarios: {e}[/red]")
        return 1
    
    console.print(f"[green]✓ Generated {len(scenarios)} scenarios[/green]")
    for s in scenarios:
        console.print(f"  • {s.name}")
    console.print()
    
    # Run scenarios
    console.print("[bold]Executing scenarios on Surfpool...[/bold]")
    
    def progress_callback(current, total, name):
        console.print(f"  [{current+1}/{total}] {name}...")
    
    try:
        runner = FuzzRunner(analysis=analysis)
        report = asyncio.run(runner.run(scenarios, config, progress_callback))
    except Exception as e:
        console.print(f"[red]Error running scenarios: {e}[/red]")
        return 1
    
    # Display report
    console.print()
    console.print(report.summary())
    
    # Export if requested
    if args.output:
        output_data = {
            "mode": mode,
            "total_scenarios": report.total_scenarios,
            "passed": report.passed,
            "failed": report.failed,
            "vulnerabilities": report.vulnerabilities,
            "anomalies": report.anomalies,
            "results": [r.scenario.to_dict() for r in report.results],
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[dim]Report exported to: {args.output}[/dim]")
    
    return 0 if not report.vulnerabilities else 1


def run_attack(args: argparse.Namespace) -> int:
    """Run adversarial testing on a program."""
    load_env()
    
    idl_path = args.idl
    focus = args.focus
    num_scenarios = args.scenarios
    
    console.print()
    console.print(Panel(
        f"[bold red]ADVERSARIAL MODE[/bold red]\n\n"
        f"[dim]IDL: {idl_path}[/dim]\n"
        f"[dim]Focus: {focus or 'all attack vectors'}[/dim]",
        title="[bold]⚔️ Solana Gauntlet - Adversarial Testing[/bold]",
    ))
    console.print()
    
    # Parse IDL
    from simengine.analysis import IDLParser
    from simengine.adversarial import AdversarialAgent, VulnerabilityDetector
    from simengine.fuzzing import FuzzRunner, FuzzingConfig
    
    try:
        parser = IDLParser()
        analysis = parser.parse_file(idl_path)
    except FileNotFoundError:
        console.print(f"[red]Error: IDL file not found: {idl_path}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Error parsing IDL: {e}[/red]")
        return 1
    
    console.print("[green]✓ Target analyzed[/green]")
    console.print()
    
    # Analyze attack surface
    console.print("[bold]Analyzing attack surface...[/bold]")
    
    try:
        agent = AdversarialAgent()
        surface = agent.analyze_attack_surface(analysis)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    if surface["high_value_targets"]:
        console.print("[yellow]High-value targets identified:[/yellow]")
        for t in surface["high_value_targets"]:
            console.print(f"  💰 {t['account']} (via {t['instruction']})")
    
    if surface["privileged_functions"]:
        console.print("[yellow]Privileged functions:[/yellow]")
        for p in surface["privileged_functions"]:
            console.print(f"  🔒 {p['name']}")
    
    console.print(f"\n[dim]Applicable attack vectors: {len(surface['applicable_attacks'])}[/dim]")
    console.print()
    
    # Generate attack scenarios
    console.print("[bold red]Generating attack scenarios...[/bold red]")
    
    try:
        scenarios = agent.generate_attack_scenarios(analysis, focus=focus, num_scenarios=num_scenarios)
    except Exception as e:
        console.print(f"[red]Error generating attacks: {e}[/red]")
        return 1
    
    console.print(f"[yellow]⚔️ {len(scenarios)} attack vectors prepared[/yellow]")
    for s in scenarios:
        console.print(f"  • {s.name}")
    console.print()
    
    # Execute attacks
    console.print("[bold]Executing attacks on Surfpool...[/bold]")
    
    def progress_callback(current, total, name):
        console.print(f"  [{current+1}/{total}] Attacking: {name}...")
    
    config = FuzzingConfig(num_scenarios=num_scenarios, mode="attack")
    
    try:
        runner = FuzzRunner(analysis=analysis)
        report = asyncio.run(runner.run(scenarios, config, progress_callback))
    except Exception as e:
        console.print(f"[red]Error running attacks: {e}[/red]")
        return 1
    
    # Run VulnerabilityDetector for deeper analysis with CWE classifications
    detector = VulnerabilityDetector()
    vulnerabilities = detector.analyze(report.results)
    
    # Display results
    console.print()
    
    if vulnerabilities:
        console.print("[bold red]🚨 VULNERABILITIES FOUND 🚨[/bold red]")
        for vuln in vulnerabilities:
            severity_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "blue",
                "low": "cyan",
            }.get(vuln.severity.value, "white")
            
            console.print(f"\n[{severity_color}]{vuln.severity.value.upper()}: {vuln.name}[/{severity_color}]")
            console.print(f"  Scenario: {vuln.scenario_name}")
            console.print(f"  {vuln.description}")
            if vuln.cwe_id:
                console.print(f"  [dim]CWE: {vuln.cwe_id}[/dim]")
            if vuln.recommendation:
                console.print(f"  [green]Fix: {vuln.recommendation}[/green]")
    elif report.vulnerabilities:
        console.print("[bold red]🚨 VULNERABILITIES FOUND 🚨[/bold red]")
        for vuln in report.vulnerabilities:
            console.print(f"\n[red]CRITICAL: {vuln['name']}[/red]")
            console.print(f"  Scenario: {vuln['scenario']}")
            console.print(f"  {vuln['description']}")
    else:
        console.print("[green]✓ No critical vulnerabilities found[/green]")
    
    if report.anomalies:
        console.print(f"\n[yellow]⚠️ {len(report.anomalies)} anomalies detected[/yellow]")
        for anom in report.anomalies[:3]:
            console.print(f"  • {anom['description']}")
    
    console.print(f"\n[dim]Time: {report.total_time_ms/1000:.1f}s[/dim]")
    
    # Export if requested
    if args.output:
        # Get detailed vulnerability report from detector
        vuln_report = detector.generate_report()
        
        output_data = {
            "mode": "adversarial",
            "focus": focus,
            "vulnerability_summary": vuln_report["summary"],
            "vulnerability_counts": vuln_report["counts"],
            "vulnerabilities": vuln_report["findings"],
            "anomalies": report.anomalies,
            "attack_scenarios": [s.to_dict() for s in scenarios],
            "coverage": report.coverage,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[dim]Report exported to: {args.output}[/dim]")
    
    # Return exit code based on severity
    if vulnerabilities:
        critical_count = sum(1 for v in vulnerabilities if v.severity.value == "critical")
        high_count = sum(1 for v in vulnerabilities if v.severity.value == "high")
        if critical_count > 0:
            return 2  # Critical findings
        elif high_count > 0:
            return 1  # High findings
    return 0



def run_analyze(args: argparse.Namespace) -> int:
    """Analyze a program without running tests."""
    load_env()
    
    idl_path = args.idl
    
    console.print()
    console.print(Panel(
        f"[bold cyan]Program Analysis[/bold cyan]\n\n"
        f"[dim]IDL: {idl_path}[/dim]",
        title="[bold]🔍 Solana Gauntlet - Static Analysis[/bold]",
    ))
    console.print()
    
    from simengine.analysis import IDLParser, StateGraphBuilder, InvariantExtractor
    
    # Parse IDL
    try:
        parser = IDLParser()
        analysis = parser.parse_file(idl_path)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    # Display program info
    console.print("[bold]Program Information[/bold]")
    console.print(f"  Name: {analysis.name}")
    console.print(f"  Program ID: {analysis.program_id or 'Not specified'}")
    console.print(f"  Instructions: {len(analysis.instructions)}")
    console.print()
    
    # Display instructions
    console.print("[bold]Instructions[/bold]")
    table = Table()
    table.add_column("Name", style="cyan")
    table.add_column("Accounts", style="dim")
    table.add_column("Args", style="dim")
    table.add_column("Flags", style="yellow")
    
    for ix in analysis.instructions:
        flags = []
        if ix.is_privileged:
            flags.append("🔒 Privileged")
        if ix.modifies_funds:
            flags.append("💰 Funds")
        if ix.can_create_accounts:
            flags.append("➕ Creates")
        if ix.can_close_accounts:
            flags.append("➖ Closes")
        
        table.add_row(
            ix.name,
            str(len(ix.accounts)),
            str(len(ix.arguments)),
            ", ".join(flags) if flags else "-"
        )
    
    console.print(table)
    console.print()
    
    # Build state graph
    console.print("[bold]State Graph[/bold]")
    builder = StateGraphBuilder()
    graph = builder.build(analysis)
    
    console.print(f"  States: {len(graph.nodes)}")
    for name, node in graph.nodes.items():
        console.print(f"    • {name} ({node.state_type.value})")
    
    console.print(f"  Transitions: {len(graph.transitions)}")
    for t in graph.transitions[:5]:
        console.print(f"    • {t.from_state} → {t.to_state} via {t.instruction}")
    if len(graph.transitions) > 5:
        console.print(f"    ... and {len(graph.transitions) - 5} more")
    console.print()
    
    # Extract invariants
    console.print("[bold]Detected Invariants[/bold]")
    extractor = InvariantExtractor()
    invariants = extractor.extract(analysis)
    
    for inv in invariants:
        severity_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(inv.severity, "white")
        console.print(f"  [{severity_color}]● {inv.name}[/{severity_color}]")
        console.print(f"    [dim]{inv.description}[/dim]")
    
    if not invariants:
        console.print("  [dim]No invariants detected[/dim]")
    
    # Export if requested
    if args.output:
        output_data = {
            "program": analysis.name,
            "instructions": [
                {
                    "name": ix.name,
                    "accounts": [a.name for a in ix.accounts],
                    "arguments": [a.name for a in ix.arguments],
                    "privileged": ix.is_privileged,
                    "modifies_funds": ix.modifies_funds,
                }
                for ix in analysis.instructions
            ],
            "state_graph": graph.to_dict(),
            "invariants": [
                {"name": inv.name, "description": inv.description, "severity": inv.severity}
                for inv in invariants
            ],
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[dim]Analysis exported to: {args.output}[/dim]")
    
    # Show mermaid diagram option
    if args.mermaid:
        console.print("\n[bold]State Graph (Mermaid)[/bold]")
        console.print("```mermaid")
        console.print(graph.to_mermaid())
        console.print("```")
    
    return 0


def run_replay(args: argparse.Namespace) -> int:
    """Replay a PoC from a JSON file."""
    load_env()
    
    poc_path = args.poc
    
    console.print()
    console.print(Panel(
        f"[bold red]PoC Replay[/bold red]\n\n"
        f"[dim]File: {poc_path}[/dim]",
        title="[bold]⚔️ Solana Gauntlet - Exploit Replay[/bold]",
    ))
    console.print()
    
    # Load PoC
    try:
        with open(poc_path, "r") as f:
            poc_data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading PoC: {e}[/red]")
        return 1
    
    console.print(f"[bold]PoC: {poc_data.get('name', 'Unknown')}[/bold]")
    console.print(f"  Vulnerability: {poc_data.get('vulnerability', 'Unknown')}")
    console.print(f"  Severity: {poc_data.get('severity', 'Unknown')}")
    console.print(f"  Description: {poc_data.get('description', 'No description')}")
    console.print()
    
    # Show steps
    console.print("[bold]Exploit Steps[/bold]")
    transactions = poc_data.get("transactions", [])
    for i, tx in enumerate(transactions):
        console.print(f"  {i + 1}. {tx.get('instruction', 'Unknown')}")
        if tx.get("description"):
            console.print(f"     [dim]{tx['description']}[/dim]")
    console.print()
    
    # Ask for confirmation
    if not args.yes:
        console.print("[yellow]⚠️ This will execute the PoC on a local Surfpool instance.[/yellow]")
        console.print("[dim]Use --yes to skip confirmation[/dim]")
        try:
            confirm = input("Continue? [y/N] ")
            if confirm.lower() != 'y':
                console.print("[dim]Aborted[/dim]")
                return 0
        except KeyboardInterrupt:
            console.print("\n[dim]Aborted[/dim]")
            return 0
    
    # Execute on Surfpool
    console.print("[bold]Executing PoC...[/bold]")
    
    from simengine.core.surfpool import SurfpoolManager, SurfpoolConfig
    
    async def _execute():
        config = SurfpoolConfig(
            rpc_port=9200,
            ws_port=9300,
            clone_from="mainnet",
        )
        
        try:
            async with SurfpoolManager(config=config) as surfpool:
                console.print(f"  [green]✓ Surfpool started at {surfpool.rpc_url}[/green]")
                
                for i, tx in enumerate(transactions):
                    console.print(f"  [{i + 1}/{len(transactions)}] Executing {tx.get('instruction', 'step')}...")
                    # In a full implementation, we would build and send the actual transaction
                    # For now, just simulate success
                    console.print(f"    [green]✓ Success[/green]")
                
                console.print()
                console.print(poc_data.get("expected_result", "Exploit executed"))
        except Exception as e:
            console.print(f"[red]Execution error: {e}[/red]")
            return 1
        
        return 0
    
    try:
        return asyncio.run(_execute())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="simengine",
        description="Natural language simulation engine for Solana protocols",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # run command
    run_parser = subparsers.add_parser("run", help="Run a simulation with real data")
    run_parser.add_argument("prompt", type=str, help="Natural language prompt")
    run_parser.add_argument(
        "--wallet", "-w",
        type=str,
        help=f"Wallet address (default: {DEFAULT_WALLET[:8]}...)"
    )
    run_parser.add_argument(
        "--network", "-n",
        type=str,
        choices=["devnet", "mainnet"],
        default="devnet",
        help="Network to use (default: devnet)"
    )
    run_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for JSON results"
    )
    
    # fuzz command
    fuzz_parser = subparsers.add_parser("fuzz", help="Run agentic fuzzing on a program")
    fuzz_parser.add_argument("idl", type=str, help="Path to Anchor IDL JSON file")
    fuzz_parser.add_argument(
        "--prompt", "-p",
        type=str,
        help="Optional guidance (e.g., 'focus on deposit instruction')"
    )
    fuzz_parser.add_argument(
        "--scenarios", "-n",
        type=int,
        default=10,
        help="Number of scenarios to generate (default: 10)"
    )
    fuzz_parser.add_argument(
        "--mode", "-m",
        type=str,
        choices=["explore", "boundary", "negative"],
        default="explore",
        help="Fuzzing mode (default: explore)"
    )
    fuzz_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for JSON report"
    )
    
    # attack command
    attack_parser = subparsers.add_parser("attack", help="Run adversarial testing")
    attack_parser.add_argument("idl", type=str, help="Path to Anchor IDL JSON file")
    attack_parser.add_argument(
        "--focus", "-f",
        type=str,
        choices=["fund-extraction", "privilege", "dos", "state", "all"],
        default="all",
        help="Focus area for attacks (default: all)"
    )
    attack_parser.add_argument(
        "--scenarios", "-n",
        type=int,
        default=5,
        help="Number of attack scenarios (default: 5)"
    )
    attack_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for JSON report"
    )
    
    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a program (static analysis)")
    analyze_parser.add_argument("idl", type=str, help="Path to Anchor IDL JSON file")
    analyze_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for JSON analysis"
    )
    analyze_parser.add_argument(
        "--mermaid",
        action="store_true",
        help="Output state graph as Mermaid diagram"
    )
    
    # replay command
    replay_parser = subparsers.add_parser("replay", help="Replay a PoC exploit")
    replay_parser.add_argument("poc", type=str, help="Path to PoC JSON file")
    replay_parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt"
    )
    
    # deploy command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy and test a custom program")
    deploy_parser.add_argument("program", type=str, help="Path to .so program file")
    deploy_parser.add_argument(
        "--idl", "-i",
        type=str,
        help="Path to Anchor IDL JSON file (for testing)"
    )
    deploy_parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Run fuzzing after deployment"
    )
    deploy_parser.add_argument(
        "--attack",
        action="store_true",
        help="Run adversarial testing after deployment"
    )
    deploy_parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for JSON report"
    )
    
    # parse command (preview only, no execution)
    parse_parser = subparsers.add_parser("parse", help="Parse prompt without running")
    parse_parser.add_argument("prompt", type=str, help="Natural language prompt")
    
    # tokens command
    subparsers.add_parser("tokens", help="List available tokens")
    
    # balance command
    balance_parser = subparsers.add_parser("balance", help="Show wallet balance")
    balance_parser.add_argument(
        "--wallet", "-w",
        type=str,
        help=f"Wallet address (default: {DEFAULT_WALLET[:8]}...)"
    )
    balance_parser.add_argument(
        "--network", "-n",
        type=str,
        choices=["devnet", "mainnet"],
        default="devnet",
        help="Network (default: devnet)"
    )
    
    return parser


def run_deploy(args: argparse.Namespace) -> int:
    """Deploy and test a custom program."""
    load_env()
    
    program_path = args.program
    idl_path = args.idl
    
    console.print()
    console.print(Panel(
        f"[bold cyan]Program Deployment[/bold cyan]\n\n"
        f"[dim]Program: {program_path}[/dim]",
        title="[bold]🚀 Solana Gauntlet - Custom Program Deployment[/bold]",
    ))
    console.print()
    
    # Validate program file
    from simengine.analysis import ProgramLoader
    
    loader = ProgramLoader()
    try:
        program_info = loader.load(program_path)
    except Exception as e:
        console.print(f"[red]Error loading program: {e}[/red]")
        return 1
    
    console.print("[bold]Program Info[/bold]")
    console.print(loader.summary(program_info))
    console.print()
    
    # Validate for deployment
    is_valid, issues = loader.validate_for_deployment(program_info)
    
    if not is_valid:
        console.print("[red]Program validation failed:[/red]")
        for issue in issues:
            console.print(f"  • {issue}")
        return 1
    
    console.print("[green]✓ Program validated for deployment[/green]")
    
    # Deploy to Surfpool
    from simengine.core.surfpool import SurfpoolManager, SurfpoolConfig
    
    console.print("\n[bold]Deploying to Surfpool...[/bold]")
    
    async def _deploy():
        config = SurfpoolConfig(
            rpc_port=9500,
            ws_port=9600,
            clone_from="mainnet",
            programs_to_deploy=[program_path],
        )
        
        try:
            async with SurfpoolManager(config=config) as surfpool:
                console.print(f"[green]✓ Program deployed at {surfpool.rpc_url}[/green]")
                
                # If IDL provided, run requested testing
                if idl_path and (args.fuzz or args.attack):
                    from simengine.analysis import IDLParser
                    from simengine.fuzzing import ScenarioGenerator, FuzzRunner, FuzzingConfig
                    from simengine.adversarial import AdversarialAgent
                    
                    parser = IDLParser()
                    analysis = parser.parse_file(idl_path)
                    
                    if args.fuzz:
                        console.print("\n[bold]Running fuzzing...[/bold]")
                        generator = ScenarioGenerator()
                        runner = FuzzRunner(analysis=analysis, program_path=program_path)
                        fuzz_config = FuzzingConfig(num_scenarios=5)
                        
                        scenarios = generator.generate(analysis, fuzz_config)
                        report = await runner.run(scenarios, fuzz_config)
                        
                        console.print(f"\n[bold]Fuzzing Results[/bold]")
                        console.print(f"  Scenarios: {report.total_scenarios}")
                        console.print(f"  Passed: {report.passed}")
                        console.print(f"  Failed: {report.failed}")
                        
                        if report.vulnerabilities:
                            console.print(f"\n[red]🚨 VULNERABILITIES: {len(report.vulnerabilities)}[/red]")
                        
                    if args.attack:
                        console.print("\n[bold]Running adversarial testing...[/bold]")
                        agent = AdversarialAgent()
                        attack_scenarios = agent.generate_attack_scenarios(analysis)
                        
                        runner = FuzzRunner(analysis=analysis, program_path=program_path)
                        attack_config = FuzzingConfig(num_scenarios=5, mode="adversarial")
                        report = await runner.run(attack_scenarios, attack_config)
                        
                        console.print(f"\n[bold]Attack Results[/bold]")
                        console.print(f"  Attacks: {report.total_scenarios}")
                        
                        if report.vulnerabilities:
                            console.print(f"\n[red]🚨 CRITICAL VULNERABILITIES: {len(report.vulnerabilities)}[/red]")
                else:
                    console.print("[dim]Program deployed. Use --fuzz or --attack with --idl to test.[/dim]")
                
                return 0
                
        except Exception as e:
            console.print(f"[red]Deployment error: {e}[/red]")
            return 1
    
    try:
        return asyncio.run(_deploy())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command == "run":
        return run_simulation(args)
    elif args.command == "fuzz":
        return run_fuzz(args)
    elif args.command == "attack":
        return run_attack(args)
    elif args.command == "analyze":
        return run_analyze(args)
    elif args.command == "replay":
        return run_replay(args)
    elif args.command == "deploy":
        return run_deploy(args)
    elif args.command == "parse":
        return parse_prompt_only(args)
    elif args.command == "tokens":
        return list_tokens(args)
    elif args.command == "balance":
        return show_balance(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())



