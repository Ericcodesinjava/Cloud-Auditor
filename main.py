# main.py
# Terminal entry point for the Cloud Security Auditor.
# Supports scenario selection via --scenario flag.
#
# Usage:
#   python3 main.py                          # defaults to startup
#   python3 main.py --scenario fintech
#   python3 main.py --scenario healthcare
#   python3 main.py --scenario enterprise
#   python3 main.py --scenario post_breach
#   python3 main.py --list-scenarios

import argparse

from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich         import box

from src.fetcher.mock_data import get_scenario_configs, SCENARIOS
from src.auditor.audit_engine  import AuditEngine
from src.agents.security_agent import SecurityAgent
from src.ml.predictor          import MisconfigurationPredictor, build_prediction_summary

console = Console()


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def print_banner(scenario_label: str):
    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   🛡️  AGENTIC AI CLOUD SECURITY AUDITOR              ║[/bold cyan]")
    console.print("[bold cyan]║   Predictive Misconfiguration Analysis System        ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════════════════════╝[/bold cyan]")
    console.print(f"\n  [bold white]Scenario:[/bold white] [bold yellow]{scenario_label}[/bold yellow]\n")


# ─────────────────────────────────────────────
# FINDINGS TABLE
# ─────────────────────────────────────────────

def print_findings_table(findings: list):
    table = Table(
        title      = f"🔍 Security Findings  ({len(findings)} total)",
        box        = box.ROUNDED,
        show_lines = True,
    )
    table.add_column("Severity",     style="bold",  width=10)
    table.add_column("Rule ID",      style="cyan",  width=10)
    table.add_column("Resource",     style="white", width=28)
    table.add_column("Issue",        style="white", width=42)

    COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "bold yellow",
        "MEDIUM":   "bold white",
        "LOW":      "bold green",
    }

    for f in findings:
        color = COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.rule_id,
            f.resource_name,
            f.title,
        )

    console.print(table)


# ─────────────────────────────────────────────
# RISK SUMMARY
# ─────────────────────────────────────────────

def print_summary(summary: dict):
    score      = summary["risk_score"]
    risk_color = (
        "bold red"    if score >= 75 else
        "bold yellow" if score >= 50 else
        "bold white"  if score >= 25 else
        "bold green"
    )
    risk_label = (
        "CRITICAL RISK 🔴" if score >= 75 else
        "HIGH RISK 🟠"     if score >= 50 else
        "MEDIUM RISK 🟡"   if score >= 25 else
        "LOW RISK 🟢"
    )

    console.print()
    console.print("[bold white]📊 RISK SUMMARY[/bold white]")
    console.print(f"  Risk Score      : [{risk_color}]{score}/100  —  {risk_label}[/{risk_color}]")
    console.print(f"  Severity Score  : {summary['severity_score']}/100")
    console.print(f"  Coverage Score  : {summary['coverage_score']}/100")
    console.print(f"  Total Issues    : [bold]{summary['total']}[/bold]")
    console.print(f"  🔴 Critical     : [bold red]{summary['critical']}[/bold red]")
    console.print(f"  🟠 High         : [bold yellow]{summary['high']}[/bold yellow]")
    console.print(f"  🟡 Medium       : [bold]{summary['medium']}[/bold]")
    console.print(f"  🟢 Low          : [bold green]{summary['low']}[/bold green]")
    console.print(
        f"  Resources       : {summary.get('total_resources', '?')} scanned"
    )
    console.print()


# ─────────────────────────────────────────────
# ACTION PLAN
# ─────────────────────────────────────────────

def print_action_plan(action_plan: list):
    console.print("\n[bold white]🎯 TOP 10 PRIORITY ACTIONS[/bold white]\n")

    COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "bold yellow",
        "MEDIUM":   "white",
        "LOW":      "green",
    }

    for item in action_plan:
        color = COLORS.get(item["severity"], "white")
        console.print(
            f"  [{item['priority']:>2}]  [{color}]{item['severity']:<8}[/{color}]  "
            f"[cyan]{item['resource']}[/cyan]"
        )
        console.print(f"        Issue : {item['issue']}")
        console.print(f"        Fix   : {item['fix']}")
        console.print()


# ─────────────────────────────────────────────
# PREDICTIVE SUMMARY
# ─────────────────────────────────────────────

def print_predictive_summary(predictions: list, pred_summary: dict):
    console.print("\n[bold white]🔮 PREDICTIVE ANALYSIS[/bold white]\n")

    console.print(
        f"  Total Predictions : {pred_summary['total']}\n"
        f"  🔴 Critical        : {pred_summary['critical']}\n"
        f"  🟠 High            : {pred_summary['high']}\n"
        f"  🟡 Medium          : {pred_summary['medium']}\n"
        f"  🟢 Low             : {pred_summary['low']}\n"
        f"  ⚡ Soonest Issue   : {pred_summary['soonest_days']} days\n"
    )

    # Show top 5 most urgent predictions as a table
    top5  = predictions[:5]
    table = Table(
        title      = "⏰ Top 5 Predicted Violations",
        box        = box.ROUNDED,
        show_lines = True,
    )
    table.add_column("Urgency",       style="bold",  width=10)
    table.add_column("Days Until",    style="cyan",  width=10)
    table.add_column("Resource",      style="white", width=28)
    table.add_column("Prediction",    style="white", width=30)
    table.add_column("Probability",   style="white", width=12)

    COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "bold yellow",
        "MEDIUM":   "bold white",
        "LOW":      "bold green",
    }

    for p in top5:
        color = COLORS.get(p.urgency, "white")
        table.add_row(
            f"[{color}]{p.urgency}[/{color}]",
            str(p.days_until),
            p.resource_name,
            p.prediction_type,
            f"{p.risk_probability}%",
        )

    console.print(table)


# ─────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Agentic AI Cloud Security Auditor — Terminal Version",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        default="startup",
        help=(
            "Company scenario to audit:\n" +
            "\n".join(f"  {k:<12} {v}" for k, v in SCENARIOS.items())
        ),
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List all available scenarios and exit.",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    args = parse_args()

    if args.list_scenarios:
        console.print("\n[bold cyan]Available Scenarios:[/bold cyan]\n")
        for key, label in SCENARIOS.items():
            console.print(f"  [bold yellow]{key:<14}[/bold yellow] {label}")
        console.print()
        return

    scenario       = args.scenario
    scenario_label = SCENARIOS[scenario]

    print_banner(scenario_label)

    # ── STEP 1: Fetch configs ──────────────────────────────────────
    console.print("[bold]STEP 1:[/bold] Fetching cloud configurations...")
    configs = get_scenario_configs(scenario)
    console.print(
        f"  ✅ Loaded scenario [bold yellow]{scenario_label}[/bold yellow]  "
        f"(account {configs['account_id']}, region {configs['region']})\n"
    )

    # ── STEP 2: Run security audit ─────────────────────────────────
    console.print("[bold]STEP 2:[/bold] Running security audit...")
    engine   = AuditEngine()
    findings = engine.run_full_audit(configs)

    print_findings_table(findings)

    # ── STEP 3: AI analysis ────────────────────────────────────────
    console.print("\n[bold]STEP 3:[/bold] Running AI analysis...")
    agent  = SecurityAgent()
    result = agent.analyze(findings, configs)

    print_summary(result["summary"])

    console.print("[bold white]🤖 AI SECURITY ANALYSIS REPORT[/bold white]\n")
    console.print(result["ai_report"])

    print_action_plan(result["action_plan"])

    # ── STEP 4: Predictive analysis ────────────────────────────────
    console.print("\n[bold]STEP 4:[/bold] Running predictive analysis...")
    predictor    = MisconfigurationPredictor()
    predictions  = predictor.predict(configs)
    pred_summary = build_prediction_summary(predictions)

    print_predictive_summary(predictions, pred_summary)

    console.print(
        "\n[bold cyan]✅ Audit Complete! "
        f"Found {result['summary']['total']} issues + "
        f"{pred_summary['total']} future predictions.[/bold cyan]\n"
    )


if __name__ == "__main__":
    main()