# src/agents/security_agent.py
# TRUE Agentic AI Security Analyst
# Uses LangChain + Groq (Llama3.3) for real reasoning
# Works with LangChain 1.2.x + Groq free tier

import os
import json
from collections import Counter
from dotenv import load_dotenv

from langchain_groq import ChatGroq
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

load_dotenv()

# ─────────────────────────────────────────────────────
# RISK SCORE CALCULATION — SINGLE SOURCE OF TRUTH
#
# Formula breakdown:
#
#   severity_score  = (weighted_sum / max_possible_weight) × 100
#
#       weighted_sum        = critical×5 + high×3 + medium×2 + low×1
#       max_possible_weight = total_findings × 5   (if ALL were CRITICAL)
#
#       This measures: "How bad is the average finding?"
#       Range: 0–100. Scales correctly regardless of finding count.
#
#   coverage_score  = (affected_resources / total_resources) × 100
#
#       total_resources is DYNAMIC — counted from the actual configs,
#       not hardcoded. Works for every scenario.
#
#   final_score     = (severity_score × 0.6) + (coverage_score × 0.4)
#
#       60% weight on severity (what's wrong is more important)
#       40% weight on coverage (how spread the risk is)
#       Range: 0–100
#
#   risk_level thresholds:
#       >= 75  → CRITICAL
#       >= 50  → HIGH
#       >= 25  → MEDIUM
#       <  25  → LOW
#
# ─────────────────────────────────────────────────────

def _compute_risk(findings_list: list, total_resources: int = None) -> dict:
    """
    Core risk scoring function used by both the @tool and the fallback.

    findings_list   : list of dicts with at least "severity" and "resource_name"
    total_resources : total resource count from configs (dynamic).
                      If None, falls back to unique resource names in findings.
    """
    counts   = Counter(f.get("severity") for f in findings_list)
    critical = counts.get("CRITICAL", 0)
    high     = counts.get("HIGH",     0)
    medium   = counts.get("MEDIUM",   0)
    low      = counts.get("LOW",      0)
    total    = len(findings_list)

    weighted_sum   = critical*5 + high*3 + medium*2 + low*1
    max_possible   = total * 5
    severity_score = (weighted_sum / max_possible * 100) if max_possible > 0 else 0

    affected       = len(set(f.get("resource_name") for f in findings_list))
    denom          = total_resources if (total_resources and total_resources > 0) else affected
    coverage_score = min((affected / denom) * 100, 100)

    final_score = (severity_score * 0.6) + (coverage_score * 0.4)

    if final_score >= 75:
        risk_level = "CRITICAL"
    elif final_score >= 50:
        risk_level = "HIGH"
    elif final_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "total":           total,
        "critical":        critical,
        "high":            high,
        "medium":          medium,
        "low":             low,
        "weighted_sum":    weighted_sum,
        "max_possible":    max_possible,
        "affected":        affected,
        "total_resources": denom,
        "risk_score":      round(final_score,    1),
        "severity_score":  round(severity_score, 1),
        "coverage_score":  round(coverage_score, 1),
        "risk_level":      risk_level,
    }


def _count_total_resources(configs: dict) -> int:
    """
    Count total resources in a configs dict dynamically.
    Works for every scenario regardless of resource count.
    """
    return (
        len(configs.get("s3_buckets",      [])) +
        len(configs.get("iam_users",       [])) +
        len(configs.get("security_groups", [])) +
        len(configs.get("rds_instances",   []))
    )


# ─────────────────────────────────────────────────────
# ATTACK SCENARIO DETECTION
#
# Maps finding title keywords to human-readable attack
# scenario descriptions used by the fallback report.
#
# Each entry:
#   keywords  : list of strings — if ANY appear in ANY finding title → trigger
#   scenario  : the attack scenario text to include in the report
#
# Adding a new rule to audit_engine.py?
# Add its attack scenario here too.
# ─────────────────────────────────────────────────────

ATTACK_SCENARIOS = [
    {
        "keywords": ["SSH Port Open"],
        "scenario": (
            "  🎯 Brute Force SSH Attack\n"
            "     Automated scanners (Shodan, Masscan) find open port 22 within minutes.\n"
            "     Attacker runs credential stuffing or brute force — no rate limiting on raw SSH.\n"
        ),
    },
    {
        "keywords": ["RDP Port Open"],
        "scenario": (
            "  🎯 RDP Ransomware Entry Point\n"
            "     Open RDP (port 3389) is the #1 ransomware entry vector.\n"
            "     Attackers buy leaked RDP credentials on dark web markets for under $10.\n"
        ),
    },
    {
        "keywords": ["S3 Bucket is Publicly Accessible"],
        "scenario": (
            "  🎯 Data Exfiltration via Public S3\n"
            "     Tools like GrayhatWarfare and bucket-finder index public buckets automatically.\n"
            "     Attacker downloads all objects with no authentication required.\n"
        ),
    },
    {
        "keywords": ["MFA Not Enabled"],
        "scenario": (
            "  🎯 Account Takeover via Phishing\n"
            "     Phishing email steals admin password. Without MFA, attacker has full AWS access.\n"
            "     From there: create backdoor IAM users, exfiltrate data, launch crypto-miners.\n"
        ),
    },
    {
        "keywords": ["Database Publicly Accessible"],
        "scenario": (
            "  🎯 Direct Database Attack\n"
            "     Public database endpoint found by automated port scanners within hours.\n"
            "     Attacker attempts SQL injection, default credentials, or known CVEs.\n"
        ),
    },
    {
        "keywords": ["Access Key Not Rotated"],
        "scenario": (
            "  🎯 Leaked Credentials Abuse\n"
            "     Old access keys are frequently leaked in public GitHub repos, CI logs, or Docker images.\n"
            "     Automated scanners (truffleHog, GitGuardian) find them and spin up crypto-miners within minutes.\n"
        ),
    },
    {
        "keywords": ["Redis Port Open"],
        "scenario": (
            "  🎯 Redis Unauthenticated Remote Code Execution\n"
            "     Redis open to 0.0.0.0/0 with no auth is a known critical CVE pattern.\n"
            "     Attacker writes SSH keys to the server via Redis CONFIG SET — instant shell access.\n"
        ),
    },
    {
        "keywords": ["Elasticsearch Port Open"],
        "scenario": (
            "  🎯 Elasticsearch Data Exfiltration\n"
            "     Elasticsearch (port 9200) open to the internet requires no authentication by default.\n"
            "     Attacker hits /_cat/indices, dumps all data — frequently leads to regulatory fines.\n"
        ),
    },
    {
        "keywords": ["MySQL Port Open", "PostgreSQL Port Open", "MongoDB Port Open"],
        "scenario": (
            "  🎯 Database Port Exposure\n"
            "     Database port open to 0.0.0.0/0 allows direct connection attempts.\n"
            "     Attacker tries default credentials, known CVEs, or brute forces the auth.\n"
        ),
    },
    {
        "keywords": ["Inactive User Account"],
        "scenario": (
            "  🎯 Dormant Account Exploitation\n"
            "     Inactive accounts (ex-employees, old service accounts) are rarely monitored.\n"
            "     Attacker compromises forgotten credentials — no one notices unusual activity.\n"
        ),
    },
    {
        "keywords": ["Database Backups Disabled"],
        "scenario": (
            "  🎯 Ransomware with No Recovery Path\n"
            "     Ransomware encrypts the database. Without backups, the only option is paying the ransom.\n"
            "     Average ransom demand for a mid-size company: $200,000–$2,000,000.\n"
        ),
    },
]


def _build_attack_scenarios(findings: list) -> str:
    """
    Build the attack scenarios section of the fallback report.
    Only includes scenarios where at least one finding title
    matches a keyword — no more hardcoded always-on scenarios.
    """
    titles   = [f.title for f in findings]
    sections = []
    seen     = set()

    for entry in ATTACK_SCENARIOS:
        key = entry["scenario"][:40]   # dedup key — first 40 chars of scenario text
        if key in seen:
            continue
        if any(kw in title for kw in entry["keywords"] for title in titles):
            sections.append(entry["scenario"])
            seen.add(key)

    return "\n".join(sections) if sections else "  No specific attack scenarios identified.\n"


# ─────────────────────────────────────────────────────
# TOOLS — Functions the AI Agent can CHOOSE to call
# ─────────────────────────────────────────────────────

@tool
def calculate_risk_score(findings_json: str) -> str:
    """Calculate normalized risk score from findings.
    Use this FIRST to understand overall risk level.
    Input must be a JSON string of findings array."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Error parsing findings JSON"

    result = _compute_risk(findings, total_resources=None)
    return json.dumps(result)


@tool
def analyze_critical_findings(findings_json: str) -> str:
    """Get summary of most dangerous findings.
    Use this to understand the top critical and high severity issues.
    Input must be a JSON string of findings array."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Error parsing findings JSON"

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high     = [f for f in findings if f.get("severity") == "HIGH"]

    result  = f"CRITICAL FINDINGS ({len(critical)}):\n"
    for f in critical[:5]:
        result += f"  - [{f.get('resource_type')}] {f.get('resource_name')}: {f.get('title')}\n"

    result += f"\nHIGH FINDINGS ({len(high)}):\n"
    for f in high[:5]:
        result += f"  - [{f.get('resource_type')}] {f.get('resource_name')}: {f.get('title')}\n"

    return result


@tool
def analyze_by_resource_type(findings_json: str) -> str:
    """Group findings by resource type to see which areas are most affected.
    Use this to identify the most vulnerable parts of infrastructure.
    Input must be a JSON string of findings array."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Error parsing findings JSON"

    by_type = {}
    for f in findings:
        rtype = f.get("resource_type", "Unknown")
        if rtype not in by_type:
            by_type[rtype] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_type[rtype][f.get("severity", "LOW")] += 1

    result = "FINDINGS BY RESOURCE TYPE:\n"
    for rtype, counts in by_type.items():
        total   = sum(counts.values())
        result += f"\n{rtype} ({total} issues): "
        result += f"Critical={counts['CRITICAL']}, High={counts['HIGH']}, "
        result += f"Medium={counts['MEDIUM']}, Low={counts['LOW']}\n"

    return result


@tool
def check_compliance_violations(findings_json: str) -> str:
    """Check which compliance standards are violated based on findings.
    Maps technical issues to legal requirements like GDPR, HIPAA, NIST.
    Input must be a JSON string of findings array."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Error parsing findings JSON"

    titles     = [f.get("title", "") for f in findings]
    violations = []

    if any("Encrypt" in t for t in titles):
        violations.append("GDPR Article 32 - Encryption of personal data required")
        violations.append("PCI-DSS Req 3.4 - Payment card data must be encrypted")
    if any("MFA" in t for t in titles):
        violations.append("NIST 800-53 IA-2 - Multi-factor authentication mandatory")
        violations.append("ISO 27001 A.9.4 - Strong authentication required")
    if any("Public" in t for t in titles):
        violations.append("HIPAA §164.312 - PHI must not be publicly accessible")
    if any("Logging" in t for t in titles):
        violations.append("SOC 2 CC7.2 - Audit logging and monitoring required")
    if any("Inactive" in t for t in titles):
        violations.append("ISO 27001 A.9.2.6 - Access rights of inactive users must be removed")
    if any("Key" in t or "Password" in t for t in titles):
        violations.append("NIST 800-53 IA-5 - Authenticator management and rotation required")
    if any("Multi-AZ" in t for t in titles):
        violations.append("SOC 2 A1.1 - Availability commitments require redundant infrastructure")

    if not violations:
        return "No compliance violations detected."

    return "COMPLIANCE VIOLATIONS:\n" + "\n".join(f"  ❌ {v}" for v in violations)


@tool
def get_remediation_priorities(findings_json: str) -> str:
    """Get top 10 priority remediation actions sorted by severity.
    Use this to build the action plan.
    Input must be a JSON string of findings array."""
    try:
        findings = json.loads(findings_json)
    except Exception:
        return "Error parsing findings JSON"

    order    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(findings, key=lambda f: order.get(f.get("severity"), 99))

    result = "TOP 10 PRIORITY ACTIONS:\n"
    for i, f in enumerate(sorted_f[:10], 1):
        result += f"\n[{i}] {f.get('severity')} - {f.get('resource_name')}\n"
        result += f"    Issue: {f.get('title')}\n"
        result += f"    Fix:   {f.get('recommendation')}\n"

    return result


# ─────────────────────────────────────────────────────
# HELPER — Build compact findings for tools
# ─────────────────────────────────────────────────────

def _compact_findings(findings):
    """Return minimal findings dict — just what tools need"""
    return [
        {
            "severity":       f.severity,
            "rule_id":        f.rule_id,
            "resource_type":  f.resource_type,
            "resource_name":  f.resource_name,
            "title":          f.title,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]


# ─────────────────────────────────────────────────────
# MAIN SECURITY AGENT CLASS
# ─────────────────────────────────────────────────────

class SecurityAgent:

    def __init__(self):
        self.llm = ChatGroq(
            api_key     = os.getenv("GROQ_API_KEY"),
            model       = "llama-3.1-8b-instant",
            temperature = 0.1,
            max_tokens  = 1024,
        )

        self.tools = [
            calculate_risk_score,
            analyze_critical_findings,
            analyze_by_resource_type,
            check_compliance_violations,
            get_remediation_priorities,
        ]

        self.system_prompt = """
        You are a senior cloud security expert AI agent.

You have access to tools:
- calculate_risk_score (use this first)
- analyze_critical_findings
- analyze_by_resource_type
- check_compliance_violations
- get_remediation_priorities

Guidelines:
- Always start with calculate_risk_score
- Use other tools when they improve accuracy
- Focus on critical and high severity issues first
- Correlate risks across services (IAM, S3, RDS, Security Groups)
- Base your analysis on tool outputs when possible

Your goal:
Produce a structured security report with:

1. Executive Summary (include risk score)
2. Top Risks
3. Attack Scenarios
4. Immediate Actions
5. Compliance Impact

Keep the analysis clear, practical, and security-focused.
Avoid unnecessary verbosity.
"""

        self.agent = create_react_agent(
            model  = self.llm,
            tools  = self.tools,
            prompt = self.system_prompt
        )

    def analyze(self, findings, configs):
        """Main entry — runs the agentic analysis"""

        print("\n🤖 Agentic AI Security Analyst Starting...\n")
        print("   (Watch the agent think in real time!)\n")
        print("─" * 50)

        total_resources = _count_total_resources(configs)
        full_compact    = _compact_findings(findings)
        summary_data    = _compute_risk(full_compact, total_resources=total_resources)

        important = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        important = important[:10]
        compact   = _compact_findings(important)

        summary_lines    = [
            f"{f['severity']} | {f['resource_name']} | {f['title']}"
            for f in compact
        ]
        findings_summary = "\n".join(summary_lines)

        risk_score = summary_data["risk_score"]
        risk_level = summary_data["risk_level"]
        total      = summary_data["total"]

        try:
            response = self.agent.invoke({
                "messages": [
                    HumanMessage(
                        content=(
                            f"Analyze these {total} AWS security findings and produce a security report.\n\n"
                            f"PRE-COMPUTED RISK SCORE (based on ALL {total} findings): "
                            f"{risk_score}/100 — {risk_level}\n\n"
                            f"TOP CRITICAL/HIGH FINDINGS (showing {len(important)} of {total}):\n"
                            f"{findings_summary}\n\n"
                            f"Use {risk_score}/100 as the authoritative risk score in your Executive Summary."
                        )
                    )
                ]
            })

            messages  = response.get("messages", [])
            ai_report = messages[-1].content if messages else "No report generated."

        except Exception as e:
            print(f"\n⚠️  Agent error: {e}\n")
            print("   Falling back to rule-based report...\n")
            ai_report = self._fallback_report(findings, configs, summary_data)

        summary = {
            "total":           summary_data["total"],
            "critical":        summary_data["critical"],
            "high":            summary_data["high"],
            "medium":          summary_data["medium"],
            "low":             summary_data["low"],
            "risk_score":      summary_data["risk_score"],
            "severity_score":  summary_data["severity_score"],
            "coverage_score":  summary_data["coverage_score"],
            "total_resources": summary_data["total_resources"],
        }

        action_plan = self._build_action_plan(findings)

        print("\n" + "─" * 50)
        print("✅ Agentic Analysis Complete!\n")

        return {
            "summary":     summary,
            "ai_report":   ai_report,
            "action_plan": action_plan,
        }

    def _fallback_report(self, findings, configs, summary_data=None):
        """
        Fallback rule-based report if Groq API fails.
        Uses _compute_risk for consistent, correct scoring.
        """
        if summary_data is None:
            total_resources = _count_total_resources(configs)
            compact         = _compact_findings(findings)
            summary_data    = _compute_risk(compact, total_resources=total_resources)

        critical        = summary_data["critical"]
        high            = summary_data["high"]
        medium          = summary_data["medium"]
        low             = summary_data["low"]
        severity_score  = summary_data["severity_score"]
        coverage_score  = summary_data["coverage_score"]
        score           = summary_data["risk_score"]
        affected        = summary_data["affected"]
        total_resources = summary_data["total_resources"]

        risk_label = (
            "CRITICAL RISK 🔴" if score >= 75 else
            "HIGH RISK 🟠"     if score >= 50 else
            "MEDIUM RISK 🟡"   if score >= 25 else
            "LOW RISK 🟢"
        )

        critical_findings = [f for f in findings if f.severity == "CRITICAL"]

        # ── Top 3 critical risks ──────────────────────────────────
        top_risks = ""
        for i, f in enumerate(critical_findings[:3], 1):
            top_risks += f"  {i}. [{f.resource_type}] {f.resource_name}: {f.title}\n"
            top_risks += f"     {f.description}\n\n"

        # ── Attack scenarios — dynamic, driven by ATTACK_SCENARIOS table ──
        scenarios = _build_attack_scenarios(findings)

        # ── Immediate actions ─────────────────────────────────────
        immediate = ""
        for f in critical_findings[:5]:
            immediate += f"  • {f.resource_name}: {f.recommendation}\n"

        # ── Compliance violations ─────────────────────────────────
        titles     = [f.title for f in findings]
        violations = []
        if any("Encrypt" in t for t in titles):
            violations.append("  ❌ GDPR Article 32 — encryption of personal data required")
            violations.append("  ❌ PCI-DSS Req 3.4 — payment card data must be encrypted")
        if any("MFA" in t for t in titles):
            violations.append("  ❌ NIST 800-53 IA-2 — MFA mandatory for all accounts")
            violations.append("  ❌ ISO 27001 A.9.4 — strong authentication required")
        if any("Public" in t for t in titles):
            violations.append("  ❌ HIPAA §164.312 — PHI must not be publicly accessible")
        if any("Logging" in t for t in titles):
            violations.append("  ❌ SOC 2 CC7.2 — audit logging and monitoring required")
        if any("Inactive" in t for t in titles):
            violations.append("  ❌ ISO 27001 A.9.2.6 — inactive user access must be revoked")
        if any("Key" in t or "Password" in t for t in titles):
            violations.append("  ❌ NIST 800-53 IA-5 — credential rotation required")
        if any("Multi-AZ" in t for t in titles):
            violations.append("  ❌ SOC 2 A1.1 — redundant infrastructure required for availability")

        return f"""
🔴 OVERALL RISK LEVEL: {risk_label} ({score}/100)
{'='*60}
  Severity Score     : {severity_score}/100
  Coverage Score     : {coverage_score}/100
  Resources Affected : {affected}/{total_resources}

1. EXECUTIVE SUMMARY
{'-'*40}
The AWS infrastructure audit reveals a {risk_label} posture with a risk score
of {score}/100. A total of {len(findings)} issues were identified across {affected}
resources, including {critical} critical and {high} high severity findings
requiring immediate attention.

2. TOP 3 CRITICAL RISKS
{'-'*40}
{top_risks}
3. ATTACK SCENARIOS
{'-'*40}
{scenarios}
4. IMMEDIATE ACTIONS (Fix within 24 hours)
{'-'*40}
{immediate}
5. COMPLIANCE IMPACT
{'-'*40}
{chr(10).join(violations) if violations else "  No compliance violations detected."}
"""

    def _build_action_plan(self, findings):
        """Build prioritized action plan"""
        order    = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_f = sorted(findings, key=lambda f: order.get(f.severity, 99))

        return [
            {
                "priority": i,
                "severity": f.severity,
                "resource": f.resource_name,
                "issue":    f.title,
                "fix":      f.recommendation,
            }
            for i, f in enumerate(sorted_f[:10], 1)
        ]