# dashboard.py
# Streamlit Web Dashboard for Cloud Security Auditor

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from src.fetcher.mock_data import get_scenario_configs, SCENARIOS
from src.auditor.audit_engine  import AuditEngine
from src.agents.security_agent import SecurityAgent
from src.ml.predictor          import MisconfigurationPredictor, build_prediction_summary


# ─────────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────────
st.set_page_config(
    page_title = "Cloud Security Auditor",
    page_icon  = "🛡️",
    layout     = "wide"
)

# ─────────────────────────────────────────────
# CUSTOM CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1e2130;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        border: 1px solid #2d3250;
    }
    .critical { color: #ff4b4b; font-size: 2rem; font-weight: bold; }
    .high     { color: #ffa500; font-size: 2rem; font-weight: bold; }
    .medium   { color: #ffd700; font-size: 2rem; font-weight: bold; }
    .low      { color: #00cc00; font-size: 2rem; font-weight: bold; }
    .header-title {
        font-size: 2.5rem;
        font-weight: bold;
        color: #00d4ff;
        text-align: center;
    }
    .sub-title {
        font-size: 1.1rem;
        color: #888;
        text-align: center;
        margin-bottom: 30px;
    }
    .scenario-badge {
        background: #1e2130;
        border: 1px solid #2d3250;
        border-radius: 8px;
        padding: 10px 16px;
        font-size: 0.9rem;
        color: #00d4ff;
        margin-bottom: 12px;
    }
    .score-sub {
        font-size: 0.85rem;
        color: #888;
        margin-top: 4px;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.markdown('<div class="header-title">🛡️ Agentic AI Cloud Security Auditor</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Predictive Misconfiguration Analysis System</div>', unsafe_allow_html=True)
st.divider()


# ─────────────────────────────────────────────
# SCENARIO DESCRIPTIONS
# ─────────────────────────────────────────────
SCENARIO_DESCRIPTIONS = {
    "startup":     "🚀 Moving fast, skipping basics. Expect open ports, shared admin keys, no encryption.",
    "fintech":     "💳 Handles payments. Heavy PCI-DSS & GDPR violations. Audit is incoming.",
    "healthcare":  "🏥 Stores patient data (PHI). HIPAA exposure across all resource types.",
    "enterprise":  "🏢 10+ years of legacy config debt. Ex-employees, ancient keys, forgotten rules.",
    "post_breach": "🔥 Breach happened 3 days ago. Attacker may still have a foothold. Maximum severity.",
}

SCENARIO_ICONS = {
    "startup":     "🚀",
    "fintech":     "💳",
    "healthcare":  "🏥",
    "enterprise":  "🏢",
    "post_breach": "🔥",
}


# ─────────────────────────────────────────────
# COMPLIANCE MAPPING
# Maps finding title keywords → compliance violations.
# Used to show ONLY violations that are actually triggered
# by the current audit findings rather than hardcoding all 6.
# ─────────────────────────────────────────────
COMPLIANCE_MAP = [
    {
        "trigger_keywords": ["Encrypt", "Not Encrypted"],
        "standard": "GDPR",
        "ref":      "Article 32",
        "desc":     "Encryption of personal data at rest is required",
    },
    {
        "trigger_keywords": ["Encrypt", "Not Encrypted"],
        "standard": "PCI-DSS",
        "ref":      "Req 3.4",
        "desc":     "Payment card data must be encrypted",
    },
    {
        "trigger_keywords": ["MFA"],
        "standard": "NIST 800-53",
        "ref":      "IA-2",
        "desc":     "Multi-factor authentication is mandatory for all users",
    },
    {
        "trigger_keywords": ["MFA"],
        "standard": "ISO 27001",
        "ref":      "A.9.4",
        "desc":     "Strong authentication mechanisms are required",
    },
    {
        "trigger_keywords": ["Publicly Accessible", "Public"],
        "standard": "HIPAA",
        "ref":      "§164.312",
        "desc":     "PHI must not be publicly accessible",
    },
    {
        "trigger_keywords": ["Logging"],
        "standard": "SOC 2",
        "ref":      "CC7.2",
        "desc":     "Audit logging and monitoring are required",
    },
    {
        "trigger_keywords": ["Inactive User", "Inactive"],
        "standard": "ISO 27001",
        "ref":      "A.9.2.6",
        "desc":     "Access rights of inactive users must be removed or disabled",
    },
    {
        "trigger_keywords": ["Access Key Not Rotated", "Key"],
        "standard": "NIST 800-53",
        "ref":      "IA-5",
        "desc":     "Authenticator management — credentials must be rotated regularly",
    },
    {
        "trigger_keywords": ["Deletion Protection"],
        "standard": "SOC 2",
        "ref":      "A1.2",
        "desc":     "Environmental protections must prevent accidental data destruction",
    },
    {
        "trigger_keywords": ["Multi-AZ"],
        "standard": "SOC 2",
        "ref":      "A1.1",
        "desc":     "Availability commitments require redundant infrastructure",
    },
]


def get_triggered_violations(findings: list) -> list:
    """
    Return only the compliance violations that are actually
    triggered by the current set of findings.
    No more hardcoded ❌ for everything.
    """
    titles    = [f.title for f in findings]
    triggered = []
    seen      = set()

    for rule in COMPLIANCE_MAP:
        key = f"{rule['standard']}_{rule['ref']}"
        if key in seen:
            continue
        if any(
            any(kw in title for title in titles)
            for kw in rule["trigger_keywords"]
        ):
            triggered.append(rule)
            seen.add(key)

    return triggered


# ─────────────────────────────────────────────
# RISK LEVEL HELPERS
# Thresholds match security_agent.py: 75 / 50 / 25
# ─────────────────────────────────────────────

def risk_color(score: float) -> str:
    if score >= 75: return "#ff4b4b"
    if score >= 50: return "#ffa500"
    if score >= 25: return "#ffd700"
    return "#00cc00"

def risk_label(score: float) -> str:
    if score >= 75: return "CRITICAL RISK 🔴"
    if score >= 50: return "HIGH RISK 🟠"
    if score >= 25: return "MEDIUM RISK 🟡"
    return "LOW RISK 🟢"


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Cloud Auditor")
    st.markdown("---")

    st.markdown("### 🎭 Select Scenario")
    selected_scenario = st.selectbox(
        label       = "Company Profile:",
        options     = list(SCENARIOS.keys()),
        format_func = lambda k: SCENARIOS[k],
        index       = 0,
        help        = "Each scenario simulates a different company with unique misconfiguration patterns."
    )

    st.markdown(
        f"<div class='scenario-badge'>{SCENARIO_DESCRIPTIONS[selected_scenario]}</div>",
        unsafe_allow_html=True
    )

    st.divider()
    run_audit = st.button("🔍 Run Security Audit", type="primary", use_container_width=True)

    st.divider()
    st.markdown("### 📋 About")
    st.markdown("""
    This tool audits cloud infrastructure
    configurations and detects security
    misconfigurations using AI-powered
    analysis.

    **Rules Engine:** CIS Benchmarks
    **Standards:** NIST, GDPR, HIPAA
    **Resources Scanned:**
    - S3 Buckets
    - IAM Users
    - Security Groups
    - RDS Databases
    """)


# ─────────────────────────────────────────────
# MAIN CONTENT
# ─────────────────────────────────────────────
if run_audit:

    # ── RUN THE FULL PIPELINE ─────────────────
    with st.spinner("🔍 Fetching cloud configurations..."):
        configs = get_scenario_configs(selected_scenario)

    st.info(
        f"**Scenario:** {SCENARIOS[selected_scenario]} — "
        f"{SCENARIO_DESCRIPTIONS[selected_scenario]}"
    )

    with st.spinner("⚙️ Running security checks..."):
        engine   = AuditEngine()
        findings = engine.run_full_audit(configs)

    with st.spinner("🤖 Running AI analysis..."):
        agent  = SecurityAgent()
        result = agent.analyze(findings, configs)

    with st.spinner("🔮 Running predictive analysis..."):
        predictor    = MisconfigurationPredictor()
        predictions  = predictor.predict(configs)
        pred_summary = build_prediction_summary(predictions)

    summary = result["summary"]
    score   = summary["risk_score"]

    st.success(
        f"✅ Audit Complete! "
        f"Found **{summary['total']} issues** across "
        f"**{summary['total_resources']} resources** + "
        f"**{pred_summary['total']} future predictions**."
    )

    # ── RISK SCORE GAUGE ─────────────────────
    st.markdown("### 📊 Overall Risk Score")
    col_gauge, col_metrics = st.columns([1, 1])

    with col_gauge:
        fig_gauge = go.Figure(go.Indicator(
            mode  = "gauge+number",
            value = score,
            title = {
                "text": f"Risk Score — {risk_label(score)}",
                "font": {"size": 16}
            },
            gauge = {
                "axis": {"range": [0, 100]},
                "bar":  {"color": risk_color(score)},
                # Zones now match security_agent.py thresholds: 25 / 50 / 75
                "steps": [
                    {"range": [0,  25],  "color": "#003d00"},
                    {"range": [25, 50],  "color": "#3d3500"},
                    {"range": [50, 75],  "color": "#3d2000"},
                    {"range": [75, 100], "color": "#3d0000"},
                ],
                "threshold": {
                    "line":      {"color": "white", "width": 4},
                    "thickness": 0.75,
                    "value":     score,
                }
            }
        ))
        fig_gauge.update_layout(
            height        = 300,
            paper_bgcolor = "#0e1117",
            font_color    = "white"
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        # Severity + Coverage subscores below the gauge
        sub1, sub2 = st.columns(2)
        sub1.metric(
            "📐 Severity Score",
            f"{summary['severity_score']}/100",
            help="Weighted density of findings. 100 = all findings are CRITICAL."
        )
        sub2.metric(
            "📡 Coverage Score",
            f"{summary['coverage_score']}/100",
            help=f"Fraction of scanned resources affected. "
                 f"{summary.get('total_resources', '?')} resources total."
        )

    with col_metrics:
        st.markdown("### 🔢 Findings Breakdown")
        m1, m2 = st.columns(2)
        m3, m4 = st.columns(2)

        m1.metric("🔴 Critical", summary["critical"])
        m2.metric("🟠 High",     summary["high"])
        m3.metric("🟡 Medium",   summary["medium"])
        m4.metric("🟢 Low",      summary["low"])

        st.markdown(f"""
        | Severity    | Count |
        |-------------|-------|
        | 🔴 Critical | {summary['critical']} |
        | 🟠 High     | {summary['high']} |
        | 🟡 Medium   | {summary['medium']} |
        | 🟢 Low      | {summary['low']} |
        | **Total**   | **{summary['total']}** |
        | **Resources scanned** | **{summary.get('total_resources', '?')}** |
        """)

    st.divider()

    # ── PIE CHART + BAR CHART ─────────────────
    col_pie, col_bar = st.columns(2)

    with col_pie:
        st.markdown("### 🥧 Issues by Severity")
        fig_pie = px.pie(
            values                  = [summary["critical"], summary["high"],
                                       summary["medium"],   summary["low"]],
            names                   = ["Critical", "High", "Medium", "Low"],
            color_discrete_sequence = ["#ff4b4b", "#ffa500", "#ffd700", "#00cc00"],
            hole                    = 0.4,
        )
        fig_pie.update_layout(
            paper_bgcolor = "#0e1117",
            font_color    = "white",
            height        = 350,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_bar:
        st.markdown("### 📦 Issues by Resource Type")
        resource_counts = {}
        for f in findings:
            resource_counts[f.resource_type] = resource_counts.get(f.resource_type, 0) + 1

        fig_bar = px.bar(
            x      = list(resource_counts.keys()),
            y      = list(resource_counts.values()),
            color  = list(resource_counts.values()),
            color_continuous_scale = "reds",
            labels = {"x": "Resource Type", "y": "Number of Issues"},
        )
        fig_bar.update_layout(
            paper_bgcolor = "#0e1117",
            plot_bgcolor  = "#1e2130",
            font_color    = "white",
            height        = 350,
            showlegend    = False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    st.divider()

    # ── FINDINGS TABLE ────────────────────────
    st.markdown("### 🔍 Detailed Findings")

    severity_filter = st.multiselect(
        "Filter by Severity:",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default = ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )

    filtered = [f for f in findings if f.severity in severity_filter]

    if filtered:
        df = pd.DataFrame([{
            "Severity":       f.severity,
            "Rule ID":        f.rule_id,
            "Resource Type":  f.resource_type,
            "Resource Name":  f.resource_name,
            "Issue":          f.title,
            "Recommendation": f.recommendation,
        } for f in filtered])

        def color_severity(val):
            return {
                "CRITICAL": "background-color: #3d0000; color: #ff4b4b",
                "HIGH":     "background-color: #3d2000; color: #ffa500",
                "MEDIUM":   "background-color: #3d3500; color: #ffd700",
                "LOW":      "background-color: #003d00; color: #00cc00",
            }.get(val, "")

        st.dataframe(
            df.style.map(color_severity, subset=["Severity"]),
            use_container_width = True,
            height              = 400,
        )
    else:
        st.info("No findings match the selected severity filter.")

    st.divider()

    # ── AI REPORT ─────────────────────────────
    st.markdown("### 🤖 AI Security Analysis Report")

    tab1, tab2, tab3 = st.tabs(["📋 Full Report", "🎯 Action Plan", "⚖️ Compliance"])

    with tab1:
        st.code(result["ai_report"], language=None)

    with tab2:
        st.markdown("#### 🎯 Top 10 Priority Actions")
        SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        for item in result["action_plan"]:
            emoji = SEVERITY_EMOJI.get(item["severity"], "⚪")
            with st.expander(
                f"{emoji} [{item['priority']}] {item['resource']} — {item['issue']}"
            ):
                st.markdown(f"**Severity:** `{item['severity']}`")
                st.markdown(f"**Resource:** `{item['resource']}`")
                st.markdown(f"**Issue:** {item['issue']}")
                st.markdown(f"**Fix:** {item['fix']}")

    with tab3:
        st.markdown("#### ⚖️ Compliance Violations Detected")
        st.markdown(
            "*Only showing standards violated by findings in this audit.*"
        )

        triggered = get_triggered_violations(findings)

        if triggered:
            for rule in triggered:
                st.markdown(
                    f"❌ **{rule['standard']}** `{rule['ref']}` — {rule['desc']}"
                )
        else:
            st.success("✅ No compliance violations detected in this audit.")

        st.markdown("---")
        st.markdown(
            f"**{len(triggered)} of {len(COMPLIANCE_MAP)} "
            "tracked standards violated** in this scenario."
        )

    st.divider()

    # ── PREDICTIVE ANALYSIS ───────────────────
    st.markdown("### 🔮 Predictive Misconfiguration Analysis")
    st.markdown("*Forecasting future security violations based on current configuration trends*")

    pc1, pc2, pc3, pc4, pc5 = st.columns(5)
    pc1.metric("🔮 Total Predictions", pred_summary["total"])
    pc2.metric("🔴 Critical",          pred_summary["critical"])
    pc3.metric("🟠 High",              pred_summary["high"])
    pc4.metric("🟡 Medium",            pred_summary["medium"])
    pc5.metric("⚡ Soonest Issue",     f"{pred_summary['soonest_days']} days")

    st.markdown(f"""
    > ⚠️ **Next predicted violation in {pred_summary['soonest_days']} days:**
    > {pred_summary['soonest_issue']}
    """)

    if predictions:
        pred_df = pd.DataFrame([p.to_dict() for p in predictions])

        fig_pred = px.bar(
            pred_df,
            x          = "resource_name",
            y          = "days_until",
            color      = "urgency",
            hover_data = ["prediction_type", "risk_probability", "predicted_date"],
            color_discrete_map = {
                "CRITICAL": "#ff4b4b",
                "HIGH":     "#ffa500",
                "MEDIUM":   "#ffd700",
                "LOW":      "#00cc00",
            },
            labels = {
                "resource_name": "Resource",
                "days_until":    "Days Until Violation",
                "urgency":       "Urgency",
            },
            title = "⏰ Predicted Violations Timeline — Days Until Issue",
        )
        fig_pred.update_layout(
            paper_bgcolor   = "#0e1117",
            plot_bgcolor    = "#1e2130",
            font_color      = "white",
            height          = 420,
            xaxis_tickangle = -45,
        )
        st.plotly_chart(fig_pred, use_container_width=True)

    st.markdown("#### 📋 Detailed Predictions")

    urgency_filter = st.multiselect(
        "Filter Predictions by Urgency:",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default = ["CRITICAL", "HIGH", "MEDIUM"],
        key     = "pred_filter",
    )

    filtered_preds = [p for p in predictions if p.urgency in urgency_filter]

    if filtered_preds:
        pred_table = pd.DataFrame([{
            "Urgency":          p.urgency,
            "Resource":         p.resource_name,
            "Prediction Type":  p.prediction_type,
            "Days Until Issue": p.days_until,
            "Predicted Date":   p.predicted_date,
            "Risk %":           f"{p.risk_probability}%",
            "Recommendation":   p.recommendation,
        } for p in filtered_preds])

        def color_urgency(val):
            return {
                "CRITICAL": "background-color: #3d0000; color: #ff4b4b",
                "HIGH":     "background-color: #3d2000; color: #ffa500",
                "MEDIUM":   "background-color: #3d3500; color: #ffd700",
                "LOW":      "background-color: #003d00; color: #00cc00",
            }.get(val, "")

        st.dataframe(
            pred_table.style.map(color_urgency, subset=["Urgency"]),
            use_container_width = True,
            height              = 350,
        )
    else:
        st.info("No predictions match the selected urgency filter.")

    # ── RUN AGAIN ─────────────────────────────
    st.divider()
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🔄 Run Audit Again", type="secondary", use_container_width=True):
            st.rerun()

else:
    # ── WELCOME SCREEN ────────────────────────
    st.markdown("""
    <div style='text-align:center; padding: 60px 0;'>
        <div style='font-size:5rem;'>🛡️</div>
        <h2 style='color:#00d4ff;'>Welcome to Cloud Security Auditor</h2>
        <p style='color:#888; font-size:1.1rem;'>
            Select a <b>company scenario</b> from the sidebar, then click
            <b>"Run Security Audit"</b> to begin scanning.
        </p>
        <br>
        <p style='color:#555;'>
            Powered by CIS Benchmarks • NIST 800-53 • GDPR • HIPAA • SOC 2
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🎭 Available Scenarios")
    cols = st.columns(len(SCENARIOS))
    for col, (key, label) in zip(cols, SCENARIOS.items()):
        with col:
            st.markdown(f"""
            <div style='background:#1e2130; border:1px solid #2d3250;
                        border-radius:10px; padding:16px; text-align:center; height:140px;'>
                <div style='font-size:2rem;'>{SCENARIO_ICONS[key]}</div>
                <div style='color:#00d4ff; font-weight:bold; font-size:0.85rem;
                            margin-top:8px;'>{label}</div>
                <div style='color:#666; font-size:0.75rem; margin-top:6px;'>
                    {SCENARIO_DESCRIPTIONS[key][:60]}...
                </div>
            </div>
            """, unsafe_allow_html=True)