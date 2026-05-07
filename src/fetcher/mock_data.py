# src/fetcher/mock_data.py
# Scenario-based AWS configuration simulator
# Each scenario represents a different company profile with realistic misconfigurations

from datetime import datetime


SCENARIOS = {
    "startup":     "Startup (Lean & Fast)",
    "fintech":     "FinTech (Compliance Risk)",
    "healthcare":  "Healthcare (HIPAA Exposure)",
    "enterprise":  "Enterprise (Legacy Debt)",
    "post_breach": "Post-Breach (Actively Compromised)",
}


def get_scenario_configs(scenario: str) -> dict:
    """
    Master dispatcher — returns AWS configs for the selected scenario.
    scenario must be one of the keys in SCENARIOS.
    """
    generators = {
        "startup":     generate_startup_configs,
        "fintech":     generate_fintech_configs,
        "healthcare":  generate_healthcare_configs,
        "enterprise":  generate_enterprise_configs,
        "post_breach": generate_post_breach_configs,
    }
    fn = generators.get(scenario, generate_startup_configs)
    return fn()


# ─────────────────────────────────────────────────────────────────
# SCENARIO 1 — STARTUP
# Profile: Moving fast, skipping security basics, dev=prod mindset
# Expected: ~18 findings, mostly MEDIUM/HIGH
# ─────────────────────────────────────────────────────────────────

def generate_startup_configs() -> dict:
    return {
        "account_id": "111111111111",
        "region": "us-east-1",
        "scan_time": datetime.now().isoformat(),
        "scenario": "startup",
        "s3_buckets": [
            {
                "name": "startup-user-uploads",
                "public_access": True,      # ❌ dev left it open
                "versioning": False,        # ❌ not configured
                "encryption": False,        # ❌ skipped
                "logging": False,           # ❌ skipped
                "region": "us-east-1"
            },
            {
                "name": "startup-code-artifacts",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": True,         # ✅
                "logging": False,           # ❌ nobody set it up
                "region": "us-east-1"
            },
            {
                "name": "startup-staging-data",
                "public_access": True,      # ❌ staging treated like dev
                "versioning": False,        # ❌
                "encryption": False,        # ❌
                "logging": False,           # ❌
                "region": "us-west-2"
            },
            {
                "name": "startup-analytics",
                "public_access": False,     # ✅
                "versioning": False,        # ❌ never prioritized
                "encryption": True,         # ✅
                "logging": True,            # ✅
                "region": "us-east-1"
            },
        ],
        "iam_users": [
            {
                "username": "founder-cto",
                "mfa_enabled": False,           # ❌ "too annoying"
                "has_admin_policy": True,       # ❌ does everything himself
                "access_key_age_days": 400,     # ❌ set it once, forgot
                "last_login_days": 1,
                "password_age_days": 400
            },
            {
                "username": "dev-alice",
                "mfa_enabled": False,           # ❌
                "has_admin_policy": True,       # ❌ everyone gets admin
                "access_key_age_days": 50,      # ✅ recently onboarded
                "last_login_days": 1,
                "password_age_days": 50
            },
            {
                "username": "dev-bob",
                "mfa_enabled": True,            # ✅ bob reads security blogs
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 45,      # ✅
                "last_login_days": 2,
                "password_age_days": 45
            },
            {
                "username": "ci-service-account",
                "mfa_enabled": False,           # ⚠️ service account
                "has_admin_policy": True,       # ❌ CI pipeline needs "everything"
                "access_key_age_days": 200,     # ❌ set during initial setup
                "last_login_days": 0,
                "password_age_days": 200
            },
        ],
        "security_groups": [
            {
                "name": "all-open-sg",
                "id": "sg-s01",
                "inbound_rules": [
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ SSH open to world
                    {"port": 3306, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ MySQL open to world
                    {"port": 80,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                ]
            },
            {
                "name": "dev-machine-sg",
                "id": "sg-s02",
                "inbound_rules": [
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌
                    {"port": 8080, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ dev server exposed
                ]
            },
            {
                "name": "prod-api-sg",
                "id": "sg-s03",
                "inbound_rules": [
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 80,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                ]
            },
        ],
        "rds_instances": [
            {
                "name": "startup-prod-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": False,             # ❌ never enabled
                "backup_enabled": True,         # ✅
                "multi_az": False,              # acceptable for startup
                "deletion_protection": False    # ❌
            },
            {
                "name": "startup-dev-db",
                "engine": "postgres",
                "publicly_accessible": True,    # ❌ dev connects directly
                "encrypted": False,             # ❌
                "backup_enabled": False,        # ❌ "it's just dev"
                "multi_az": False,
                "deletion_protection": False    # ❌
            },
            {
                "name": "startup-analytics-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": False,
                "deletion_protection": True     # ✅
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────
# SCENARIO 2 — FINTECH
# Profile: Handles payments, partially compliant, audit incoming
# Expected: ~22 findings, heavy CRITICAL (PCI-DSS violations)
# ─────────────────────────────────────────────────────────────────

def generate_fintech_configs() -> dict:
    return {
        "account_id": "222222222222",
        "region": "us-east-1",
        "scan_time": datetime.now().isoformat(),
        "scenario": "fintech",
        "s3_buckets": [
            {
                "name": "fintech-transaction-logs",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": False,        # ❌ CRITICAL — payment logs unencrypted
                "logging": True,            # ✅
                "region": "us-east-1"
            },
            {
                "name": "fintech-user-kyc-docs",
                "public_access": True,      # ❌ CRITICAL — KYC docs publicly accessible!
                "versioning": False,        # ❌
                "encryption": False,        # ❌ CRITICAL
                "logging": False,           # ❌
                "region": "us-east-1"
            },
            {
                "name": "fintech-card-data-exports",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": False,        # ❌ CRITICAL — card data!
                "logging": True,            # ✅
                "region": "us-east-1"
            },
            {
                "name": "fintech-reports",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": True,         # ✅
                "logging": True,            # ✅
                "region": "us-east-1"
            },
        ],
        "iam_users": [
            {
                "username": "payment-processor-svc",
                "mfa_enabled": False,           # ⚠️
                "has_admin_policy": True,       # ❌ CRITICAL — service has full admin
                "access_key_age_days": 500,     # ❌ key never rotated
                "last_login_days": 0,
                "password_age_days": 500
            },
            {
                "username": "compliance-officer",
                "mfa_enabled": True,            # ✅
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 85,      # ❌ slightly overdue
                "last_login_days": 3,
                "password_age_days": 85
            },
            {
                "username": "finance-analyst",
                "mfa_enabled": False,           # ❌ CRITICAL — accesses card data
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 150,     # ❌
                "last_login_days": 1,
                "password_age_days": 150
            },
            {
                "username": "dev-lead",
                "mfa_enabled": True,            # ✅
                "has_admin_policy": True,       # ❌
                "access_key_age_days": 60,      # ✅
                "last_login_days": 1,
                "password_age_days": 60
            },
        ],
        "security_groups": [
            {
                "name": "payment-gateway-sg",
                "id": "sg-f01",
                "inbound_rules": [
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 3306, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                ]
            },
            {
                "name": "admin-panel-sg",
                "id": "sg-f02",
                "inbound_rules": [
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 3389, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ RDP open!
                ]
            },
            {
                "name": "internal-services-sg",
                "id": "sg-f03",
                "inbound_rules": [
                    {"port": 8080, "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                    {"port": 443,  "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                ]
            },
        ],
        "rds_instances": [
            {
                "name": "fintech-transactions-db",
                "engine": "postgres",
                "publicly_accessible": False,   # ✅
                "encrypted": False,             # ❌ CRITICAL — transaction data
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": True     # ✅
            },
            {
                "name": "fintech-user-accounts-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": False    # ❌
            },
            {
                "name": "fintech-audit-log-db",
                "engine": "postgres",
                "publicly_accessible": False,   # ✅
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": False,
                "deletion_protection": True     # ✅
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────
# SCENARIO 3 — HEALTHCARE
# Profile: Hospital SaaS, stores PHI, HIPAA audit upcoming
# Expected: ~24 findings, very heavy CRITICAL (HIPAA violations)
# ─────────────────────────────────────────────────────────────────

def generate_healthcare_configs() -> dict:
    return {
        "account_id": "333333333333",
        "region": "us-east-1",
        "scan_time": datetime.now().isoformat(),
        "scenario": "healthcare",
        "s3_buckets": [
            {
                "name": "patient-records-bucket",
                "public_access": True,      # ❌ CRITICAL — patient records PUBLIC
                "versioning": False,        # ❌
                "encryption": False,        # ❌ CRITICAL — PHI unencrypted
                "logging": False,           # ❌ CRITICAL — no audit trail
                "region": "us-east-1"
            },
            {
                "name": "medical-imaging-store",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": False,        # ❌ CRITICAL — MRI/CT scans unencrypted
                "logging": True,            # ✅
                "region": "us-east-1"
            },
            {
                "name": "prescription-exports",
                "public_access": True,      # ❌ CRITICAL
                "versioning": False,        # ❌
                "encryption": False,        # ❌
                "logging": False,           # ❌
                "region": "us-west-2"
            },
            {
                "name": "hospital-backups",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": True,         # ✅
                "logging": True,            # ✅
                "region": "us-east-1"
            },
        ],
        "iam_users": [
            {
                "username": "ehr-system-svc",
                "mfa_enabled": False,           # ⚠️
                "has_admin_policy": True,       # ❌ CRITICAL
                "access_key_age_days": 730,     # ❌ 2 years old!
                "last_login_days": 0,
                "password_age_days": 730
            },
            {
                "username": "dr-smith",
                "mfa_enabled": False,           # ❌ CRITICAL — doctor has no MFA
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 200,     # ❌
                "last_login_days": 1,
                "password_age_days": 200
            },
            {
                "username": "nurse-coordinator",
                "mfa_enabled": False,           # ❌
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 120,     # ❌
                "last_login_days": 1,
                "password_age_days": 120
            },
            {
                "username": "it-admin",
                "mfa_enabled": True,            # ✅
                "has_admin_policy": True,       # ❌
                "access_key_age_days": 75,      # ✅
                "last_login_days": 2,
                "password_age_days": 75
            },
        ],
        "security_groups": [
            {
                "name": "ehr-app-sg",
                "id": "sg-h01",
                "inbound_rules": [
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌
                    {"port": 3306, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                ]
            },
            {
                "name": "imaging-server-sg",
                "id": "sg-h02",
                "inbound_rules": [
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                    {"port": 21,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ FTP!
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌
                ]
            },
            {
                "name": "internal-only-sg",
                "id": "sg-h03",
                "inbound_rules": [
                    {"port": 8080, "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                    {"port": 443,  "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                ]
            },
        ],
        "rds_instances": [
            {
                "name": "patient-db",
                "engine": "postgres",
                "publicly_accessible": True,    # ❌ CRITICAL — patient DB on internet
                "encrypted": False,             # ❌ CRITICAL
                "backup_enabled": False,        # ❌ CRITICAL — no backups of patient data
                "multi_az": False,
                "deletion_protection": False    # ❌
            },
            {
                "name": "appointments-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": False,             # ❌
                "backup_enabled": True,         # ✅
                "multi_az": False,
                "deletion_protection": False    # ❌
            },
            {
                "name": "billing-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": True     # ✅
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────
# SCENARIO 4 — ENTERPRISE
# Profile: Large corp, 10+ years old infra, legacy config debt
# Expected: ~20 findings, mix of all severities, old keys/passwords
# ─────────────────────────────────────────────────────────────────

def generate_enterprise_configs() -> dict:
    return {
        "account_id": "444444444444",
        "region": "us-east-1",
        "scan_time": datetime.now().isoformat(),
        "scenario": "enterprise",
        "s3_buckets": [
            {
                "name": "corp-legacy-archive-2015",
                "public_access": False,     # ✅ at least this is private
                "versioning": False,        # ❌ never enabled
                "encryption": False,        # ❌ created before encryption was standard
                "logging": False,           # ❌
                "region": "us-east-1"
            },
            {
                "name": "corp-intranet-assets",
                "public_access": True,      # ❌ was intentional, now forgotten
                "versioning": False,        # ❌
                "encryption": False,        # ❌
                "logging": True,            # ✅ compliance team enabled this
                "region": "us-east-1"
            },
            {
                "name": "corp-hr-documents",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": True,         # ✅
                "logging": True,            # ✅
                "region": "us-east-1"
            },
            {
                "name": "corp-data-warehouse-exports",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": False,        # ❌ export pipeline predates encryption
                "logging": True,            # ✅
                "region": "us-east-1"
            },
        ],
        "iam_users": [
            {
                "username": "legacy-etl-service",
                "mfa_enabled": False,           # ⚠️
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 1200,    # ❌ 3+ year old key
                "last_login_days": 3,
                "password_age_days": 1200
            },
            {
                "username": "ex-employee-mark",
                "mfa_enabled": False,           # ❌
                "has_admin_policy": True,       # ❌ CRITICAL — ex-employee still has admin!
                "access_key_age_days": 800,     # ❌
                "last_login_days": 180,         # ❌ hasn't logged in for 6 months
                "password_age_days": 800
            },
            {
                "username": "svc-erp-integration",
                "mfa_enabled": False,           # ⚠️
                "has_admin_policy": True,       # ❌ ERP needed broad access "temporarily"
                "access_key_age_days": 600,     # ❌
                "last_login_days": 1,
                "password_age_days": 600
            },
            {
                "username": "security-auditor",
                "mfa_enabled": True,            # ✅
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 30,      # ✅
                "last_login_days": 1,
                "password_age_days": 30
            },
        ],
        "security_groups": [
            {
                "name": "legacy-app-sg",
                "id": "sg-e01",
                "inbound_rules": [
                    {"port": 23,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ TELNET!
                    {"port": 21,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ FTP!
                    {"port": 80,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                ]
            },
            {
                "name": "corp-vpn-sg",
                "id": "sg-e02",
                "inbound_rules": [
                    {"port": 22,   "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅ internal only
                    {"port": 443,  "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                ]
            },
            {
                "name": "warehouse-db-sg",
                "id": "sg-e03",
                "inbound_rules": [
                    {"port": 5432, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                    {"port": 27017,"protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ MongoDB!
                ]
            },
        ],
        "rds_instances": [
            {
                "name": "corp-erp-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": False,             # ❌ created in 2014
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": True     # ✅
            },
            {
                "name": "corp-reporting-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": False,
                "deletion_protection": False    # ❌
            },
            {
                "name": "corp-legacy-crm-db",
                "engine": "postgres",
                "publicly_accessible": True,    # ❌ external vendor needs access
                "encrypted": False,             # ❌
                "backup_enabled": False,        # ❌ backup was "migrated" but never verified
                "multi_az": False,
                "deletion_protection": False    # ❌
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────
# SCENARIO 5 — POST-BREACH
# Profile: Company 3 days after a breach, some things locked down,
#          attacker may still have foothold
# Expected: ~26 findings, maximum CRITICAL density
# ─────────────────────────────────────────────────────────────────

def generate_post_breach_configs() -> dict:
    return {
        "account_id": "555555555555",
        "region": "us-east-1",
        "scan_time": datetime.now().isoformat(),
        "scenario": "post_breach",
        "s3_buckets": [
            {
                "name": "breached-customer-data",
                "public_access": True,      # ❌ CRITICAL — attacker exfiltrated via this
                "versioning": False,        # ❌ can't tell what was deleted
                "encryption": False,        # ❌ data was plaintext
                "logging": False,           # ❌ no evidence trail
                "region": "us-east-1"
            },
            {
                "name": "attacker-staging-bucket",
                "public_access": True,      # ❌ CRITICAL — attacker created this
                "versioning": False,        # ❌
                "encryption": False,        # ❌
                "logging": False,           # ❌
                "region": "us-east-1"
            },
            {
                "name": "incident-response-logs",
                "public_access": False,     # ✅ IR team locked this down
                "versioning": True,         # ✅
                "encryption": True,         # ✅
                "logging": True,            # ✅
                "region": "us-east-1"
            },
            {
                "name": "backup-store",
                "public_access": False,     # ✅
                "versioning": True,         # ✅
                "encryption": False,        # ❌ backups unencrypted — attacker read them
                "logging": True,            # ✅
                "region": "us-east-1"
            },
        ],
        "iam_users": [
            {
                "username": "compromised-admin",
                "mfa_enabled": False,           # ❌ CRITICAL — how attacker got in
                "has_admin_policy": True,       # ❌ CRITICAL
                "access_key_age_days": 900,     # ❌ key was leaked
                "last_login_days": 0,           # active right now
                "password_age_days": 900
            },
            {
                "username": "attacker-backdoor-svc",
                "mfa_enabled": False,           # ❌ attacker created this account
                "has_admin_policy": True,       # ❌ CRITICAL — backdoor with full admin
                "access_key_age_days": 3,       # recently created
                "last_login_days": 0,           # actively used
                "password_age_days": 3
            },
            {
                "username": "ir-responder",
                "mfa_enabled": True,            # ✅ IR team
                "has_admin_policy": True,       # necessary for incident response
                "access_key_age_days": 1,       # ✅ just created
                "last_login_days": 0,
                "password_age_days": 1
            },
            {
                "username": "regular-employee",
                "mfa_enabled": False,           # ❌ still not fixed
                "has_admin_policy": False,      # ✅
                "access_key_age_days": 300,     # ❌ potentially compromised
                "last_login_days": 3,
                "password_age_days": 300
            },
        ],
        "security_groups": [
            {
                "name": "compromised-server-sg",
                "id": "sg-p01",
                "inbound_rules": [
                    {"port": 22,   "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                    {"port": 3306, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                    {"port": 5432, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                    {"port": 443,  "protocol": "tcp", "source": "0.0.0.0/0"},  # ✅
                ]
            },
            {
                "name": "attacker-c2-sg",
                "id": "sg-p02",
                "inbound_rules": [
                    {"port": 27017,"protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ C2 channel
                    {"port": 3389, "protocol": "tcp", "source": "0.0.0.0/0"},  # ❌ CRITICAL
                ]
            },
            {
                "name": "isolated-clean-sg",
                "id": "sg-p03",
                "inbound_rules": [
                    {"port": 443,  "protocol": "tcp", "source": "10.0.0.0/8"}, # ✅
                ]
            },
        ],
        "rds_instances": [
            {
                "name": "exfiltrated-customer-db",
                "engine": "postgres",
                "publicly_accessible": True,    # ❌ CRITICAL — how data left
                "encrypted": False,             # ❌ CRITICAL
                "backup_enabled": True,         # ✅
                "multi_az": False,
                "deletion_protection": False    # ❌ attacker could delete evidence
            },
            {
                "name": "prod-db-compromised",
                "engine": "mysql",
                "publicly_accessible": False,   # partially locked down
                "encrypted": False,             # ❌
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": False    # ❌
            },
            {
                "name": "clean-restored-db",
                "engine": "mysql",
                "publicly_accessible": False,   # ✅ IR restored this cleanly
                "encrypted": True,              # ✅
                "backup_enabled": True,         # ✅
                "multi_az": True,               # ✅
                "deletion_protection": True     # ✅
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────
# BACKWARDS COMPATIBILITY
# Keep old function names working so nothing else breaks
# ─────────────────────────────────────────────────────────────────

def generate_mock_aws_configs():
    """Legacy alias — maps to startup scenario."""
    return generate_startup_configs()


def generate_fintech_startup_configs():
    """Legacy alias — maps to fintech scenario."""
    return generate_fintech_configs()