# src/auditor/audit_engine.py
# Security Audit Engine
# Checks all cloud configs against CIS-inspired security rules
# and produces a structured list of findings with severity levels.

from datetime import datetime


# ─────────────────────────────────────────────
# SEVERITY LEVELS
# ─────────────────────────────────────────────
CRITICAL = "CRITICAL"   # Must fix immediately — active exploit risk
HIGH     = "HIGH"       # Fix within 24–72 hours
MEDIUM   = "MEDIUM"     # Fix within the sprint
LOW      = "LOW"        # Good hygiene, fix when possible


# ─────────────────────────────────────────────
# FINDING
# ─────────────────────────────────────────────

class Finding:
    """
    Represents a single security finding produced by a rule check.

    Attributes
    ----------
    resource_type   : e.g. "S3 Bucket", "IAM User"
    resource_name   : e.g. "prod-uploads", "founder-cto"
    rule_id         : e.g. "S3-001"  — stable identifier for this rule
    title           : short human-readable name of the issue
    description     : full explanation of what is wrong and why it matters
    severity        : CRITICAL / HIGH / MEDIUM / LOW
    recommendation  : concrete remediation step
    timestamp       : ISO-8601 time the finding was generated
    """

    def __init__(self, resource_type, resource_name, rule_id,
                 title, description, severity, recommendation):
        self.resource_type  = resource_type
        self.resource_name  = resource_name
        self.rule_id        = rule_id
        self.title          = title
        self.description    = description
        self.severity       = severity
        self.recommendation = recommendation
        self.timestamp      = datetime.now().isoformat()

    def to_dict(self):
        return {
            "resource_type":  self.resource_type,
            "resource_name":  self.resource_name,
            "rule_id":        self.rule_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity,
            "recommendation": self.recommendation,
            "timestamp":      self.timestamp,
        }

    def __repr__(self):
        return f"<Finding [{self.severity}] {self.rule_id} — {self.resource_name}: {self.title}>"


# ─────────────────────────────────────────────
# AUDIT ENGINE
# ─────────────────────────────────────────────

class AuditEngine:
    """
    Runs all security rule checks across every resource type
    and collects findings into a single list.

    Usage
    -----
        engine   = AuditEngine()
        findings = engine.run_full_audit(configs)

    Safe to reuse: call reset() between audits if you want
    to reuse the same engine instance.
    """

    # Dangerous ports: port → (service_name, severity)
    DANGEROUS_PORTS = {
        22:    ("SSH",        CRITICAL),
        3389:  ("RDP",        CRITICAL),
        3306:  ("MySQL",      CRITICAL),
        5432:  ("PostgreSQL", CRITICAL),
        27017: ("MongoDB",    CRITICAL),
        23:    ("Telnet",     HIGH),
        21:    ("FTP",        HIGH),
        8080:  ("HTTP-Alt",   MEDIUM),    # ← NEW: dev server exposed
        6379:  ("Redis",      CRITICAL),  # ← NEW: Redis open to internet
        9200:  ("Elasticsearch", CRITICAL), # ← NEW: ES open to internet
    }

    def __init__(self):
        self.findings = []
        self._ran     = False   # guard against accidental double-runs

    def reset(self):
        """Clear findings so the engine can be reused for a new audit."""
        self.findings = []
        self._ran     = False

    # ─────────────────────────────────────────
    # MAIN ENTRY
    # ─────────────────────────────────────────

    def run_full_audit(self, configs: dict) -> list:
        """
        Run all checks on all resources in configs.

        Returns the full list of Finding objects.
        Raises RuntimeError if called twice without reset().
        """
        if self._ran:
            raise RuntimeError(
                "AuditEngine.run_full_audit() called twice on the same instance. "
                "Call engine.reset() first, or create a new AuditEngine()."
            )

        self._ran = True
        print("\n🔍 Starting Security Audit...\n")

        self._audit_s3_buckets(configs["s3_buckets"])
        self._audit_iam_users(configs["iam_users"])
        self._audit_security_groups(configs["security_groups"])
        self._audit_rds_instances(configs["rds_instances"])

        # ── Print per-type summary ──────────────────────────────────
        from collections import Counter
        by_type = Counter(f.resource_type for f in self.findings)
        print(f"✅ Audit complete! Found {len(self.findings)} issues:\n")
        for rtype, count in sorted(by_type.items()):
            print(f"   {rtype:<20} {count} finding(s)")
        print()

        return self.findings

    # ─────────────────────────────────────────
    # INTERNAL HELPER
    # ─────────────────────────────────────────

    def _add(self, **kwargs):
        """Convenience wrapper — creates and appends a Finding."""
        self.findings.append(Finding(**kwargs))

    # ─────────────────────────────────────────
    # S3 BUCKET CHECKS
    # ─────────────────────────────────────────

    def _audit_s3_buckets(self, buckets: list):
        print("  📦 Checking S3 Buckets...")

        for bucket in buckets:
            name = bucket["name"]

            # S3-001 — Public access (CRITICAL)
            if bucket.get("public_access"):
                self._add(
                    resource_type  = "S3 Bucket",
                    resource_name  = name,
                    rule_id        = "S3-001",
                    title          = "S3 Bucket is Publicly Accessible",
                    description    = (
                        f"Bucket '{name}' is open to the public internet. "
                        "Anyone with the URL can read, list, or download its contents "
                        "without any authentication."
                    ),
                    severity       = CRITICAL,
                    recommendation = "Enable 'Block all public access' in S3 bucket settings immediately."
                )

            # S3-002 — Encryption at rest (HIGH)
            if not bucket.get("encryption"):
                self._add(
                    resource_type  = "S3 Bucket",
                    resource_name  = name,
                    rule_id        = "S3-002",
                    title          = "S3 Bucket Not Encrypted",
                    description    = (
                        f"Bucket '{name}' stores data without server-side encryption. "
                        "If an attacker gains access to the underlying storage, "
                        "all data is immediately readable."
                    ),
                    severity       = HIGH,
                    recommendation = "Enable AES-256 (SSE-S3) or AWS KMS encryption on the bucket."
                )

            # S3-003 — Versioning (MEDIUM)
            if not bucket.get("versioning"):
                self._add(
                    resource_type  = "S3 Bucket",
                    resource_name  = name,
                    rule_id        = "S3-003",
                    title          = "S3 Bucket Versioning Disabled",
                    description    = (
                        f"Bucket '{name}' has no versioning enabled. "
                        "Accidental deletions or overwrites are permanent "
                        "and cannot be recovered."
                    ),
                    severity       = MEDIUM,
                    recommendation = "Enable S3 versioning to allow recovery of deleted or overwritten objects."
                )

            # S3-004 — Access logging (LOW)
            if not bucket.get("logging"):
                self._add(
                    resource_type  = "S3 Bucket",
                    resource_name  = name,
                    rule_id        = "S3-004",
                    title          = "S3 Bucket Access Logging Disabled",
                    description    = (
                        f"Bucket '{name}' has no server access logging. "
                        "Without logs, there is no audit trail of who accessed, "
                        "modified, or deleted data — required by SOC 2 and HIPAA."
                    ),
                    severity       = LOW,
                    recommendation = "Enable S3 server access logging, directing logs to a separate audit bucket."
                )

    # ─────────────────────────────────────────
    # IAM USER CHECKS
    # ─────────────────────────────────────────

    def _audit_iam_users(self, users: list):
        print("  👤 Checking IAM Users...")

        for user in users:
            name     = user["username"]
            key_age  = user.get("access_key_age_days", 0)
            login    = user.get("last_login_days", 0)
            pw_age   = user.get("password_age_days", 0)

            # IAM-001 — MFA not enabled (CRITICAL)
            if not user.get("mfa_enabled"):
                self._add(
                    resource_type  = "IAM User",
                    resource_name  = name,
                    rule_id        = "IAM-001",
                    title          = "MFA Not Enabled",
                    description    = (
                        f"User '{name}' has no Multi-Factor Authentication. "
                        "A stolen or guessed password alone is sufficient to "
                        "fully compromise this account."
                    ),
                    severity       = CRITICAL,
                    recommendation = "Enable MFA (virtual or hardware token) immediately for this user."
                )

            # IAM-002 — Admin policy (HIGH)
            if user.get("has_admin_policy"):
                self._add(
                    resource_type  = "IAM User",
                    resource_name  = name,
                    rule_id        = "IAM-002",
                    title          = "User Has Full Admin Access",
                    description    = (
                        f"User '{name}' has the AdministratorAccess policy attached. "
                        "This gives unrestricted access to every AWS service and resource, "
                        "violating the principle of least privilege."
                    ),
                    severity       = HIGH,
                    recommendation = "Replace AdministratorAccess with scoped, role-specific IAM policies."
                )

            # IAM-003 — Stale access key (HIGH)
            if key_age > 90:
                self._add(
                    resource_type  = "IAM User",
                    resource_name  = name,
                    rule_id        = "IAM-003",
                    title          = "Access Key Not Rotated",
                    description    = (
                        f"User '{name}' has an access key that is {key_age} days old "
                        f"(policy requires rotation every 90 days). "
                        "Long-lived keys are high-value targets and are frequently "
                        "leaked accidentally in code repositories."
                    ),
                    severity       = HIGH,
                    recommendation = "Rotate this access key immediately and enforce 90-day rotation policy."
                )

            # IAM-004 — Inactive account (MEDIUM)
            if login > 60:
                self._add(
                    resource_type  = "IAM User",
                    resource_name  = name,
                    rule_id        = "IAM-004",
                    title          = "Inactive User Account",
                    description    = (
                        f"User '{name}' has not logged in for {login} days. "
                        "Dormant accounts with active credentials are a silent "
                        "entry point for attackers — especially ex-employees."
                    ),
                    severity       = MEDIUM,
                    recommendation = "Disable or delete this account. If needed, reactivate with new credentials."
                )

            # IAM-005 — Stale password (MEDIUM)  ← NEW RULE
            if pw_age > 90:
                self._add(
                    resource_type  = "IAM User",
                    resource_name  = name,
                    rule_id        = "IAM-005",
                    title          = "Password Exceeds 90-Day Policy",
                    description    = (
                        f"User '{name}' has a password that is {pw_age} days old. "
                        "Passwords older than 90 days increase the window of exposure "
                        "if credentials were ever silently compromised."
                    ),
                    severity       = MEDIUM,
                    recommendation = "Force a password reset for this user and enforce a 90-day password policy."
                )

    # ─────────────────────────────────────────
    # SECURITY GROUP CHECKS
    # ─────────────────────────────────────────

    def _audit_security_groups(self, groups: list):
        print("  🔒 Checking Security Groups...")

        for group in groups:
            name = group["name"]

            for rule in group.get("inbound_rules", []):
                port   = rule["port"]
                source = rule["source"]

                # SG-001 — Dangerous port open to internet
                if source in ("0.0.0.0/0", "::/0") and port in self.DANGEROUS_PORTS:
                    service, severity = self.DANGEROUS_PORTS[port]
                    self._add(
                        resource_type  = "Security Group",
                        resource_name  = name,
                        rule_id        = "SG-001",
                        title          = f"{service} Port Open to Internet",
                        description    = (
                            f"Security group '{name}' allows inbound {service} "
                            f"(port {port}) from ANY IP address (0.0.0.0/0). "
                            "Automated scanners find and attack these within minutes of exposure."
                        ),
                        severity       = severity,
                        recommendation = (
                            f"Remove the 0.0.0.0/0 rule for port {port}. "
                            "Restrict to specific trusted CIDR ranges or use a VPN/bastion host."
                        )
                    )

    # ─────────────────────────────────────────
    # RDS INSTANCE CHECKS
    # ─────────────────────────────────────────

    def _audit_rds_instances(self, instances: list):
        print("  🗄️  Checking RDS Databases...")

        for db in instances:
            name = db["name"]

            # RDS-001 — Publicly accessible (CRITICAL)
            if db.get("publicly_accessible"):
                self._add(
                    resource_type  = "RDS Instance",
                    resource_name  = name,
                    rule_id        = "RDS-001",
                    title          = "Database Publicly Accessible",
                    description    = (
                        f"RDS instance '{name}' has a public endpoint reachable "
                        "from the internet. Databases should never be directly exposed — "
                        "applications should connect via private subnets only."
                    ),
                    severity       = CRITICAL,
                    recommendation = "Disable 'Publicly Accessible' and move the instance into a private VPC subnet."
                )

            # RDS-002 — Encryption at rest (HIGH)
            if not db.get("encrypted"):
                self._add(
                    resource_type  = "RDS Instance",
                    resource_name  = name,
                    rule_id        = "RDS-002",
                    title          = "Database Not Encrypted",
                    description    = (
                        f"RDS instance '{name}' stores data without encryption at rest. "
                        "Snapshots, automated backups, and read replicas will also be unencrypted, "
                        "violating GDPR, HIPAA, and PCI-DSS requirements."
                    ),
                    severity       = HIGH,
                    recommendation = "Enable encryption at rest via AWS KMS. Note: requires snapshot restore for existing instances."
                )

            # RDS-003 — Backups disabled (HIGH)
            if not db.get("backup_enabled"):
                self._add(
                    resource_type  = "RDS Instance",
                    resource_name  = name,
                    rule_id        = "RDS-003",
                    title          = "Database Backups Disabled",
                    description    = (
                        f"RDS instance '{name}' has automated backups turned off. "
                        "Any data corruption, accidental deletion, or ransomware attack "
                        "would result in permanent, unrecoverable data loss."
                    ),
                    severity       = HIGH,
                    recommendation = "Enable automated backups with a minimum 7-day retention period."
                )

            # RDS-004 — Deletion protection off (MEDIUM)
            if not db.get("deletion_protection"):
                self._add(
                    resource_type  = "RDS Instance",
                    resource_name  = name,
                    rule_id        = "RDS-004",
                    title          = "Deletion Protection Disabled",
                    description    = (
                        f"RDS instance '{name}' can be permanently deleted with a single API call. "
                        "Without deletion protection, a misconfigured script or malicious actor "
                        "can destroy the database and all its data instantly."
                    ),
                    severity       = MEDIUM,
                    recommendation = "Enable deletion protection on all non-temporary RDS instances."
                )

            # RDS-005 — No Multi-AZ (LOW)  ← NEW RULE
            if not db.get("multi_az"):
                self._add(
                    resource_type  = "RDS Instance",
                    resource_name  = name,
                    rule_id        = "RDS-005",
                    title          = "Multi-AZ Not Enabled",
                    description    = (
                        f"RDS instance '{name}' runs in a single Availability Zone. "
                        "An AZ outage or hardware failure will cause downtime with no automatic failover."
                    ),
                    severity       = LOW,
                    recommendation = "Enable Multi-AZ deployment for automatic failover and high availability."
                )