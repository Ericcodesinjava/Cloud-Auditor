# src/ml/predictor.py
# Predictive Misconfiguration Analysis Engine
# Analyzes current config trends and predicts future violations.
# No ML training needed — uses intelligent rule-based trajectory scoring.

from datetime import datetime, timedelta
from collections import Counter


# ─────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────

KEY_ROTATION_DAYS  = 90     # IAM key rotation policy threshold
PASSWORD_AGE_DAYS  = 90     # Password rotation policy threshold
INACTIVITY_DAYS    = 60     # Account inactivity threshold


# ─────────────────────────────────────────────────────
# PREDICTION OBJECT
# ─────────────────────────────────────────────────────

class Prediction:
    """
    Represents a single future risk prediction.

    Attributes
    ----------
    resource_type    : resource category, e.g. "IAM User"
    resource_name    : specific resource, e.g. "founder-cto"
    prediction_type  : short label, e.g. "Access Key Expiry"
    description      : what will happen and why
    days_until       : how many days until the violation occurs
    risk_probability : 0–100 integer representing likelihood
    urgency          : CRITICAL / HIGH / MEDIUM / LOW (derived from days_until)
    predicted_date   : human-readable calendar date of predicted violation
    recommendation   : concrete action to prevent this prediction
    """

    URGENCY_THRESHOLDS = [
        (7,  "CRITICAL"),
        (14, "HIGH"),
        (30, "MEDIUM"),
    ]

    def __init__(self, resource_type, resource_name, prediction_type,
                 description, days_until, risk_probability, recommendation):
        self.resource_type    = resource_type
        self.resource_name    = resource_name
        self.prediction_type  = prediction_type
        self.description      = description
        self.days_until       = max(days_until, 1)   # never 0 or negative
        self.risk_probability = min(max(int(risk_probability), 1), 99)  # clamp 1–99
        self.urgency          = self._get_urgency()
        self.predicted_date   = (
            datetime.now() + timedelta(days=self.days_until)
        ).strftime("%d %b %Y")
        self.recommendation   = recommendation

    def _get_urgency(self) -> str:
        for threshold, label in self.URGENCY_THRESHOLDS:
            if self.days_until <= threshold:
                return label
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "resource_type":    self.resource_type,
            "resource_name":    self.resource_name,
            "prediction_type":  self.prediction_type,
            "description":      self.description,
            "days_until":       self.days_until,
            "risk_probability": self.risk_probability,
            "urgency":          self.urgency,
            "predicted_date":   self.predicted_date,
            "recommendation":   self.recommendation,
        }

    def __repr__(self):
        return (
            f"<Prediction [{self.urgency}] {self.prediction_type} "
            f"— {self.resource_name} in {self.days_until}d ({self.risk_probability}%)>"
        )


# ─────────────────────────────────────────────────────
# HELPER — linear interpolation probability
# ─────────────────────────────────────────────────────

def _trajectory_prob(current: int, threshold: int,
                     min_prob: int = 5, max_prob: int = 95) -> int:
    """
    Calculate probability that a metric will breach its threshold,
    based on how far along the trajectory it currently is.

    Examples:
        key_age=45, threshold=90  → 50%  (halfway to violation)
        key_age=81, threshold=90  → 90%  (90% of the way there)
        key_age=0,  threshold=90  → 5%   (floor, not 0%)
    """
    if threshold <= 0:
        return max_prob
    ratio = current / threshold
    prob  = min_prob + int(ratio * (max_prob - min_prob))
    return min(max(prob, min_prob), max_prob)


# ─────────────────────────────────────────────────────
# MAIN PREDICTOR CLASS
# ─────────────────────────────────────────────────────

class MisconfigurationPredictor:
    """
    Predicts future misconfigurations by analyzing current config
    trends and patterns.

    Each prediction module looks at how close a config is to
    violating a rule and forecasts WHEN it will cross the line.

    Usage
    -----
        predictor   = MisconfigurationPredictor()
        predictions = predictor.predict(configs)

    Safe to reuse: predict() resets internal state on each call.
    """

    def __init__(self):
        self.predictions: list[Prediction] = []

    # ─────────────────────────────────────────
    # MAIN ENTRY
    # ─────────────────────────────────────────

    def predict(self, configs: dict) -> list:
        """
        Run all prediction modules on the provided configs.

        Resets internal state at the start of each call so the
        same predictor instance can be reused safely.

        Returns sorted list of Prediction objects (most urgent first).
        """
        # ── Reset on every call — safe for reuse ──────────────────
        self.predictions = []

        print("\n🔮 Predictive Analysis Engine Starting...\n")

        self._predict_iam(configs["iam_users"])
        self._predict_s3(configs["s3_buckets"])
        self._predict_rds(configs["rds_instances"])
        self._predict_combined_risk(configs)

        # Sort: urgency first, then soonest within same urgency
        urgency_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.predictions.sort(
            key=lambda p: (urgency_order.get(p.urgency, 99), p.days_until)
        )

        print(f"✅ Predictive Analysis Complete! "
              f"{len(self.predictions)} predictions generated.\n")
        return self.predictions

    # ─────────────────────────────────────────
    # IAM PREDICTIONS
    # ─────────────────────────────────────────

    def _predict_iam(self, users: list):
        """
        Predicts three future IAM violations per user:
        - Access key approaching 90-day rotation limit
        - Account approaching 60-day inactivity threshold
        - Password approaching 90-day age limit
        """
        for user in users:
            name    = user["username"]
            key_age = user.get("access_key_age_days", 0)
            login   = user.get("last_login_days",     0)
            pw_age  = user.get("password_age_days",   0)

            # ── Prediction: Access key nearing rotation deadline ──
            if key_age < KEY_ROTATION_DAYS:
                days_left = KEY_ROTATION_DAYS - key_age
                prob      = _trajectory_prob(key_age, KEY_ROTATION_DAYS)
                self.predictions.append(Prediction(
                    resource_type    = "IAM User",
                    resource_name    = name,
                    prediction_type  = "Access Key Expiry",
                    description      = (
                        f"Access key for '{name}' will violate the {KEY_ROTATION_DAYS}-day "
                        f"rotation policy in {days_left} days (currently {key_age} days old)."
                    ),
                    days_until       = days_left,
                    risk_probability = prob,
                    recommendation   = (
                        f"Rotate the access key for '{name}' before day {KEY_ROTATION_DAYS} "
                        "to stay compliant. Create the new key first, update all integrations, "
                        "then deactivate the old one."
                    )
                ))

            # ── Prediction: Account approaching inactivity flag ──
            if login < INACTIVITY_DAYS:
                days_left = INACTIVITY_DAYS - login
                prob      = _trajectory_prob(login, INACTIVITY_DAYS)
                self.predictions.append(Prediction(
                    resource_type    = "IAM User",
                    resource_name    = name,
                    prediction_type  = "Account Inactivity Risk",
                    description      = (
                        f"User '{name}' will be flagged as inactive in {days_left} days "
                        f"(last login was {login} days ago, threshold is {INACTIVITY_DAYS} days)."
                    ),
                    days_until       = days_left,
                    risk_probability = prob,
                    recommendation   = (
                        f"Monitor '{name}' activity. If no login occurs within {days_left} days, "
                        "disable the account. Review if the account is still needed."
                    )
                ))

            # ── Prediction: Password approaching age limit ──
            if pw_age < PASSWORD_AGE_DAYS:
                days_left = PASSWORD_AGE_DAYS - pw_age
                prob      = _trajectory_prob(pw_age, PASSWORD_AGE_DAYS)
                self.predictions.append(Prediction(
                    resource_type    = "IAM User",
                    resource_name    = name,
                    prediction_type  = "Password Age Violation",
                    description      = (
                        f"Password for '{name}' will exceed the {PASSWORD_AGE_DAYS}-day "
                        f"policy in {days_left} days (currently {pw_age} days old)."
                    ),
                    days_until       = days_left,
                    risk_probability = prob,
                    recommendation   = (
                        f"Enforce a password reset for '{name}' within {days_left} days. "
                        "Enable the IAM password policy to enforce this automatically."
                    )
                ))

    # ─────────────────────────────────────────
    # S3 PREDICTIONS
    # ─────────────────────────────────────────

    def _predict_s3(self, buckets: list):
        """
        Predicts two future S3 compliance violations:
        - Unencrypted private bucket heading toward GDPR audit failure
        - Bucket with no versioning AND no logging heading toward data loss
        """
        for bucket in buckets:
            name = bucket["name"]

            # ── Prediction: GDPR compliance failure (unencrypted, private) ──
            # Public buckets are already CRITICAL findings.
            # This catches the "quiet time-bomb" — private but unencrypted.
            if not bucket.get("encryption") and not bucket.get("public_access"):
                self.predictions.append(Prediction(
                    resource_type    = "S3 Bucket",
                    resource_name    = name,
                    prediction_type  = "GDPR Compliance Failure",
                    description      = (
                        f"Bucket '{name}' is private but unencrypted. "
                        "As data volume grows, this will fail a GDPR Article 32 audit "
                        "within 30 days if personal data is being stored."
                    ),
                    days_until       = 30,
                    risk_probability = 78,
                    recommendation   = "Enable AES-256 (SSE-S3) encryption immediately to prevent compliance failure."
                ))

            # ── Prediction: Data loss risk (no versioning + no logging) ──
            if not bucket.get("versioning") and not bucket.get("logging"):
                self.predictions.append(Prediction(
                    resource_type    = "S3 Bucket",
                    resource_name    = name,
                    prediction_type  = "Data Loss Risk",
                    description      = (
                        f"Bucket '{name}' has neither versioning nor access logging. "
                        "Without versioning, deleted files are unrecoverable. "
                        "Without logging, you cannot even determine what was lost or when."
                    ),
                    days_until       = 45,
                    risk_probability = 65,
                    recommendation   = (
                        "Enable S3 versioning to allow recovery of deleted objects. "
                        "Enable server access logging to a separate audit bucket."
                    )
                ))

    # ─────────────────────────────────────────
    # RDS PREDICTIONS
    # ─────────────────────────────────────────

    def _predict_rds(self, instances: list):
        """
        Predicts two future RDS database risks:
        - Accidental deletion (no deletion protection, but backups exist)
        - Compliance audit failure (unencrypted, private DB)
        """
        for db in instances:
            name = db["name"]

            # ── Prediction: Accidental deletion ──
            # Condition: no deletion_protection but backup_enabled.
            # backup_enabled means there's real data worth protecting.
            if not db.get("deletion_protection") and db.get("backup_enabled"):
                self.predictions.append(Prediction(
                    resource_type    = "RDS Instance",
                    resource_name    = name,
                    prediction_type  = "Accidental Deletion Risk",
                    description      = (
                        f"Database '{name}' has automated backups but no deletion protection. "
                        "A single mistaken CLI command (e.g. wrong --db-instance-identifier) "
                        "can permanently delete this database with no confirmation prompt."
                    ),
                    days_until       = 60,
                    risk_probability = 40,
                    recommendation   = "Enable deletion protection now. It is a one-click change with no downtime."
                ))

            # ── Prediction: Compliance audit failure (unencrypted, private) ──
            # Publicly accessible + unencrypted is already a CRITICAL finding.
            # This catches private but unencrypted databases.
            if not db.get("encrypted") and not db.get("publicly_accessible"):
                self.predictions.append(Prediction(
                    resource_type    = "RDS Instance",
                    resource_name    = name,
                    prediction_type  = "Compliance Audit Failure",
                    description      = (
                        f"Database '{name}' is private but stores data unencrypted. "
                        "This will fail a PCI-DSS Req 3.4 or GDPR Article 32 audit "
                        "if financial or personal data is present."
                    ),
                    days_until       = 30,
                    risk_probability = 85,
                    recommendation   = (
                        "Enable RDS encryption at rest via AWS KMS. "
                        "For existing instances: take a snapshot, copy it with encryption enabled, "
                        "then restore from the encrypted snapshot."
                    )
                ))

    # ─────────────────────────────────────────
    # COMBINED / COMPOUND RISK PREDICTIONS
    # ─────────────────────────────────────────

    def _predict_combined_risk(self, configs: dict):
        """
        Predicts compound risks where multiple weak configurations
        together create exponentially higher risk than each alone.

        Two compound patterns:
        1. No MFA + Old access key  → Account Takeover
        2. Public bucket + No encryption → Data Breach
        """
        users   = configs["iam_users"]
        buckets = configs["s3_buckets"]

        # ── Pattern 1: No MFA + Old key → Account Takeover ──────────
        for user in users:
            name    = user["username"]
            key_age = user.get("access_key_age_days", 0)

            if not user.get("mfa_enabled") and key_age > 60:
                # Probability scales with how old the key is beyond 60 days.
                # At 60 days: 50%. Each additional day adds 2%, capped at 95%.
                overage = key_age - 60
                prob    = min(50 + overage * 2, 95)

                # Time estimate: the older the key, the sooner the breach prediction.
                # Keys 61–90 days → 30 day warning. Beyond 90 → 14 day warning.
                days = 14 if key_age > 90 else 30

                self.predictions.append(Prediction(
                    resource_type    = "IAM User",
                    resource_name    = name,
                    prediction_type  = "Account Takeover Prediction",
                    description      = (
                        f"COMPOUND RISK: '{name}' has no MFA AND an access key "
                        f"{key_age} days old. "
                        f"The combined probability of account compromise is {prob}% "
                        f"within {days} days. Without MFA, a leaked key provides "
                        "complete, unchallenged AWS account access."
                    ),
                    days_until       = days,
                    risk_probability = prob,
                    recommendation   = (
                        "URGENT: Enable MFA first (blocks immediate exploitation), "
                        "then rotate the access key. "
                        "Treating these as separate tasks is insufficient — both must be done."
                    )
                ))

        # ── Pattern 2: Public + Unencrypted → Data Breach ────────────
        for bucket in buckets:
            if bucket.get("public_access") and not bucket.get("encryption"):
                # Fixed high probability — this combination is actively scanned for
                # by automated tools within hours of exposure.
                self.predictions.append(Prediction(
                    resource_type    = "S3 Bucket",
                    resource_name    = bucket["name"],
                    prediction_type  = "Data Breach Prediction",
                    description      = (
                        f"COMPOUND RISK: Bucket '{bucket['name']}' is both PUBLIC "
                        "and UNENCRYPTED. "
                        "Automated S3 scanners (GrayhatWarfare, bucket finder tools) "
                        "index public buckets within hours. "
                        "With no encryption, exfiltrated data is immediately readable."
                    ),
                    days_until       = 14,
                    risk_probability = 92,
                    recommendation   = (
                        "URGENT — fix in this order: "
                        "(1) Enable 'Block all public access' immediately. "
                        "(2) Enable AES-256 encryption. "
                        "(3) Audit S3 access logs for any existing unauthorized access."
                    )
                ))


# ─────────────────────────────────────────────────────
# SUMMARY BUILDER
# ─────────────────────────────────────────────────────

def build_prediction_summary(predictions: list) -> dict:
    """
    Build a summary dict from all predictions.

    Score formula:
        Uses a normalized weighted density approach —
        same philosophy as the risk score in security_agent.py.

        weighted_sum  = critical×4 + high×3 + medium×2 + low×1
        max_possible  = total_predictions × 4  (if all were CRITICAL)
        score         = (weighted_sum / max_possible) × 100

        This scales correctly regardless of prediction count
        and never needs an arbitrary cap.
    """
    if not predictions:
        return {
            "total":         0,
            "critical":      0,
            "high":          0,
            "medium":        0,
            "low":           0,
            "risk_score":    0,
            "soonest_issue": "No predictions generated.",
            "soonest_days":  0,
        }

    counts = Counter(p.urgency for p in predictions)
    critical = counts.get("CRITICAL", 0)
    high     = counts.get("HIGH",     0)
    medium   = counts.get("MEDIUM",   0)
    low      = counts.get("LOW",      0)
    total    = len(predictions)

    # Normalized weighted density (0–100, no arbitrary cap needed)
    weighted_sum = critical*4 + high*3 + medium*2 + low*1
    max_possible = total * 4
    score        = round((weighted_sum / max_possible) * 100, 1) if max_possible > 0 else 0

    soonest = min(predictions, key=lambda p: p.days_until)

    return {
        "total":         total,
        "critical":      critical,
        "high":          high,
        "medium":        medium,
        "low":           low,
        "risk_score":    score,
        "soonest_issue": soonest.description,
        "soonest_days":  soonest.days_until,
    }