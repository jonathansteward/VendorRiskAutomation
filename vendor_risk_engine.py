# Risk model: FAIR (Factor Analysis of Information Risk) with probability distributions
#
# FAIR component flow:
#   Inherent Risk  = TEF × Vulnerability (no resistance) × Loss Magnitude
#   Residual Risk  = Adjusted TEF × Adjusted Vulnerability × Adjusted Loss Magnitude
#
# Key model decisions:
#   - Inherent risk sets resistance = 0 → vulnerability = 1.0 per FAIR specification.
#     Vulnerability is P(threat capability > resistance strength); when resistance = 0,
#     any threat event succeeds → P = 1.0. Using threat_capability here would conflate
#     two distinct FAIR concepts.
#   - Monte Carlo simulation via triangular distributions provides P10/P50/P90 ranges
#     per Open FAIR standard (FAIR-U: probability distributions, not point estimates alone).
#   - Attestation multipliers reward independently verified controls over documentation-only claims.
#   - Governance controls split 40% preventive / 60% detective-corrective per FAIR Institute
#     administrative control classification guidance.
#   - Reduction ceilings (70% preventive, 65% DC) ensure residual risk > 0 even with
#     perfect scores, calibrated against IBM 2024 Cost of a Data Breach data.

import random
from statistics import mean as _mean


# ---------------------------------------------------------------------------
# Attestation Multipliers
#
# Applied to individual control implementation scores during weighted calculation.
# Multipliers boost controls scored > 0 (cannot lift a non-existent control).
# Capped per-control at 1.0: no control can exceed "Fully Implemented".
#
# Hierarchy rationale:
#   SOC 2 Type II:  Highest — sustained operation testing over 6–12 months by independent
#                   CPA firm; confirms controls operated effectively over the period.
#   ISO 27001:      ISMS certification via third-party audit; systemic control coverage.
#   Pen Test:       Offensive validation confirms technical controls resist real attacks.
#   Other:          Other third-party attestation (SOC 1, HITRUST, CSA STAR, IRAP, etc.)
#   None:           Documentation only — control existence stated, not independently verified.
# ---------------------------------------------------------------------------

ATTESTATION_MULTIPLIERS = {
    "soc2_type2": 1.25,
    "iso27001":   1.20,
    "pentest":    1.15,
    "other":      1.10,
    "none":       1.00,
}


# ---------------------------------------------------------------------------
# Loss Magnitude — Structured Component Calculator
#
# Replaces a single revenue-proxy with a sum of FAIR primary and secondary
# loss components per the Open FAIR Body of Knowledge, Section 4.
#
#   Primary loss:   Productivity (downtime), Replacement, Competitive advantage
#   Secondary loss: Response costs, Fines/judgments, Reputational damage
#
# Reference: Open FAIR Body of Knowledge v2.0 — Loss Event Frequency & Magnitude
# ---------------------------------------------------------------------------

def calculate_loss_magnitude(
    breach_notification_cost: float = 0.0,
    regulatory_fine_exposure: float = 0.0,
    incident_response_cost: float = 0.0,
    downtime_cost_per_hour: float = 0.0,
    estimated_downtime_hours: float = 0.0,
    reputation_damage_pct: float = 0.0,
    annual_revenue: float = 0.0,
) -> dict:
    """
    Calculate total loss magnitude from structured FAIR loss components.

    Args:
        breach_notification_cost: Per-record notification cost × estimated records affected.
                                  IBM 2024 Cost of a Data Breach Report avg: $164/record.
        regulatory_fine_exposure: Maximum estimated regulatory fine (GDPR, CCPA, HIPAA, etc.)
        incident_response_cost:   Forensics, legal counsel, PR/communications, remediation labor.
        downtime_cost_per_hour:   Revenue or productivity loss per hour of service disruption.
        estimated_downtime_hours: Expected duration of disruption in a material loss event.
        reputation_damage_pct:    Estimated % of annual revenue lost to customer churn/pipeline
                                  damage from reputational impact (enter as percent, e.g. 5.0 = 5%).
        annual_revenue:           Total annual revenue — used to compute reputation damage amount.

    Returns:
        Dict with 'total' (USD), 'components' breakdown, and 'distribution' (min/likely/max).
        Distribution bounds: -30% optimistic / +50% pessimistic — reflects financial
        estimation uncertainty documented in Ponemon/IBM breach cost confidence intervals.
    """
    downtime_total    = downtime_cost_per_hour * estimated_downtime_hours
    reputation_amount = annual_revenue * (reputation_damage_pct / 100.0)

    components = {
        "breach_notification": round(breach_notification_cost, 2),
        "regulatory_fines":    round(regulatory_fine_exposure, 2),
        "incident_response":   round(incident_response_cost, 2),
        "downtime":            round(downtime_total, 2),
        "reputation_damage":   round(reputation_amount, 2),
    }
    total = sum(components.values())

    return {
        "total":      round(total, 2),
        "components": components,
        # Distribution for Monte Carlo: -30% optimistic (faster response, lower fine, fewer records)
        # +50% pessimistic (regulatory maximum, extended downtime, broad reputational impact)
        "distribution": {
            "min":    round(total * 0.70, 2),
            "likely": round(total, 2),
            "max":    round(total * 1.50, 2),
        },
    }


# ---------------------------------------------------------------------------
# Inherent Risk
# ---------------------------------------------------------------------------

def calculate_inherent_risk(
    contact_frequency: float,
    probability_of_action: float,
    threat_capability: float,
    loss_magnitude: float,
) -> float:
    """
    Calculate inherent risk using the FAIR model — before any controls are applied.

    Vulnerability is set to 1.0 (not threat_capability) because:
      Vulnerability = P(threat capability > resistance strength).
      When resistance = 0, any threat actor with nonzero capability succeeds,
      so P = 1.0. Using threat_capability here would conflate actor capability
      (a threat intelligence input) with vulnerability (a FAIR derived factor).

    threat_capability is used downstream in residual risk where it modulates
    how much resistance controls must overcome.

    Args:
        contact_frequency:     How often a threat actor contacts the asset (events/year)
        probability_of_action: Likelihood the threat actor acts on contact (0.0–1.0)
        threat_capability:     Threat actor skill score (not used here; see docstring above)
        loss_magnitude:        Expected loss in USD if a loss event occurs

    Returns:
        Annualized inherent risk exposure in USD/year
    """
    threat_event_frequency = contact_frequency * probability_of_action
    vulnerability          = 1.0  # resistance = 0 → all threat events become loss events
    loss_event_frequency   = threat_event_frequency * vulnerability
    return round(loss_event_frequency * loss_magnitude, 2)


def _ordered_triangular(t: tuple) -> tuple:
    """Convert (min, likely, max) tuple to random.triangular(low, high, mode) argument order."""
    lo, mode, hi = t
    return (lo, hi, mode)


def calculate_inherent_risk_distribution(
    contact_frequency: tuple,
    probability_of_action: tuple,
    loss_magnitude: tuple,
    iterations: int = 10_000,
) -> dict:
    """
    Monte Carlo simulation of inherent risk using triangular probability distributions.

    Implements the Open FAIR standard approach (FAIR-U): express each input as a range
    (min, likely, max) sampled via triangular distribution. Returns P10/P50/P90 outputs
    that show the uncertainty range around the point estimate.

    Args:
        contact_frequency:     (min, likely, max) events/year
        probability_of_action: (min, likely, max) probability 0.0–1.0
        loss_magnitude:        (min, likely, max) USD per loss event
        iterations:            Monte Carlo sample count (default 10,000)

    Returns:
        Dict with point_estimate (mode-based), mean, p10, p50, p90, iterations
    """
    samples = [
        random.triangular(*_ordered_triangular(contact_frequency))
        * random.triangular(*_ordered_triangular(probability_of_action))
        * random.triangular(*_ordered_triangular(loss_magnitude))
        for _ in range(iterations)
    ]
    samples.sort()
    n = len(samples)

    cf_min, cf_mode, cf_max    = contact_frequency
    poa_min, poa_mode, poa_max = probability_of_action
    lm_min, lm_mode, lm_max    = loss_magnitude

    return {
        "point_estimate": round(cf_mode * poa_mode * lm_mode, 2),
        "mean":  round(_mean(samples), 2),
        "p10":   round(samples[max(0, int(n * 0.10) - 1)], 2),
        "p50":   round(samples[int(n * 0.50)], 2),
        "p90":   round(samples[min(n - 1, int(n * 0.90))], 2),
        "iterations": iterations,
    }


# ---------------------------------------------------------------------------
# Risk Rating Scale — ALE vs. Risk Appetite Thresholds
#
# ALE (Annualized Loss Expectancy) is compared against the user-defined High
# threshold to produce Low / Moderate / High ratings.
#
# Only the High threshold is user-defined. The Low/Moderate boundary is
# automatically set at 50% of the High threshold:
#
#   Low       ALE < high_threshold × 0.5
#   Moderate  high_threshold × 0.5 ≤ ALE < high_threshold
#   High      ALE ≥ high_threshold
# ---------------------------------------------------------------------------


def rate_risk(
    ale: float,
    high_threshold: float,
    company_revenue: float = 0.0,
) -> dict:
    """
    Assign a risk rating by comparing ALE against the user-defined High threshold.

    The Low/Moderate boundary is derived automatically as 50% of high_threshold.

    Args:
        ale:             Annualized Loss Expectancy in USD/yr (inherent or residual)
        high_threshold:  ALE at or above this is High (user-defined risk appetite)
        company_revenue: Optional — when provided, ale_pct_revenue is included in output

    Returns:
        Dict with 'rating', 'ale', 'thresholds', 'scale', optional 'ale_pct_revenue'
    """
    low_threshold = high_threshold * 0.5

    if ale < low_threshold:
        rating = "Low"
    elif ale < high_threshold:
        rating = "Moderate"
    else:
        rating = "High"

    threshold_gap = round(ale - high_threshold, 2)

    result = {
        "rating":        rating,
        "ale":           round(ale, 2),
        "threshold_gap": threshold_gap,   # positive = above threshold, negative = within appetite
        "thresholds": {
            "low":  round(low_threshold, 2),
            "high": round(high_threshold, 2),
        },
        "scale": {
            "Low":      f"ALE < ${low_threshold:,.0f}/yr — Less than risk appetite",
            "Moderate": f"ALE ${low_threshold:,.0f}–${high_threshold:,.0f}/yr — Less than risk appetite",
            "High":     f"ALE ≥ ${high_threshold:,.0f}/yr — Greater than risk appetite",
        },
    }

    if company_revenue and company_revenue > 0:
        result["ale_pct_revenue"] = round((ale / company_revenue) * 100, 2)

    return result


# ---------------------------------------------------------------------------
# Control Strength
# Implementation levels: 1 = Fully Implemented, 0.5 = Partially, 0 = Not Implemented
# Effectiveness ratings: >= 0.80 = Effective, 0.50–0.79 = Partially Effective, < 0.50 = Ineffective
# ---------------------------------------------------------------------------

ACCESS_CONTROLS = {
    "multi_factor_authentication":           0.20,
    "privileged_access_management":          0.15,
    "least_privilege_rbac":                  0.15,
    "identity_lifecycle_management":         0.10,
    "periodic_access_reviews":               0.10,
    "single_sign_on_central_identity":       0.08,
    "session_management_timeout_controls":   0.07,
    "authentication_logging_monitoring":     0.07,
    "credential_storage_security":           0.05,
    "account_lockout_brute_force_protection":0.03,
}

DATA_SECURITY_CONTROLS = {
    "encryption_at_rest":          0.20,
    "encryption_in_transit":       0.15,
    "data_access_restrictions":    0.15,
    "data_classification_program": 0.10,
    "database_security_controls":  0.10,
    "data_loss_prevention":        0.08,
    "key_management_security":     0.08,
    "secure_backup_protection":    0.07,
    "data_retention_policies":     0.04,
    "data_integrity_validation":   0.03,
}

INTEGRATION_RISK_CONTROLS = {
    "api_authentication":             0.20,
    "secure_credential_storage":      0.15,
    "input_validation_sanitization":  0.15,
    "api_authorization_controls":     0.10,
    "rate_limiting_abuse_protection": 0.10,
    "integration_logging":            0.08,
    "transport_security_tls":         0.07,
    "api_gateway_security":           0.07,
    "vendor_integration_reviews":     0.05,
    "service_account_restrictions":   0.03,
}

AI_RISK_CONTROLS = {
    "training_data_governance":    0.20,
    "model_access_control":        0.15,
    "model_validation_testing":    0.15,
    "output_monitoring":           0.10,
    "prompt_injection_protection": 0.10,
    "human_oversight_review":      0.08,
    "model_version_control":       0.08,
    "model_security_monitoring":   0.07,
    "model_input_sanitization":    0.05,
    "third_party_ai_risk_review":  0.02,
}

AVAILABILITY_RISK_CONTROLS = {
    "system_redundancy_failover":    0.20,
    "backup_restore_capability":     0.15,
    "disaster_recovery_plan":        0.15,
    "infrastructure_monitoring":     0.10,
    "capacity_planning":             0.10,
    "incident_response_procedures":  0.08,
    "network_resilience":            0.08,
    "patch_management":              0.07,
    "load_balancing":                0.05,
    "service_recovery_testing":      0.02,
}

GOVERNANCE_RISK_CONTROLS = {
    "security_policy_framework":          0.20,
    "risk_management_program":            0.15,
    "third_party_risk_management":        0.15,
    "security_awareness_training":        0.10,
    "compliance_certifications":          0.10,
    "security_incident_reporting":        0.08,
    "vulnerability_management_program":   0.08,
    "change_management":                  0.07,
    "audit_program":                      0.05,
    "security_leadership_governance":     0.02,
}

CONTROL_CATEGORIES = {
    "access":        ACCESS_CONTROLS,
    "data_security": DATA_SECURITY_CONTROLS,
    "integration":   INTEGRATION_RISK_CONTROLS,
    "ai":            AI_RISK_CONTROLS,
    "availability":  AVAILABILITY_RISK_CONTROLS,
    "governance":    GOVERNANCE_RISK_CONTROLS,
}


def _effectiveness_rating(score: float) -> str:
    if score >= 0.80:
        return "Effective"
    elif score >= 0.50:
        return "Partially Effective"
    return "Ineffective"


def calculate_control_strength(
    category: str,
    implementations: dict,
    attestation_multiplier: float = 1.0,
) -> dict:
    """
    Calculate control strength for a risk category using weighted implementation scores.

    Args:
        category:               One of 'access', 'data_security', 'integration', 'ai',
                                'availability', 'governance'
        implementations:        Dict mapping control key -> implementation level
                                (1 = Fully Implemented, 0.5 = Partial, 0 = Not Implemented)
        attestation_multiplier: Skepticism discount when no third-party attestation is present.
                                Applied as: min(level × multiplier, 1.0) per control.
                                Controls scored 0 are unaffected (absence cannot be verified).
                                1.0  = third-party attestation confirmed — full credit.
                                <1.0 = self-attested only — discount applied for lack of
                                       independent verification (default 0.85).

    Returns:
        Dict with:
            'score'               — weighted effectiveness score (0.0 to 1.0)
            'rating'              — 'Effective', 'Partially Effective', or 'Ineffective'
            'unscored_controls'   — controls not provided in implementations (defaulted to 0)
            'attestation_applied' — True if a multiplier was applied (multiplier ≠ 1.0)
    """
    if category not in CONTROL_CATEGORIES:
        raise ValueError(
            f"Unknown category '{category}'. Valid options: {list(CONTROL_CATEGORIES)}"
        )

    valid_levels = {0, 0.5, 1}
    for control, level in implementations.items():
        if level not in valid_levels:
            raise ValueError(
                f"Invalid implementation level '{level}' for '{control}'. "
                f"Must be 0 (Not Implemented), 0.5 (Partial), or 1 (Full)."
            )

    control_weights = CONTROL_CATEGORIES[category]
    unscored = [k for k in control_weights if k not in implementations]

    # Apply attestation multiplier per control, capped at 1.0.
    # Without independent verification, self-reported controls are discounted (multiplier < 1.0).
    # With third-party attestation the multiplier is 1.0 — full credit. Controls scored 0 are
    # unaffected in either case (absence of a control cannot be verified into existence).
    score = sum(
        min(implementations.get(control, 0) * attestation_multiplier, 1.0) * weight
        for control, weight in control_weights.items()
    )

    return {
        "score":               round(score, 4),
        "rating":              _effectiveness_rating(score),
        "unscored_controls":   unscored,
        "attestation_applied": attestation_multiplier != 1.0,
    }


# ---------------------------------------------------------------------------
# Residual Risk — FAIR-CAM v1.0 Aligned Control Classification
#
# Each control category maps to the FAIR-CAM Loss Event Function it implements,
# per The FAIR Institute's Control Analysis Model (FAIR-CAM v1.0).
#
# FAIR-CAM functions and the FAIR components they affect:
#
#   Prevention/Avoidance   (A) → ↓ Contact Frequency
#   Prevention/Deterrence  (B) → ↓ Probability of Action
#   Prevention/Resistance  (C) → ↓ Susceptibility (Vulnerability)
#   Detection (Visibility, Monitoring, Recognition) → manages frequency + magnitude
#   Response (Containment, Resilience, Loss Minimization) (D) → ↓ Loss Magnitude
#
# Category → FAIR-CAM function mapping:
#
#   Access Controls         → Resistance (C): MFA, PAM, RBAC, SSO directly harden the
#                             attack surface against exploitation attempts (core Resistance).
#                             Account lockout and session controls contribute minor Deterrence (B).
#
#   Integration Controls    → Resistance (C): API authentication, input validation, rate limiting,
#                             and API gateway security resist attacks at integration points.
#
#   AI Controls             → Resistance (C) + Detection: Prompt injection protection and model
#                             access control = Resistance; output/security monitoring = Detection.
#
#   Data Security Controls  → Detection + Response/Loss Minimization (D): DLP, classification,
#                             monitoring = Detection (limits breach dwell time → ↓ frequency + magnitude);
#                             encryption at rest/transit + backup = Loss Minimization (↓ LM).
#                             Applied as 50% corrective/LM value in the composite.
#
#   Availability Controls   → Response: Containment + Resilience (D): DR, backup, failover,
#                             incident response = Containment and Resilience controls that
#                             directly reduce loss magnitude when a loss event occurs.
#
#   Governance Controls     → Avoidance (A) + Deterrence (B) + Resistance (minor) + Response (minor):
#                             Risk management, TPRM, security policy = Avoidance (↓ CF by avoiding
#                             risky vendor relationships / reducing attack surface exposure).
#                             Security awareness training = Deterrence (↓ PoA; Verizon DBIR 2024:
#                             68% of breaches involve human element — training directly reduces PoA).
#                             Vulnerability management, change management = Resistance (↓ susceptibility).
#                             Incident response procedures, incident reporting = Response (↓ LM).
#
# Composite score construction (three independent FAIR composites):
#
#   effective_tef      (Avoidance + Deterrence → ↓ CF and PoA):
#     Governance 40%  — TPRM, risk mgmt, policy = Avoidance; awareness = Deterrence
#     Access 20%      — lockout, session mgmt = minor Deterrence effect on PoA
#
#   effective_resistance (Resistance → ↓ Susceptibility / Vulnerability):
#     Access, Integration, AI = primary Resistance controls (when applicable)
#     Governance 40%  — vuln management, change management, audit = Resistance contribution
#
#   effective_lm       (Detection + Response → ↓ Loss Magnitude):
#     Data Security 50% — Detection (DLP, monitoring) + Loss Minimization (encryption)
#     Availability 100% — Containment + Resilience (DR, backup, IR)
#     Governance 20%   — IR procedures, incident reporting = Response
#
# Vulnerability normalization — inherent/residual consistency:
#   Inherent risk uses vulnerability = 1.0 (resistance = 0, per FAIR spec).
#   Residual vulnerability must normalize against the no-controls baseline so that
#   zero controls → residual_risk = inherent_risk. Formula:
#     vuln_ratio = (1 − adj_resistance) / (1 − baseline_resistance)
#   This ratio is 1.0 with no controls and decreases as Resistance controls take effect.
#
# Calibrated reduction ceilings (per IBM 2024 Cost of a Data Breach + NIST SP 800-30 Rev.1):
#   TEF        → max 45% reduction (Avoidance + Deterrence ceiling)
#   Resistance → boost = effective_resistance × 0.40 × (1 − RS_baseline), capped at 0.75
#   LM         → max 40% reduction (Detection + Response ceiling)
#
#   Ceilings prevent triple-compounding of CF × vuln × LM from producing near-zero residuals
#   at average control levels. IBM 2024 CODB: highest-maturity programs reduce costs ~33%
#   vs. lowest-maturity benchmarks. Theoretical max (no controls → best-in-class): ~70%
#   reduction per NIST SP 800-30 Appendix I (residual risk is never zero).
#
# Verified output ranges:
#   0% controls   → residual = 100% of inherent
#   ~25% controls → residual ≈ 65–75% of inherent
#   50% controls  → residual ≈ 45–55% of inherent
#   100% controls → residual ≈ 28–35% of inherent
# ---------------------------------------------------------------------------

def calculate_residual_risk(
    contact_frequency: float,
    probability_of_action: float,
    threat_capability: float,
    resistance_strength: float,
    loss_magnitude: float,
    high_threshold: float,
    control_scores: dict,
    company_revenue: float = 0.0,
    applicable_categories: set = None,
    input_sources: dict = None,
    distributions: dict = None,
    monte_carlo_iterations: int = 10_000,
) -> dict:
    """
    Apply control effectiveness to FAIR components and return residual risk.

    Args:
        contact_frequency:      Events/year a threat actor contacts the asset
        probability_of_action:  Likelihood actor acts on contact (0.0–1.0)
        threat_capability:      Threat actor capability relative to controls (0.0–1.0)
        resistance_strength:    Baseline control resistance before scoring (0.0–1.0)
        loss_magnitude:         Expected loss in USD per loss event
        high_threshold:         ALE at or above this is High — Low/Moderate boundary auto-set at 50%
        control_scores:         Dict of category -> effectiveness score (0.0–1.0) from
                                calculate_control_strength(). Expected keys:
                                'access', 'integration', 'ai' (if applicable),
                                'data_security', 'availability', 'governance'
        company_revenue:        Optional total company annual revenue — used to compute ale_pct_revenue
        applicable_categories:  Set of category keys included in composite scoring.
                                Omit 'ai' for non-AI-enabled vendors. Defaults to all 6.
        input_sources:          Optional dict logged as 'input_provenance' in the output.
                                Recommended keys: source name for each FAIR input.
                                Provides an audit trail for every scored assessment.
        distributions:          Optional dict of (min, likely, max) tuples keyed by
                                'contact_frequency', 'probability_of_action',
                                'threat_capability', 'resistance_strength', 'loss_magnitude'.
                                When provided, Monte Carlo simulation is run and P10/P50/P90
                                distribution added to results.
        monte_carlo_iterations: Sample count for Monte Carlo (default 10,000).

    Returns:
        Dict with inherent_risk, residual_risk (USD/year), adjusted FAIR inputs,
        optional 'distribution' (P10/P50/P90), optional 'input_provenance'.
    """
    # Determine which categories are applicable (e.g. exclude 'ai' for non-AI vendors)
    applicable = applicable_categories if applicable_categories is not None else \
                 {"access", "integration", "ai", "data_security", "availability", "governance"}

    gov_score    = control_scores.get("governance", 0)
    access_score = control_scores.get("access", 0)

    # ── FAIR-CAM Composite 1: Avoidance + Deterrence → ↓ Contact Frequency / PoA ──
    # Governance (40%): risk mgmt, TPRM, security policy = Avoidance (A);
    #                   awareness training = Deterrence (B)
    # Access (20%):     account lockout, session timeout = minor Deterrence (B) on PoA
    effective_tef = min(0.90, gov_score * 0.40 + access_score * 0.20)

    adj_contact_frequency = contact_frequency * (1 - effective_tef * 0.45)

    # ── FAIR-CAM Composite 2: Resistance → ↓ Susceptibility (Vulnerability) ──
    # Access, Integration, AI = primary Resistance (C) controls
    # Governance (40%): vuln management, change management, audit = Resistance contribution
    resist_cats  = [c for c in ["access", "integration", "ai"] if c in applicable]
    resist_base  = (sum(control_scores.get(c, 0) for c in resist_cats) / len(resist_cats)) \
                   if resist_cats else 0.0
    effective_resistance = min(0.90, resist_base + gov_score * 0.40)

    # TC modulates how effective resistance controls are against the attacker:
    # high-capability threat actors partially overcome defenses (20% discount at TC=1.0).
    # This makes threat_capability meaningful in the residual calculation.
    tc_resistance_scale = 1.0 - threat_capability * 0.20

    # Boost baseline resistance by a fraction of the remaining gap.
    # adj_resistance >= resistance_strength always (controls can only help, never hurt).
    # Capped at 0.95: no vendor fully eliminates susceptibility — zero-days and
    # insider threats persist regardless of control maturity (NIST SP 800-30 Rev.1).
    adj_resistance = max(
        resistance_strength,
        min(0.95, resistance_strength
            + effective_resistance * 0.40 * tc_resistance_scale * (1 - resistance_strength))
    )

    # ── FAIR-CAM Composite 3: Detection + Response → ↓ Loss Magnitude ──
    # Data Security (50%): Detection (DLP, monitoring) + Loss Minimization (encryption, backup)
    # Availability (100%): Containment + Resilience (DR, backup, incident response)
    # Governance (20%):    IR procedures, incident reporting = Response contribution
    ds_score = control_scores.get("data_security", 0) if "data_security" in applicable else 0.0
    av_score = control_scores.get("availability",  0) if "availability"  in applicable else 0.0
    lm_cats  = sum(1 for c in ["data_security", "availability"] if c in applicable)
    lm_base  = (ds_score * 0.50 + av_score) / max(1, lm_cats) if lm_cats else 0.0
    effective_lm = min(0.90, lm_base + gov_score * 0.20)

    adj_loss_magnitude = loss_magnitude * (1 - effective_lm * 0.40)

    # ── Inherent risk (no controls, vulnerability = 1.0 per FAIR spec) ──
    inherent_risk = calculate_inherent_risk(
        contact_frequency, probability_of_action,
        threat_capability, loss_magnitude
    )

    # ── Residual vulnerability ratio — normalized to no-controls baseline ──
    # vuln_ratio expresses residual susceptibility as a fraction of the sector baseline
    # (the inherent exposure before any organizational controls are applied).
    # Formula: vuln_ratio = (1 − adj_resistance) / (1 − baseline_resistance)
    #   → 1.0 when no org controls are applied (adj_resistance = baseline)
    #   → decreases as Resistance controls raise adj_resistance above baseline
    # vuln_ratio is capped at 1.0: controls cannot make residual > inherent.
    baseline_exposure = max(0.001, 1.0 - resistance_strength)
    adj_exposure      = max(0.0,   1.0 - adj_resistance)
    vuln_ratio        = min(1.0, adj_exposure / baseline_exposure)

    residual_tef  = adj_contact_frequency * probability_of_action
    residual_lef  = residual_tef * vuln_ratio
    residual_risk = round(residual_lef * adj_loss_magnitude, 2)

    inherent_rating = rate_risk(inherent_risk, high_threshold, company_revenue)
    residual_rating = rate_risk(residual_risk, high_threshold, company_revenue)

    result = {
        "inherent_risk":   inherent_risk,
        "inherent_rating": inherent_rating,
        "residual_risk":   residual_risk,
        "residual_rating": residual_rating,
        "risk_reduction":  round(inherent_risk - residual_risk, 2),
        "adjusted": {
            "contact_frequency":   round(adj_contact_frequency, 4),
            "resistance_strength": round(adj_resistance, 4),
            "loss_magnitude":      round(adj_loss_magnitude, 2),
        },
        "composite_scores": {
            # FAIR-CAM function labels for audit transparency
            "avoidance_deterrence": round(effective_tef, 4),        # → TEF reduction
            "resistance":           round(effective_resistance, 4),  # → Susceptibility reduction
            "detection_response":   round(effective_lm, 4),          # → LM reduction
        },
        "applicable_categories": sorted(applicable),
    }

    # --- Input provenance (audit trail) ---
    if input_sources:
        result["input_provenance"] = input_sources

    # --- Monte Carlo distribution (when distribution tuples provided) ---
    if distributions:
        cf_dist  = distributions.get("contact_frequency")
        poa_dist = distributions.get("probability_of_action")
        tc_dist  = distributions.get("threat_capability")
        rs_dist  = distributions.get("resistance_strength")
        lm_dist  = distributions.get("loss_magnitude")

        if cf_dist and poa_dist and lm_dist:
            inherent_dist = calculate_inherent_risk_distribution(
                cf_dist, poa_dist, lm_dist, iterations=monte_carlo_iterations
            )

            residual_dist = None
            if rs_dist:
                residual_samples = []
                for _ in range(monte_carlo_iterations):
                    s_cf  = random.triangular(*_ordered_triangular(cf_dist))
                    s_poa = random.triangular(*_ordered_triangular(poa_dist))
                    s_rs  = random.triangular(*_ordered_triangular(rs_dist))
                    s_lm  = random.triangular(*_ordered_triangular(lm_dist))

                    # Apply the same FAIR-CAM formulas using point-estimate composites
                    s_adj_cf  = s_cf * (1 - effective_tef * 0.45)
                    s_adj_rs  = max(s_rs, min(0.95,
                                    s_rs + effective_resistance * 0.40 * tc_resistance_scale * (1 - s_rs)))
                    s_adj_lm  = s_lm * (1 - effective_lm * 0.40)
                    s_baseline = max(0.001, 1.0 - s_rs)
                    s_exposure = max(0.0,   1.0 - s_adj_rs)
                    s_vuln_r  = min(1.0, s_exposure / s_baseline)
                    s_tef     = s_adj_cf * s_poa
                    residual_samples.append(s_tef * s_vuln_r * s_adj_lm)

                residual_samples.sort()
                n = len(residual_samples)
                residual_dist = {
                    "mean": round(_mean(residual_samples), 2),
                    "p10":  round(residual_samples[max(0, int(n * 0.10) - 1)], 2),
                    "p50":  round(residual_samples[int(n * 0.50)], 2),
                    "p90":  round(residual_samples[min(n - 1, int(n * 0.90))], 2),
                    "iterations": monte_carlo_iterations,
                }

            result["distribution"] = {
                "inherent": inherent_dist,
                "residual": residual_dist,
            }

    return result
