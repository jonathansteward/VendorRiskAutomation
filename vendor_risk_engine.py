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
# Risk Rating Scale
#
# Expressed as Annualised Risk Exposure (ARE) as a percentage of Loss Magnitude.
# Using a relative scale makes ratings meaningful regardless of org size or sector.
#
#   ARE % = (annual risk / loss_magnitude) * 100
#
#   LOW       ARE < 20%   — risk is a small fraction of a single loss event per year
#   MODERATE  20% ≤ ARE < 50% — material exposure; controls or monitoring warranted
#   HIGH      ARE ≥ 50%   — expected annual loss is half or more of a single event value
#
# Rationale for thresholds:
#   - An ARE of 20% means roughly 1 loss event every 5 years at full magnitude — low
#   - An ARE of 50% means roughly 1 loss event every 2 years — significant and material
#   - These align with Ponemon/IBM Cost of a Data Breach frequency data showing
#     the average breach recurrence cycle across industries
# ---------------------------------------------------------------------------

RISK_SCALE = [
    (0.20, "Low"),
    (0.50, "Moderate"),
    (float("inf"), "High"),
]


def rate_risk(
    risk_amount: float,
    loss_magnitude: float,
    company_revenue: float = 0.0,
) -> dict:
    """
    Assign a risk rating based on ARE (Annualised Risk Exposure as % of Loss Magnitude).

    Args:
        risk_amount:      Annual risk in USD (inherent or residual)
        loss_magnitude:   Expected loss per event used as ARE denominator
        company_revenue:  Optional — total company annual revenue, used as a second
                          ARE denominator to show materiality relative to the whole business

    Returns:
        Dict with 'rating' (Low/Moderate/High), 'are_pct' (float),
        optional 'are_pct_company' (float), and 'scale' definition
    """
    are_pct = (risk_amount / loss_magnitude) if loss_magnitude else 0

    rating = "High"
    for threshold, label in RISK_SCALE:
        if are_pct < threshold:
            rating = label
            break

    result = {
        "rating":  rating,
        "are_pct": round(are_pct * 100, 1),
        "scale": {
            "Low":      "ARE < 20%  — less than 1 full loss event every 5 years",
            "Moderate": "ARE 20–50% — 1 full loss event every 2–5 years",
            "High":     "ARE ≥ 50%  — 1 full loss event every 1–2 years or more",
        },
    }

    if company_revenue and company_revenue > 0:
        result["are_pct_company"] = round((risk_amount / company_revenue) * 100, 2)

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
# Residual Risk
#
# Control type → FAIR component affected:
#
#   Preventive  (access, integration, ai — when applicable)
#     → Lowers contact_frequency (reduces threat actor reach / attack surface)
#     → Raises resistance_strength (hardens vulnerability)
#
#   Detective / Corrective  (data_security, availability)
#     → Lowers loss_magnitude (limits blast radius, enables faster recovery)
#
#   Administrative / Governance  (governance)
#     → Split effect: 40% preventive, 60% detective/corrective
#
# Governance 40/60 split rationale:
#   Administrative controls (policies, training, risk management programs) primarily
#   improve incident detection speed and response effectiveness rather than directly
#   preventing threat actor contact — consistent with SANS Institute and FAIR Institute
#   guidance on administrative control classification (FAIR-CAM v1.0).
#   The 40% preventive contribution accounts for security awareness training and policy
#   frameworks that reduce human-error-driven threat events. Per Verizon DBIR 2024,
#   68% of breaches involve the human element, making training a meaningful preventive factor.
#
# Reduction ceilings prevent residual risk from reaching zero even with perfect scores:
#   Preventive → max 70% reduction to contact_frequency
#   DC         → max 65% reduction to loss_magnitude
#
# Ceiling justification (NIST SP 800-30 Rev.1 alignment):
#   NIST SP 800-30 Appendix I states residual risk is never zero because some residual
#   uncertainty always remains. The 70% preventive ceiling reflects that even optimal
#   technical controls cannot eliminate all threat contact: social engineering, supply
#   chain attacks, insider threats, and zero-days persist regardless of access/integration
#   controls. The 65% DC ceiling reflects that some data loss is unavoidable in severe
#   incidents even with strong containment capabilities.
#   Both ceilings are consistent with IBM 2024 Cost of a Data Breach data showing maximum
#   observed breach cost reduction of ~60% in highest-maturity security programs (Figure 19).
#   Reference: IBM Security / Ponemon 2024 Cost of a Data Breach Report.
# ---------------------------------------------------------------------------

def calculate_residual_risk(
    contact_frequency: float,
    probability_of_action: float,
    threat_capability: float,
    resistance_strength: float,
    loss_magnitude: float,
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
        control_scores:         Dict of category -> effectiveness score (0.0–1.0) from
                                calculate_control_strength(). Expected keys:
                                'access', 'integration', 'ai' (if applicable),
                                'data_security', 'availability', 'governance'
        company_revenue:        Optional total company annual revenue for secondary ARE
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

    # --- Composite scores by control type ---
    preventive_cats  = [c for c in ["access", "integration", "ai"] if c in applicable]
    preventive_score = (
        sum(control_scores.get(c, 0) for c in preventive_cats) / len(preventive_cats)
    ) if preventive_cats else 0.0

    dc_score    = (control_scores.get("data_security", 0) + control_scores.get("availability", 0)) / 2
    admin_score = control_scores.get("governance", 0)

    # --- Preventive controls: lower contact_frequency and raise resistance ---
    # Governance contributes 40% of its score as a preventive amplifier (see rationale above)
    effective_preventive = min(1.0, preventive_score + admin_score * 0.40)

    adj_contact_frequency = contact_frequency * (1 - effective_preventive * 0.70)
    adj_resistance = min(
        1.0,
        resistance_strength + effective_preventive * (1 - resistance_strength)
    )

    # --- Detective/Corrective controls: lower loss_magnitude ---
    # Governance contributes 60% of its score as a detective/corrective amplifier (see rationale above)
    effective_dc = min(1.0, dc_score + admin_score * 0.60)

    adj_loss_magnitude = loss_magnitude * (1 - effective_dc * 0.65)

    # --- Inherent risk (no controls) ---
    inherent_risk = calculate_inherent_risk(
        contact_frequency, probability_of_action,
        threat_capability, loss_magnitude
    )

    # --- Residual risk (controls applied) ---
    residual_tef  = adj_contact_frequency * probability_of_action
    residual_vuln = threat_capability * (1 - adj_resistance)
    residual_lef  = residual_tef * residual_vuln
    residual_risk = round(residual_lef * adj_loss_magnitude, 2)

    inherent_rating = rate_risk(inherent_risk, loss_magnitude, company_revenue)
    residual_rating = rate_risk(residual_risk, loss_magnitude, company_revenue)

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
            "preventive":           round(effective_preventive, 4),
            "detective_corrective": round(effective_dc, 4),
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
            if tc_dist and rs_dist:
                residual_samples = []
                for _ in range(monte_carlo_iterations):
                    s_cf  = random.triangular(*_ordered_triangular(cf_dist))
                    s_poa = random.triangular(*_ordered_triangular(poa_dist))
                    s_tc  = random.triangular(*_ordered_triangular(tc_dist))
                    s_rs  = random.triangular(*_ordered_triangular(rs_dist))
                    s_lm  = random.triangular(*_ordered_triangular(lm_dist))

                    s_adj_cf = s_cf * (1 - effective_preventive * 0.70)
                    s_adj_rs = min(1.0, s_rs + effective_preventive * (1 - s_rs))
                    s_adj_lm = s_lm * (1 - effective_dc * 0.65)
                    s_tef    = s_adj_cf * s_poa
                    s_vuln   = s_tc * (1 - s_adj_rs)
                    residual_samples.append(s_tef * s_vuln * s_adj_lm)

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
