# Risk is below (Initial easy FAIR model application - To be updated)
# Threat Event Frequency = how many times has company been hit
# in last 3 years (last year)
# Threat capability = Search for industry, what type of threat actor is most expected to attack, apply capability score with APT being highest and script kiddie lowest
# Impact = Dollar amount
# Control strength = define later
# Inherent Risk  = (TEF = Contact Frequency * Probability of Action) * Threat Capability * Loss Magnitude
#   (Resistance Strength excluded — unknown prior to control assessment)
# Residual Risk   = (Adjusted TEF * Adjusted Vulnerability) * Adjusted Loss Magnitude
#   (Resistance Strength applied only after control assessment scores are known)

def calculate_inherent_risk(
    contact_frequency: float,
    probability_of_action: float,
    threat_capability: float,
    loss_magnitude: float,
) -> float:
    """
    Calculate inherent risk using the FAIR model — before any controls are applied.

    Resistance strength is intentionally excluded: inherent risk represents exposure
    in the absence of controls, which is unknown until a control assessment is performed.
    Vulnerability is therefore treated as fully determined by threat capability alone
    (resistance = 0, so vulnerability = threat_capability * 1).

    Args:
        contact_frequency:    How often a threat actor contacts the asset (events/year)
        probability_of_action: Likelihood the threat actor acts on contact (0.0–1.0)
        threat_capability:    Threat actor skill/capability score (0.0–1.0)
        loss_magnitude:       Expected loss in USD if a loss event occurs

    Returns:
        Annualized inherent risk exposure in USD/year
    """
    threat_event_frequency = contact_frequency * probability_of_action
    vulnerability = threat_capability  # resistance = 0, no controls assumed
    loss_event_frequency = threat_event_frequency * vulnerability
    risk = loss_event_frequency * loss_magnitude
    return round(risk, 2)


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
        loss_magnitude:   Product/service revenue used as maximum expected loss per event
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
    "access":       ACCESS_CONTROLS,
    "data_security": DATA_SECURITY_CONTROLS,
    "integration":  INTEGRATION_RISK_CONTROLS,
    "ai":           AI_RISK_CONTROLS,
    "availability": AVAILABILITY_RISK_CONTROLS,
    "governance":   GOVERNANCE_RISK_CONTROLS,
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
) -> dict:
    """
    Calculate control strength for a risk category using weighted implementation scores.

    Args:
        category: One of 'access', 'data_security', 'integration', 'ai', 'availability', 'governance'
        implementations: Dict mapping control key -> implementation level
                         (1 = Fully Implemented, 0.5 = Partially Implemented, 0 = Not Implemented)

    Returns:
        Dict with:
            'score'             - weighted effectiveness score (0.0 to 1.0)
            'rating'            - 'Effective', 'Partially Effective', or 'Ineffective'
            'unscored_controls' - list of controls not provided in implementations

    Example:
        calculate_control_strength("access", {
            "multi_factor_authentication": 1,
            "privileged_access_management": 0.5,
            "least_privilege_rbac": 1,
            ...
        })
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

    # Unscored controls default to 0 (Not Implemented / Ineffective)
    score = sum(
        implementations.get(control, 0) * weight
        for control, weight in control_weights.items()
    )

    return {
        "score": round(score, 4),
        "rating": _effectiveness_rating(score),
        "unscored_controls": unscored,
    }


# ---------------------------------------------------------------------------
# Residual Risk
#
# Control type → FAIR component affected:
#
#   Preventive  (access, integration, ai)
#     → Lowers contact_frequency (reduces threat actor reach / attack surface)
#     → Raises resistance_strength (hardens vulnerability)
#
#   Detective / Corrective  (data_security, availability)
#     → Lowers loss_magnitude (limits blast radius, enables faster recovery)
#
#   Administrative / Governance  (governance)
#     → Split effect: 40% preventive, 60% detective/corrective
#       (program-level controls reinforce but don't replace technical controls)
#
# Reduction ceilings keep residual risk > 0 even with perfect scores:
#   Preventive  → max 70% reduction to contact_frequency
#   Preventive  → fills resistance gap by score (score 1.0 → resistance → 1.0)
#   DC          → max 65% reduction to loss_magnitude
#   Governance  → max 30% secondary effect on each side
# ---------------------------------------------------------------------------

def calculate_residual_risk(
    contact_frequency: float,
    probability_of_action: float,
    threat_capability: float,
    resistance_strength: float,
    loss_magnitude: float,
    control_scores: dict,
    company_revenue: float = 0.0,
) -> dict:
    """
    Apply control effectiveness to FAIR components and return residual risk.

    Args:
        contact_frequency:    Events/year a threat actor contacts the asset
        probability_of_action: Likelihood actor acts on contact (0.0–1.0)
        threat_capability:    Threat actor capability relative to controls (0.0–1.0)
        resistance_strength:  Baseline control resistance before scoring (0.0–1.0)
        loss_magnitude:       Product/service revenue — expected loss in USD per loss event
        control_scores:       Dict of category -> effectiveness score (0.0–1.0) from
                              calculate_control_strength(). Expected keys:
                              'access', 'integration', 'ai',
                              'data_security', 'availability', 'governance'
        company_revenue:      Optional total company annual revenue for secondary ARE

    Returns:
        Dict with inherent_risk, residual_risk (both USD/year), and adjusted FAIR inputs
    """
    # --- Composite scores by control type ---
    preventive_score = (
        control_scores.get("access", 0)
        + control_scores.get("integration", 0)
        + control_scores.get("ai", 0)
    ) / 3

    dc_score = (
        control_scores.get("data_security", 0)
        + control_scores.get("availability", 0)
    ) / 2

    admin_score = control_scores.get("governance", 0)

    # --- Preventive controls: lower contact_frequency and raise resistance ---
    # Governance contributes 40% of its score as a preventive amplifier
    effective_preventive = min(1.0, preventive_score + admin_score * 0.40)

    adj_contact_frequency = contact_frequency * (1 - effective_preventive * 0.70)
    adj_resistance = min(
        1.0,
        resistance_strength + effective_preventive * (1 - resistance_strength)
    )

    # --- Detective/Corrective controls: lower loss_magnitude ---
    # Governance contributes 60% of its score as a detective/corrective amplifier
    effective_dc = min(1.0, dc_score + admin_score * 0.60)

    adj_loss_magnitude = loss_magnitude * (1 - effective_dc * 0.65)

    # --- Inherent risk (no controls — resistance_strength excluded by design) ---
    inherent_risk = calculate_inherent_risk(
        contact_frequency, probability_of_action,
        threat_capability, loss_magnitude
    )

    # --- Residual risk (controls applied) ---
    residual_tef = adj_contact_frequency * probability_of_action
    residual_vuln = threat_capability * (1 - adj_resistance)
    residual_lef = residual_tef * residual_vuln
    residual_risk = round(residual_lef * adj_loss_magnitude, 2)

    inherent_rating = rate_risk(inherent_risk, loss_magnitude, company_revenue)
    residual_rating = rate_risk(residual_risk, loss_magnitude, company_revenue)

    return {
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
    }