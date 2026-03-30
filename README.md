# VendorRiskAutomation

A web-based vendor risk assessment platform that automates third-party security evaluations using the FAIR (Factor Analysis of Information Risk) quantitative risk model, with FAIR-CAM v1.0 aligned control analysis.

## What It Does

Given a vendor name, industry sector, and either uploaded security documents or a completed questionnaire, the platform produces a quantified, dollar-denominated risk assessment with inherent and residual risk ratings and exported reports.

### Assessment Workflow

1. **Threat Intelligence** — Queries GPT-4o to derive FAIR threat inputs (contact frequency, probability of action, threat capability, resistance strength) from public sources (Verizon DBIR, CISA, FBI IC3, MITRE ATT&CK, IBM X-Force). Values are scoped to a single organization's single vendor relationship — not sector-wide aggregates.

2. **Inherent Risk Calculation** — Computes Annualized Loss Expectancy (ALE) in USD before any controls are considered, using `TEF × Vulnerability × Loss Magnitude` with vulnerability set to 1.0 (no resistance assumed). Rated Low / Moderate / High against dollar-based risk appetite thresholds auto-derived from company revenue.

3. **Control Assessment** — Reviews vendor security documentation (PDF, DOCX, TXT, MD) using an LLM across six control categories, or presents a structured questionnaire if no documents are uploaded:

   | Category | FAIR-CAM Function | FAIR Component Affected |
   |---|---|---|
   | Governance | Avoidance + Deterrence | Contact Frequency (TEF) |
   | Access Controls | Resistance / Prevention | Vulnerability (Susceptibility) |
   | Integration Risk | Resistance / Prevention | Vulnerability (Susceptibility) |
   | AI Risk | Resistance / Prevention | Vulnerability (Susceptibility) |
   | Data Security | Detection + Response | Loss Magnitude |
   | Availability | Response / Loss Minimization | Loss Magnitude |

   If the vendor does not process your data or integrate with your systems, the assessment short-circuits and returns low/no risk without running the full FAIR calculation.

4. **Residual Risk Calculation** — Applies FAIR-CAM aligned control composites to derive adjusted FAIR inputs, then calculates residual ALE. The formula ensures:
   - A vendor with zero controls always produces residual risk equal to inherent risk (100% ratio)
   - High threat-capability attackers partially overcome resistance controls
   - Risk reduction scales proportionally to control quality across all three composites

5. **Mitigation Recommendations** — Generates up to 7 prioritized control recommendations ranked by actual simulated marginal risk reduction (not static heuristics). Each recommendation includes its FAIR-CAM function label, category, priority, and whether implementing it would bring residual risk within risk appetite.

6. **Report Export** — Generates a detailed XLSX control review workbook and a PDF risk report for the assessment.

## Risk Model

### Inherent Risk

```
Inherent TEF  = contact_frequency × probability_of_action
Inherent Risk = Inherent TEF × 1.0 (no controls) × loss_magnitude
```

### Residual Risk (FAIR-CAM aligned)

Three control composites each affect a different FAIR component:

**Composite 1 — Avoidance + Deterrence (→ Contact Frequency)**
```
effective_tef    = governance × 0.40 + access × 0.20
adj_CF           = contact_frequency × (1 − effective_tef × 0.45)
```

**Composite 2 — Resistance (→ Vulnerability / Susceptibility)**
```
resist_base      = mean(access, integration, ai_risk scores)
effective_RS     = resist_base + governance × 0.40
tc_scale         = 1.0 − threat_capability × 0.20   # high-TC attackers reduce control benefit
adj_resistance   = max(RS_baseline, RS_baseline + effective_RS × 0.40 × tc_scale × (1 − RS_baseline))
vuln_ratio       = (1 − adj_resistance) / (1 − RS_baseline)  # normalized; 1.0 when no controls
```

**Composite 3 — Detection + Response (→ Loss Magnitude)**
```
lm_base          = data_security × 0.50 + availability
effective_LM     = lm_base + governance × 0.20
adj_LM           = loss_magnitude × (1 − effective_LM × 0.40)
```

**Final residual:**
```
Residual TEF  = adj_CF × probability_of_action
Residual Risk = Residual TEF × vuln_ratio × adj_LM
```

Monte Carlo simulation (10,000 iterations) over triangular distributions provides P10/P50/P90 confidence intervals for both inherent and residual risk.

### Attestation Multipliers

Third-party attestations adjust the effective resistance baseline upward:

| Attestation | Multiplier |
|---|---|
| SOC 2 Type II | ×1.25 |
| ISO 27001 | ×1.20 |
| Penetration Test | ×1.15 |
| Other | ×1.10 |
| None | ×1.00 |

Self-attested controls receive a 15% skepticism discount (×0.85).

## Architecture

| File | Purpose |
|---|---|
| `app.py` | Flask web application — routes, job management, SSE progress stream, threading safety |
| `main.py` | Entry point — starts the Flask server on port 5000 |
| `threat_intel.py` | GPT-4o integration for FAIR threat input derivation (per-org scoped) |
| `vendor_risk_engine.py` | FAIR model calculations — inherent risk, FAIR-CAM residual risk, Monte Carlo |
| `doc_review_agent.py` | AI document review, questionnaire logic, marginal-simulation recommendations, XLSX/PDF export |
| `templates/index.html` | Single-page frontend UI |

## Running the Platform

```bash
# Set required API keys
export OPENAI_API_KEY=your_key_here

# Install dependencies
pip install -r requirements.txt

# Start the server
python main.py
```

The platform will be available at `http://127.0.0.1:5000`.

> **Deployment note:** The job store is in-process memory. Run as a **single worker process** (the default `python main.py`). Multi-worker deployments (gunicorn with multiple workers) will not share job state and are not supported without adding a shared backend such as Redis.

## Security

The application is hardened against OWASP Top 10 risks including input validation, per-job access tokens, rate limiting, strict file type whitelisting (PDF, DOCX, TXT, MD), security response headers, structured audit logging, and SSRF prevention.

## Known Limitations

- **In-memory job store** — all in-progress assessments are lost on server restart.
- **Single-worker only** — see deployment note above.
- **No automated test suite** — validation was performed via manual scenario testing across diverse vendor profiles and edge cases.
- **LLM non-determinism** — threat intelligence values and document scores may vary slightly between runs for the same vendor.
