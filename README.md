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

The platform uses the FAIR (Factor Analysis of Information Risk) model to produce dollar-denominated risk estimates, with controls applied according to FAIR-CAM v1.0.

**Inherent risk** represents baseline exposure before any vendor controls are considered. It is driven by industry threat intelligence — how frequently threat actors target organizations in this sector, how capable those actors are, how likely they are to succeed, and the potential financial impact to your organization.

**Residual risk** adjusts the inherent baseline by applying the vendor's assessed control posture. Each control category maps to the specific part of the risk model it affects:

- Governance controls reduce threat event frequency — strong policies and oversight make the vendor a less accessible target.
- Access, Integration, and AI Risk controls reduce vulnerability — they lower the likelihood that a threat contact results in a successful breach.
- Data Security and Availability controls limit loss magnitude — they reduce the financial impact when an incident does occur.

A vendor with weak or absent controls will have residual risk near or equal to inherent risk. As control effectiveness improves, residual risk decreases. Third-party attestations (SOC 2 Type II, ISO 27001, penetration tests) provide additional confidence in the vendor's posture and are factored into the residual calculation. Self-attested controls are discounted to reflect the absence of independent verification.

The platform also runs a Monte Carlo simulation across plausible ranges for all threat inputs, producing P10/P50/P90 confidence intervals to reflect the uncertainty inherent in sector-level threat data.

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
