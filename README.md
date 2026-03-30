# VendorRiskAutomation

A web-based vendor risk assessment platform that automates third-party security evaluations using the FAIR (Factor Analysis of Information Risk) quantitative risk model.

## What It Does

Given a vendor name, industry sector, and either uploaded security documents or a completed questionnaire, the platform produces a quantified, dollar-denominated risk assessment with inherent and residual risk ratings and exported reports.

### Assessment Workflow

1. **Threat Intelligence** — Queries GPT-4o to derive FAIR threat inputs (contact frequency, probability of action, threat capability, resistance strength) from public sources (Verizon DBIR, CISA, FBI IC3, MITRE ATT&CK, IBM X-Force).

2. **Inherent Risk Calculation** — Computes Annualized Loss Expectancy (ALE) in USD before any controls are considered, rated Low / Moderate / High against dollar-based risk appetite thresholds auto-derived from company revenue.

3. **Control Assessment** — Reviews vendor security documentation (PDF, DOCX, TXT, MD) using an LLM across six control categories:
   - Access Controls
   - Data Security
   - Integration Risk
   - AI Risk
   - Availability
   - Governance

   If no documents are uploaded, a structured questionnaire is presented instead.

4. **Residual Risk Calculation** — Applies weighted control scores to the FAIR model inputs to calculate residual risk, risk reduction, and an adjusted risk rating (Low / Moderate / High).

5. **Report Export** — Generates a detailed XLSX control review workbook and a PDF risk report for the assessment.

## Architecture

| File | Purpose |
|---|---|
| `app.py` | Flask web application — routes, job management, SSE progress stream |
| `main.py` | Entry point — starts the Flask server on port 5000 |
| `threat_intel.py` | GPT-4o integration for FAIR threat input derivation |
| `vendor_risk_engine.py` | FAIR model calculations — inherent risk, residual risk, control strength scoring |
| `doc_review_agent.py` | AI document review using LLM, questionnaire logic, XLSX/PDF report generation |
| `templates/index.html` | Single-page frontend UI |

## Running the Platform

```bash
# Set required API keys
export OPENAI_API_KEY=your_key_here

# Install dependencies
pip install flask flask-limiter openai werkzeug reportlab openpyxl

# Start the server
python main.py
```

The platform will be available at `http://127.0.0.1:5000`.

## Security

The application is hardened against OWASP Top 10 risks including input validation, per-job access tokens, rate limiting, strict file type whitelisting (PDF, DOCX, TXT, MD), security response headers, structured audit logging, and SSRF prevention.
