"""
Threat Intelligence — FAIR Input Derivation
Queries GPT-4o to synthesize publicly available, reputable threat data
into FAIR-model inputs for a given industry sector.

Primary sources referenced:
  - Verizon Data Breach Investigations Report (DBIR)
  - CISA Known Exploited Vulnerabilities & Threat Advisories
  - FBI Internet Crime Complaint Center (IC3) Annual Report
  - MITRE ATT&CK frequency & prevalence statistics
  - IBM X-Force Threat Intelligence Index
  - Ponemon / IBM Cost of a Data Breach Report (industry breakdowns)
"""

import json
import logging
import os
import re

import openai

logger = logging.getLogger(__name__)

INDUSTRY_SECTORS = [
    "Financial Services / Banking",
    "Healthcare / Medical",
    "Technology / SaaS",
    "Retail / E-Commerce",
    "Manufacturing / Industrial",
    "Government / Public Sector",
    "Education",
    "Energy / Utilities",
    "Legal / Professional Services",
    "Insurance",
    "Media / Entertainment",
    "Telecommunications",
    "Transportation / Logistics",
    "Hospitality / Travel",
    "Non-Profit / NGO",
    "Other",
]

THREAT_INTEL_SYSTEM_PROMPT = """You are a senior cybersecurity analyst and FAIR risk model expert.
Your role is to derive quantitative FAIR threat model inputs from publicly available,
reputable threat intelligence sources.

You must base your values strictly on published data from:
- Verizon DBIR (Data Breach Investigations Report) — industry-specific attack frequency and actor data
- CISA threat advisories and KEV catalog — exploitability and attacker activity by sector
- FBI IC3 Annual Report — incident frequency and financial impact by industry
- MITRE ATT&CK statistics — technique prevalence and threat actor capability
- IBM X-Force Threat Intelligence Index — industry targeting rates
- Ponemon/IBM Cost of a Data Breach Report — industry breach likelihood and costs

Be precise and cite the specific source and data point that justifies each value."""

THREAT_INTEL_PROMPT = """Based on the most current publicly available threat intelligence,
derive the following FAIR model inputs for the {industry} sector.

Return ONLY valid JSON with exactly this structure:

{{
  "contact_frequency": <float — estimated number of significant threat contact events per year
                        for an organization in this sector, based on DBIR/IC3/CISA attack
                        frequency data. Range typically 4–52.>,

  "probability_of_action": <float 0.0–1.0 — likelihood a threat actor who makes contact
                            will follow through with an attack attempt, based on DBIR
                            actor motivation and success rate data for this sector.>,

  "threat_capability": <float 0.0–1.0 — weighted capability score of the predominant
                        threat actors targeting this sector per MITRE ATT&CK and DBIR.
                        0.3=script kiddie, 0.5=organized crime, 0.7=sophisticated crime,
                        0.9=nation-state APT.>,

  "resistance_strength": <float 0.0–1.0 — baseline industry-average resistance/maturity
                          before vendor-specific controls are applied, based on DBIR
                          breach victim security posture data and CISA sector assessments.>,

  "rationale": {{
    "contact_frequency": "<one sentence: source name, year, and specific data point>",
    "probability_of_action": "<one sentence: source name, year, and specific data point>",
    "threat_capability": "<one sentence: source name, year, and specific data point>",
    "resistance_strength": "<one sentence: source name, year, and specific data point>"
  }},

  "primary_threat_actors": ["<actor type 1>", "<actor type 2>"],
  "top_attack_vectors": ["<vector 1>", "<vector 2>", "<vector 3>"],
  "sources_referenced": ["<source 1>", "<source 2>"]
}}"""


def _get_client() -> openai.OpenAI:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENAI_API_KEY environment variable is not set. "
            "Get your key at https://platform.openai.com/api-keys"
        )
    return openai.OpenAI(api_key=api_key)


def _validate_float(value, name: str, min_val: float, max_val: float, default: float) -> float:
    try:
        f = float(value)
        return max(min_val, min(max_val, f))
    except (TypeError, ValueError):
        logger.warning("Invalid '%s' value '%s' from threat intel, using default %s", name, value, default)
        return default


def _sanitize_text(text: str) -> str:
    return re.sub(r"<[^>]+>", "", str(text)).strip()[:500]


def fetch_threat_intel(industry: str) -> dict:
    """
    Query GPT-4o to derive FAIR inputs from public threat intelligence
    for the given industry sector.

    Returns a dict with:
        contact_frequency, probability_of_action, threat_capability,
        resistance_strength, rationale, primary_threat_actors,
        top_attack_vectors, sources_referenced
    """
    if industry not in INDUSTRY_SECTORS:
        raise ValueError(f"Unknown industry sector: '{industry}'")

    logger.info("Fetching threat intelligence for sector: %s", industry)

    response = _get_client().chat.completions.create(
        model="gpt-4o",
        max_tokens=2000,
        messages=[
            {"role": "system", "content": THREAT_INTEL_SYSTEM_PROMPT},
            {"role": "user",   "content": THREAT_INTEL_PROMPT.format(industry=industry)},
        ],
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()
    raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Threat intel response was not valid JSON: {exc}") from exc

    # Validate and clamp all numeric values
    result = {
        "contact_frequency":    _validate_float(data.get("contact_frequency"),    "contact_frequency",    1,   365, 12),
        "probability_of_action":_validate_float(data.get("probability_of_action"),"probability_of_action",0.05, 1,  0.3),
        "threat_capability":    _validate_float(data.get("threat_capability"),     "threat_capability",    0.1,  1,  0.6),
        "resistance_strength":  _validate_float(data.get("resistance_strength"),   "resistance_strength",  0.05, 1,  0.3),
        "rationale": {
            k: _sanitize_text(v)
            for k, v in (data.get("rationale") or {}).items()
        },
        "primary_threat_actors": [
            _sanitize_text(a) for a in (data.get("primary_threat_actors") or [])[:5]
        ],
        "top_attack_vectors": [
            _sanitize_text(v) for v in (data.get("top_attack_vectors") or [])[:5]
        ],
        "sources_referenced": [
            _sanitize_text(s) for s in (data.get("sources_referenced") or [])[:8]
        ],
        "industry": industry,
    }

    logger.info(
        "Threat intel fetched for '%s': contact_freq=%.1f prob=%.2f capability=%.2f resistance=%.2f",
        industry,
        result["contact_frequency"],
        result["probability_of_action"],
        result["threat_capability"],
        result["resistance_strength"],
    )

    return result
