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

Be precise and cite the specific source and data point that justifies each value.
For each input, provide a plausible range (min/likely/max) reflecting the spread
of observed outcomes across organizations in this sector."""

THREAT_INTEL_PROMPT = """Based on the most current publicly available threat intelligence,
derive the following FAIR model inputs for the {industry} sector.

For each input, provide minimum, most-likely, and maximum values reflecting the plausible
range of outcomes observed across organizations in this sector (not absolute extremes —
the range should represent roughly the 10th to 90th percentile of observed values).

Return ONLY valid JSON with exactly this structure:

{{
  "contact_frequency": {{
    "min":    <float — low-end contact events/year (10th percentile organizations)>,
    "likely": <float — most probable estimate for a typical organization. Range typically 4–52.>,
    "max":    <float — high-end contact events/year (90th percentile organizations)>
  }},

  "probability_of_action": {{
    "min":    <float 0.0–1.0 — lower bound likelihood a threat actor acts on contact>,
    "likely": <float 0.0–1.0 — most probable estimate based on DBIR actor motivation data>,
    "max":    <float 0.0–1.0 — upper bound likelihood>
  }},

  "threat_capability": {{
    "min":    <float 0.0–1.0 — lower bound capability (less sophisticated actors)>,
    "likely": <float 0.0–1.0 — weighted capability of predominant threat actors per MITRE ATT&CK.
               0.3=script kiddie, 0.5=organized crime, 0.7=sophisticated crime, 0.9=nation-state APT.>,
    "max":    <float 0.0–1.0 — upper bound (most sophisticated actors targeting this sector)>
  }},

  "resistance_strength": {{
    "min":    <float 0.0–1.0 — lower bound industry baseline resistance (weakest organizations)>,
    "likely": <float 0.0–1.0 — industry-average resistance/maturity based on DBIR breach victim posture>,
    "max":    <float 0.0–1.0 — upper bound (strongest organizations in this sector)>
  }},

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


def _extract_range(
    value,
    name: str,
    abs_min: float,
    abs_max: float,
    default_min: float,
    default_likely: float,
    default_max: float,
) -> tuple:
    """
    Extract a (min, likely, max) distribution tuple from an LLM response value.
    Accepts either a dict {'min': x, 'likely': y, 'max': z} or a scalar fallback.
    Validates and clamps each bound; ensures min <= likely <= max.
    """
    if isinstance(value, dict):
        likely  = _validate_float(value.get("likely"), f"{name}.likely", abs_min, abs_max, default_likely)
        lo      = _validate_float(value.get("min"),    f"{name}.min",    abs_min, likely,  default_min)
        hi      = _validate_float(value.get("max"),    f"{name}.max",    likely,  abs_max, default_max)
    else:
        # Scalar (legacy or fallback): derive ±30% / +40% plausible range
        likely = _validate_float(value, name, abs_min, abs_max, default_likely)
        lo     = max(abs_min, likely * 0.70)
        hi     = min(abs_max, likely * 1.40)
    return (round(lo, 4), round(likely, 4), round(hi, 4))


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

    # Extract distribution ranges (min, likely, max) for each FAIR input
    cf_dist  = _extract_range(data.get("contact_frequency"),     "contact_frequency",     1,    365, 6,    12,   24)
    poa_dist = _extract_range(data.get("probability_of_action"), "probability_of_action", 0.05, 1,   0.15, 0.30, 0.55)
    tc_dist  = _extract_range(data.get("threat_capability"),     "threat_capability",     0.10, 1,   0.35, 0.60, 0.85)
    rs_dist  = _extract_range(data.get("resistance_strength"),   "resistance_strength",   0.05, 1,   0.15, 0.30, 0.55)

    result = {
        # Scalar likely-values for backward compatibility with downstream code
        "contact_frequency":     cf_dist[1],
        "probability_of_action": poa_dist[1],
        "threat_capability":     tc_dist[1],
        "resistance_strength":   rs_dist[1],
        # Full (min, likely, max) tuples for Monte Carlo simulation
        "distributions": {
            "contact_frequency":     cf_dist,
            "probability_of_action": poa_dist,
            "threat_capability":     tc_dist,
            "resistance_strength":   rs_dist,
        },
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
        "Threat intel fetched for '%s': contact_freq=%.1f (%.1f–%.1f) prob=%.2f capability=%.2f resistance=%.2f",
        industry,
        result["contact_frequency"], cf_dist[0], cf_dist[2],
        result["probability_of_action"],
        result["threat_capability"],
        result["resistance_strength"],
    )

    return result
