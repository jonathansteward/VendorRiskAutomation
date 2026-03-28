"""
Vendor Risk Assessment Platform — Flask Application
Security hardened per OWASP Top 10:
  A01 Broken Access Control     — job ownership tokens, download whitelist
  A02 Cryptographic Failures    — no sensitive data in logs or error responses
  A03 Injection                 — secure_filename, strict input validation
  A04 Insecure Design           — replaced monkey-patch with logging callbacks
  A05 Security Misconfiguration — security headers, no debug mode, port from env
  A06 Vulnerable Components     — file-type whitelist, size limits
  A07 Auth/Auth Failures        — job ownership token required for results/download
  A08 Insecure Deserialization  — JSON schema validation on LLM output
  A09 Logging/Monitoring        — structured audit log for all sensitive operations
  A10 SSRF                      — vendor_website not fetched, stored only
"""

import json
import logging
import os

from dotenv import load_dotenv
load_dotenv()
import queue
import re
import secrets
import shutil
import threading
import uuid
from datetime import date, datetime, timedelta

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

from doc_review_agent import (
    export_control_review_xlsx,
    export_risk_report_pdf,
    review_security_documentation,
)
from threat_intel import INDUSTRY_SECTORS, fetch_threat_intel
from vendor_risk_engine import calculate_inherent_risk, rate_risk

# ---------------------------------------------------------------------------
# Logging — structured audit trail (A09)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
audit_log = logging.getLogger("audit")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB hard limit (A06)
_secret_key = os.environ.get("FLASK_SECRET_KEY")
if not _secret_key:
    import warnings
    warnings.warn(
        "FLASK_SECRET_KEY not set — using an ephemeral key. "
        "Set this environment variable for production deployments.",
        stacklevel=2,
    )
    _secret_key = secrets.token_hex(32)
app.config["SECRET_KEY"] = _secret_key

# Rate limiting — prevent abuse / DoS (A07, A05)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "outputs")

# Strict whitelist — only these extensions are accepted (A03, A06)
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".md", ".docx"}
ALLOWED_DOWNLOAD_TYPES = {"xlsx", "pdf"}  # prevents path traversal via file_type param

# In-memory job store: job_id -> {status, access_token, progress_queue, result, error, output_files}
jobs: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Input validation helpers (A03)
# ---------------------------------------------------------------------------

def _safe_vendor_name(name: str) -> str:
    """Strip characters that could be used for injection or path manipulation."""
    sanitized = re.sub(r"[^\w\s\-\.,&()]", "", name).strip()
    return sanitized[:120]  # hard length cap


def _validate_float(value: str, name: str, min_val: float, max_val: float) -> float:
    """Parse and range-check a float form field, raising ValueError on bad input."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"'{name}' must be a number.")
    if not (min_val <= f <= max_val):
        raise ValueError(f"'{name}' must be between {min_val} and {max_val}.")
    return f


def _allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


# Output reports are deleted after this retention window (A02)
OUTPUT_RETENTION_HOURS = int(os.environ.get("OUTPUT_RETENTION_HOURS", "24"))


def _cleanup_old_outputs():
    """Delete report files in OUTPUT_DIR older than OUTPUT_RETENTION_HOURS."""
    cutoff = datetime.utcnow() - timedelta(hours=OUTPUT_RETENTION_HOURS)
    try:
        for fname in os.listdir(OUTPUT_DIR):
            fpath = os.path.join(OUTPUT_DIR, fname)
            if os.path.isfile(fpath):
                mtime = datetime.utcfromtimestamp(os.path.getmtime(fpath))
                if mtime < cutoff:
                    os.remove(fpath)
                    audit_log.info("OUTPUT_CLEANUP deleted=%s", fname)
    except Exception:
        audit_log.exception("OUTPUT_CLEANUP_ERROR")


# ---------------------------------------------------------------------------
# Security headers (A05)
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/industry-sectors")
def industry_sectors():
    """Return the list of supported industry sectors for the UI dropdown."""
    return jsonify({"sectors": INDUSTRY_SECTORS})


@app.route("/threat-intel", methods=["POST"])
@limiter.limit("20 per hour")
def get_threat_intel():
    """
    Fetch FAIR inputs derived from public threat intelligence for a given sector.
    Loss magnitude is intentionally excluded — it stays user-defined.
    """
    data = request.get_json(silent=True) or {}
    industry = data.get("industry", "").strip()

    if not industry:
        return jsonify({"error": "Industry sector is required."}), 400

    if industry not in INDUSTRY_SECTORS:
        return jsonify({"error": "Invalid industry sector."}), 400

    try:
        result = fetch_threat_intel(industry)
        audit_log.info("THREAT_INTEL_FETCH sector=%s ip=%s", industry, request.remote_addr)
        return jsonify(result)
    except Exception as exc:
        audit_log.exception("THREAT_INTEL_ERROR sector=%s", industry)
        return jsonify({"error": "Failed to fetch threat intelligence. Please try again."}), 500


@app.route("/assess", methods=["POST"])
@limiter.limit("10 per hour")  # cap expensive AI assessments (A07)
def start_assessment():
    """Accept vendor info + uploaded files, kick off background assessment."""
    # --- Input validation (A03) ---
    raw_vendor_name = request.form.get("vendor_name", "").strip()
    if not raw_vendor_name:
        return jsonify({"error": "Vendor name is required."}), 400

    vendor_name = _safe_vendor_name(raw_vendor_name)
    if not vendor_name:
        return jsonify({"error": "Vendor name contains invalid characters."}), 400

    # vendor_website is stored for display only — never fetched (A10 SSRF prevention)
    vendor_website     = request.form.get("vendor_website", "").strip()[:256]
    vendor_description = request.form.get("vendor_description", "").strip()[:1000]

    # Industry sector is required — FAIR threat inputs are fetched automatically (A10)
    industry = request.form.get("industry", "").strip()
    if not industry or industry not in INDUSTRY_SECTORS:
        return jsonify({"error": "A valid industry sector is required."}), 400

    try:
        # product_revenue is used as loss_magnitude — the revenue at risk from this vendor
        product_revenue = _validate_float(request.form.get("product_revenue", "1000000"), "product_revenue", 0, 1_000_000_000)
        # company_revenue is optional — used as a second ARE denominator for materiality
        raw_company_rev = request.form.get("company_revenue", "").strip()
        company_revenue = _validate_float(raw_company_rev, "company_revenue", 0, 1_000_000_000_000) if raw_company_rev else 0.0
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    loss_magnitude = product_revenue

    # --- File handling (A03, A06) — documents are optional; no docs triggers questionnaire ---
    files       = request.files.getlist("documents")
    valid_files = [f for f in files if f and f.filename]

    if len(valid_files) > 20:
        return jsonify({"error": "Maximum 20 files per assessment."}), 400

    job_id         = str(uuid.uuid4())
    job_upload_dir = os.path.join(UPLOAD_DIR, job_id)
    saved_paths    = []

    if valid_files:
        os.makedirs(job_upload_dir, exist_ok=True)
        for f in valid_files:
            if not _allowed_file(f.filename):
                continue
            safe_name = secure_filename(f.filename)
            if not safe_name:
                continue
            dest = os.path.join(job_upload_dir, safe_name)
            f.save(dest)
            saved_paths.append(dest)
            audit_log.info("FILE_UPLOAD job=%s file=%s", job_id, safe_name)

    # doc_folder is None when no files — triggers questionnaire mode in assessment worker
    doc_folder = job_upload_dir if saved_paths else None

    # Per-job access token — caller must present this for all subsequent calls (A01, A07)
    access_token    = secrets.token_urlsafe(32)
    progress_queue: queue.Queue = queue.Queue()

    jobs[job_id] = {
        "status":                "running",
        "access_token":          access_token,
        "progress_queue":        progress_queue,
        "result":                None,
        "error":                 None,
        "output_files":          [],
        "questionnaire_event":   threading.Event(),
        "questionnaire_answers": None,
    }

    audit_log.info(
        "ASSESSMENT_START job=%s vendor=%s industry=%s files=%d ip=%s",
        job_id, vendor_name, industry, len(saved_paths), request.remote_addr,
    )

    thread = threading.Thread(
        target=_run_assessment,
        args=(
            job_id, doc_folder, vendor_name, vendor_website,
            vendor_description, industry, loss_magnitude, company_revenue,
        ),
        daemon=True,
    )
    thread.start()

    # Return job_id AND the access token the client must use for all subsequent calls
    return jsonify({"job_id": job_id, "access_token": access_token})


def _check_access(job_id: str, allow_query_param: bool = False) -> tuple[dict | None, Response | None]:
    """Validate job_id exists and the caller's access token matches (A01).

    allow_query_param should only be True for SSE endpoints where browsers cannot
    send custom headers via EventSource.  All other routes require the
    X-Access-Token header to prevent tokens from leaking into server access logs
    and browser history.
    """
    if job_id not in jobs:
        return None, (jsonify({"error": "Not found."}), 404)

    provided = request.headers.get("X-Access-Token", "")
    if allow_query_param and not provided:
        provided = request.args.get("token", "")

    expected = jobs[job_id].get("access_token", "")

    # Constant-time comparison prevents timing attacks (A02)
    if not secrets.compare_digest(provided, expected):
        audit_log.warning("UNAUTHORIZED_ACCESS job=%s ip=%s", job_id, request.remote_addr)
        return None, (jsonify({"error": "Unauthorized."}), 403)

    return jobs[job_id], None


@app.route("/progress/<job_id>")
def progress_stream(job_id: str):
    """Server-Sent Events stream for real-time progress updates."""
    # EventSource does not support custom headers, so query param is permitted here only (A01)
    job, err = _check_access(job_id, allow_query_param=True)
    if err:
        return err

    def generate():
        q = job["progress_queue"]
        while True:
            try:
                msg = q.get(timeout=60)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") in ("complete", "error"):
                    break
            except queue.Empty:
                yield "data: {\"type\": \"heartbeat\"}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/results/<job_id>")
def get_results(job_id: str):
    """Return the completed assessment results."""
    job, err = _check_access(job_id)
    if err:
        return err

    if job["status"] == "running":
        return jsonify({"status": "running"}), 202
    if job["status"] == "error":
        # Return a generic message — never expose raw exception text to the client (A05)
        return jsonify({"status": "error", "error": "Assessment failed. Check server logs."}), 500
    return jsonify({"status": "complete", "result": job["result"]})


@app.route("/download/<job_id>/<file_type>")
def download_file(job_id: str, file_type: str):
    """Download the XLSX or PDF output for a completed job."""
    # Whitelist file_type to prevent path traversal (A01, A03)
    if file_type not in ALLOWED_DOWNLOAD_TYPES:
        return jsonify({"error": "Invalid file type."}), 400

    job, err = _check_access(job_id)
    if err:
        return err

    if job["status"] != "complete":
        return jsonify({"error": "Results not ready."}), 404

    output_files = job.get("output_files", [])
    matches = [f for f in output_files if f.endswith(f".{file_type}")]
    if not matches:
        return jsonify({"error": "File not found."}), 404

    filename = os.path.basename(matches[0])
    audit_log.info("DOWNLOAD job=%s file_type=%s ip=%s", job_id, file_type, request.remote_addr)
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


# ---------------------------------------------------------------------------
# Questionnaire submission (resumes paused assessment thread)
# ---------------------------------------------------------------------------

@app.route("/questionnaire/<job_id>", methods=["POST"])
def submit_questionnaire(job_id: str):
    """Accept control questionnaire answers and resume the paused assessment."""
    job, err = _check_access(job_id)
    if err:
        return err

    if job["status"] != "questionnaire_required":
        return jsonify({"error": "This assessment is not awaiting a questionnaire."}), 400

    answers = request.get_json(silent=True) or {}
    if not answers:
        return jsonify({"error": "Questionnaire answers are required."}), 400

    job["questionnaire_answers"] = answers
    job["status"] = "running"
    job["questionnaire_event"].set()

    audit_log.info("QUESTIONNAIRE_SUBMIT job=%s ip=%s", job_id, request.remote_addr)
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Background assessment worker
# ---------------------------------------------------------------------------

def _emit(q: queue.Queue, msg_type: str, message: str, data: dict = None):
    payload = {"type": msg_type, "message": message}
    if data:
        payload.update(data)
    q.put(payload)


def _run_assessment(
    job_id: str,
    doc_folder: str | None,
    vendor_name: str,
    vendor_website: str,
    vendor_description: str,
    industry: str,
    loss_magnitude: float,
    company_revenue: float = 0.0,
):
    q    = jobs[job_id]["progress_queue"]
    intel: dict = {}

    # Progress callback — replaces monkey-patching builtins.print (A04)
    def progress(msg: str):
        _emit(q, "progress", msg)
        audit_log.info("PROGRESS job=%s msg=%s", job_id, msg)

    try:
        progress(f"Starting assessment for {vendor_name}...")

        # ── Step 1: Fetch threat intelligence ────────────────────────────────
        progress(f"Fetching {industry} threat intelligence from public sources...")
        try:
            intel = fetch_threat_intel(industry)
        except Exception as exc:
            audit_log.exception("THREAT_INTEL_FETCH_ERROR job=%s industry=%s", job_id, industry)
            raise RuntimeError(
                f"Failed to fetch threat intelligence for '{industry}': {exc}"
            ) from exc

        contact_frequency     = intel["contact_frequency"]
        probability_of_action = intel["probability_of_action"]
        threat_capability     = intel["threat_capability"]
        resistance_strength   = intel["resistance_strength"]

        # ── Step 2: Emit inherent risk immediately (before controls) ─────────
        inherent_risk   = calculate_inherent_risk(
            contact_frequency, probability_of_action, threat_capability, loss_magnitude
        )
        inherent_rating = rate_risk(inherent_risk, loss_magnitude, company_revenue)
        progress(f"Inherent risk: ${inherent_risk:,.0f}/yr ({inherent_rating['rating']})")

        _emit(q, "inherent_risk", "Inherent risk calculated.", {
            "inherent_risk":   inherent_risk,
            "inherent_rating": inherent_rating,
            "threat_intel": {
                "industry":              industry,
                "contact_frequency":     contact_frequency,
                "probability_of_action": probability_of_action,
                "threat_capability":     threat_capability,
                "resistance_strength":   resistance_strength,
                "primary_threat_actors": intel.get("primary_threat_actors", []),
                "top_attack_vectors":    intel.get("top_attack_vectors", []),
                "sources_referenced":    intel.get("sources_referenced", []),
                "rationale":             intel.get("rationale", {}),
            },
        })

        # ── Step 3: Document review (or request questionnaire) ───────────────
        if doc_folder:
            progress("Extracting and reviewing security documentation...")
        else:
            progress("No documents uploaded — questionnaire will be required.")

        assessment = review_security_documentation(
            doc_source=doc_folder,
            vendor_name=vendor_name,
            contact_frequency=contact_frequency,
            probability_of_action=probability_of_action,
            threat_capability=threat_capability,
            resistance_strength=resistance_strength,
            loss_magnitude=loss_magnitude,
            company_revenue=company_revenue,
            progress_callback=progress,
        )

        # ── Step 4: Questionnaire fallback if no documents ───────────────────
        if assessment.get("questionnaire_required"):
            jobs[job_id]["status"] = "questionnaire_required"
            _emit(
                q, "questionnaire",
                "No documents available. Please complete the security control questionnaire.",
                {"categories": assessment["questionnaire_data"]},
            )

            # Wait for questionnaire submission (30-minute timeout)
            got_answers = jobs[job_id]["questionnaire_event"].wait(timeout=1800)
            if not got_answers:
                raise TimeoutError("Questionnaire was not completed within 30 minutes.")

            questionnaire_answers = jobs[job_id]["questionnaire_answers"]
            progress("Questionnaire received. Calculating control scores...")

            assessment = review_security_documentation(
                doc_source=None,
                vendor_name=vendor_name,
                contact_frequency=contact_frequency,
                probability_of_action=probability_of_action,
                threat_capability=threat_capability,
                resistance_strength=resistance_strength,
                loss_magnitude=loss_magnitude,
                company_revenue=company_revenue,
                questionnaire_answers=questionnaire_answers,
                progress_callback=progress,
            )

        # ── Step 5: Export reports ────────────────────────────────────────────
        progress("Generating XLSX control review...")
        safe_name = secure_filename(vendor_name.replace(" ", "_"))
        xlsx_path = os.path.join(OUTPUT_DIR, f"{safe_name}_control_review.xlsx")
        export_control_review_xlsx(assessment, xlsx_path)

        progress("Generating PDF risk report...")
        pdf_path = os.path.join(OUTPUT_DIR, f"{safe_name}_risk_report.pdf")
        export_risk_report_pdf(assessment, pdf_path)

        jobs[job_id]["output_files"] = [xlsx_path, pdf_path]

        risk          = assessment["risk"]
        effectiveness = assessment["control_effectiveness"]

        mitigation_required = risk["residual_rating"].get("rating", "Low") in ("Moderate", "High")

        result_summary = {
            "vendor":            vendor_name,
            "vendor_website":    vendor_website,
            "assessment_date":   assessment.get("assessment_date", date.today().isoformat()),
            "product_revenue":   loss_magnitude,
            "company_revenue":   company_revenue,
            "inherent_risk":     risk["inherent_risk"],
            "inherent_rating":   risk["inherent_rating"],
            "residual_risk":     risk["residual_risk"],
            "residual_rating":   risk["residual_rating"],
            "risk_reduction":    risk["risk_reduction"],
            "reduction_pct": round(
                risk["risk_reduction"] / risk["inherent_risk"] * 100
                if risk["inherent_risk"] else 0, 1
            ),
            "composite_scores":  risk["composite_scores"],
            "adjusted":          risk["adjusted"],
            "control_effectiveness": {
                k: {"score": v["score"], "rating": v["rating"]}
                for k, v in effectiveness.items()
            },
            "gaps":              assessment.get("gaps", []),
            "overall_summary":   assessment.get("overall_summary", ""),
            "fair_inputs":       assessment.get("fair_inputs", {}),
            "threat_intel": {
                "industry":              industry,
                "contact_frequency":     contact_frequency,
                "probability_of_action": probability_of_action,
                "threat_capability":     threat_capability,
                "resistance_strength":   resistance_strength,
                "primary_threat_actors": intel.get("primary_threat_actors", []),
                "top_attack_vectors":    intel.get("top_attack_vectors", []),
                "sources_referenced":    intel.get("sources_referenced", []),
                "rationale":             intel.get("rationale", {}),
            },
            "mitigation_required":        mitigation_required,
            "mitigation_recommendations": assessment.get("mitigation_recommendations", []),
        }

        jobs[job_id]["status"] = "complete"
        jobs[job_id]["result"] = result_summary

        audit_log.info(
            "ASSESSMENT_COMPLETE job=%s vendor=%s industry=%s inherent=%.2f residual=%.2f mitigation_required=%s",
            job_id, vendor_name, industry,
            risk["inherent_risk"], risk["residual_risk"], mitigation_required,
        )

        _emit(q, "complete", "Assessment complete.", {"result": result_summary})

    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"]  = str(exc)
        # Log full exception server-side; send only a generic message to the client (A05)
        audit_log.exception("ASSESSMENT_ERROR job=%s", job_id)
        _emit(q, "error", "Assessment failed. Please check your documents and try again.")

    finally:
        # Clean up uploaded files after assessment completes (A02)
        if doc_folder:
            shutil.rmtree(doc_folder, ignore_errors=True)
        # Purge old output reports to limit sensitive data at rest (A02)
        _cleanup_old_outputs()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Vendor Risk Assessment Platform at http://127.0.0.1:{port}")
    app.run(debug=False, threaded=True, port=port)
