"""
Digital Forensics AI Toolkit (DAFT) - Flask Backend
Enhanced with: RBAC, Case Management, Evidence Hashing,
Metadata Extraction, Log Analysis, AI Assistant, Activity Logging,
Extended Image Analysis, Network Analysis, CSV/JSON Exports
"""

import os
import csv
import json
import uuid
import hashlib
import base64
import tempfile
import logging
from io import BytesIO, StringIO
from datetime import datetime, timedelta
from functools import wraps

import numpy as np
import pandas as pd
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file, flash
)
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import cv2
from PIL import Image
from PIL.ExifTags import TAGS
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.units import inch

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app.secret_key = os.environ.get("SECRET_KEY", "forensics-ai-secret-2024-xK9mP")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory analytics counters
# ---------------------------------------------------------------------------
analytics = {
    "total_scans": 0,
    "intrusions_detected": 0,
    "anomalies_found": 0,
    "images_analyzed": 0,
    "alerts": [],
    "cases": []
}

cases = []

activity_logs = []

# ---------------------------------------------------------------------------
# RBAC — User store with roles
# ---------------------------------------------------------------------------
USERS = {
    "admin":   {"password": "forensics2024", "role": "police"},
    "analyst": {"password": "analyst123",    "role": "analyst"},
    "student": {"password": "student123",    "role": "student"},
}

ROLE_LABELS = {
    "police":  "Law Enforcement",
    "analyst": "Forensic Analyst",
    "student": "Student / Researcher",
}

ROLE_PERMISSIONS = {
    "police":  ["dashboard", "evidence", "intrusion", "image_analysis",
                "cases", "log_analysis", "network_analysis", "reports", "activity_log"],
    "analyst": ["dashboard", "evidence", "intrusion", "image_analysis",
                "cases", "log_analysis", "network_analysis", "reports"],
    "student": ["dashboard", "evidence", "image_analysis"],
}

# ---------------------------------------------------------------------------
# In-memory stores (DB-ready structures)
# ---------------------------------------------------------------------------
activity_log_store: list[dict] = []
cases_store: dict[str, dict] = {}
evidence_registry: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Auth & RBAC decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*allowed_roles):
    """Restrict route to specific roles. Usage: @role_required('police','analyst')"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                return jsonify({
                    "error": "Access denied. Insufficient permissions.",
                    "required": list(allowed_roles),
                    "your_role": session.get("role")
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def permission_required(perm):
    """Restrict route by feature permission name."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            allowed = ROLE_PERMISSIONS.get(session.get("role", "student"), [])
            if perm not in allowed:
                return render_template("403.html",
                                       user=session.get("user", ""),
                                       role=session.get("role", ""),
                                       role_label=session.get("role_label", "")) if request.method == "GET" \
                    else jsonify({"error": f"Your role cannot access '{perm}'"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Activity Logging
# ---------------------------------------------------------------------------
def log_activity(action: str, details: str = "", file_name: str = "", case_id: str = ""):
    entry = {
        "id":        str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":      session.get("user", "anonymous"),
        "role":      session.get("role", "unknown"),
        "action":    action,
        "details":   details,
        "file":      file_name,
        "case_id":   case_id,
        "ip":        request.remote_addr if request else "system",
    }
    activity_log_store.insert(0, entry)
    if len(activity_log_store) > 500:
        activity_log_store.pop()
    return entry


# ---------------------------------------------------------------------------
# Case Management helpers
# ---------------------------------------------------------------------------
def create_case(title: str, description: str, created_by: str) -> dict:
    case_id = "CASE-" + str(uuid.uuid4())[:6].upper()
    case = {
        "case_id":     case_id,
        "title":       title,
        "description": description,
        "status":      "open",
        "created_by":  created_by,
        "created_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "evidence":    [],
        "notes":       [],
    }
    cases_store[case_id] = case
    log_activity("case_created", f"Created: {title}", case_id=case_id)
    return case


def update_case_status(case_id: str, status: str) -> dict | None:
    if status not in {"open", "investigating", "closed"}:
        return None
    case = cases_store.get(case_id)
    if not case:
        return None
    case["status"] = status
    case["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_activity("case_updated", f"Status → {status}", case_id=case_id)
    return case


def attach_evidence_to_case(case_id: str, evidence_id: str) -> bool:
    case = cases_store.get(case_id)
    if not case:
        return False
    if evidence_id not in case["evidence"]:
        case["evidence"].append(evidence_id)
        case["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return True


def add_case_note(case_id: str, note_text: str) -> bool:
    case = cases_store.get(case_id)
    if not case:
        return False
    case["notes"].append({
        "text": note_text,
        "by":   session.get("user", "unknown"),
        "at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return True


# ---------------------------------------------------------------------------
# File Hashing & Evidence Registration
# ---------------------------------------------------------------------------
def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def hash_file_bytes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def register_evidence(file_bytes: bytes, filename: str,
                      file_type: str, case_id: str = "") -> dict:
    hashes = hash_file_bytes(file_bytes)
    evidence_id = "EV-" + str(uuid.uuid4())[:8].upper()
    record = {
        "evidence_id":     evidence_id,
        "filename":        filename,
        "file_type":       file_type,
        "size_bytes":      len(file_bytes),
        "size_human":      _human_size(len(file_bytes)),
        "md5":             hashes["md5"],
        "sha256":          hashes["sha256"],
        "uploaded_by":     session.get("user", "unknown"),
        "uploaded_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "case_id":         case_id,
        "integrity":       "verified",
        "original_sha256": hashes["sha256"],
    }
    evidence_registry[evidence_id] = record
    if case_id:
        attach_evidence_to_case(case_id, evidence_id)
    log_activity("evidence_uploaded", f"File: {filename}", file_name=filename, case_id=case_id)
    return record


def check_integrity(evidence_id: str, current_bytes: bytes) -> dict:
    record = evidence_registry.get(evidence_id)
    if not record:
        return {"error": "Evidence not found"}
    current = hash_file_bytes(current_bytes)
    is_safe = current["sha256"] == record["original_sha256"]
    record["integrity"] = "safe" if is_safe else "tampered"
    log_activity("integrity_check",
                 f"Evidence {evidence_id}: {'safe' if is_safe else 'TAMPERED'}",
                 case_id=record.get("case_id", ""))
    return {
        "evidence_id":     evidence_id,
        "status":          "safe" if is_safe else "tampered",
        "match":           is_safe,
        "original_sha256": record["original_sha256"],
        "current_sha256":  current["sha256"],
        "original_md5":    record["md5"],
        "current_md5":     current["md5"],
    }


# ---------------------------------------------------------------------------
# Metadata Extraction
# ---------------------------------------------------------------------------
def _parse_gps(gps_info: dict) -> dict | None:
    try:
        def to_deg(vals):
            d, m, s = vals
            return float(d) + float(m) / 60 + float(s) / 3600
        lat = to_deg(gps_info.get(2, (0, 0, 0)))
        lon = to_deg(gps_info.get(4, (0, 0, 0)))
        lat *= -1 if gps_info.get(1, "N") == "S" else 1
        lon *= -1 if gps_info.get(3, "E") == "W" else 1
        return {"latitude": round(lat, 6), "longitude": round(lon, 6)}
    except Exception:
        return None


def extract_image_metadata(file_bytes: bytes, filename: str) -> dict:
    meta = {
        "filename": filename,
        "size_bytes": len(file_bytes),
        "size_human": _human_size(len(file_bytes)),
        "exif": {}, "dimensions": None, "format": None, "mode": None, "gps": None,
    }
    try:
        img = Image.open(BytesIO(file_bytes))
        meta["dimensions"] = f"{img.width} × {img.height}"
        meta["format"]     = img.format or "Unknown"
        meta["mode"]       = img.mode
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if tag == "GPSInfo":
                    meta["gps"] = _parse_gps(value)
                    continue
                if isinstance(value, (str, int, float)):
                    meta["exif"][tag] = str(value)
                elif isinstance(value, bytes):
                    meta["exif"][tag] = value.hex()[:40]
    except Exception as e:
        meta["error"] = str(e)
    return meta


def extract_file_metadata(file_bytes: bytes, filename: str, mime_type: str) -> dict:
    if mime_type.startswith("image/"):
        return extract_image_metadata(file_bytes, filename)
    if mime_type in ("text/csv", "text/plain"):
        try:
            text  = file_bytes.decode("utf-8", errors="replace")
            lines = text.splitlines()
            return {
                "filename": filename, "size_bytes": len(file_bytes),
                "size_human": _human_size(len(file_bytes)),
                "line_count": len(lines), "char_count": len(text),
                "preview": "\n".join(lines[:5]),
            }
        except Exception as e:
            return {"filename": filename, "error": str(e)}
    return {"filename": filename, "size_bytes": len(file_bytes),
            "size_human": _human_size(len(file_bytes)), "mime_type": mime_type}


# ---------------------------------------------------------------------------
# Extended Analysis Stubs
# ---------------------------------------------------------------------------
def detect_deepfake(file_bytes: bytes) -> dict:
    """Placeholder — integrate EfficientNet / XceptionNet weights here."""
    return {
        "method": "deepfake_detection", "status": "stub",
        "score": 0.0, "verdict": "ANALYSIS_PENDING", "confidence": 0.0,
        "note": "Integrate a pretrained model (e.g., FaceForensics++ weights).",
    }


def detect_copy_move(file_bytes: bytes) -> dict:
    """Placeholder — implement SIFT keypoint or DCT block-matching here."""
    return {
        "method": "copy_move_detection", "status": "stub",
        "regions": [], "verdict": "ANALYSIS_PENDING",
        "note": "Implement SIFT-based or DCT block-matching approach.",
    }


def detect_noise_inconsistency(file_bytes: bytes) -> dict:
    """Placeholder — implement SRM or wavelet analysis here."""
    return {
        "method": "noise_inconsistency", "status": "stub",
        "verdict": "ANALYSIS_PENDING",
        "note": "Implement SRM or wavelet-based noise analysis.",
    }


# ---------------------------------------------------------------------------
# Log Analysis (rule-based)
# ---------------------------------------------------------------------------
LOG_RULES = [
    {"pattern": "failed password",        "severity": "HIGH",     "label": "Brute-force attempt"},
    {"pattern": "authentication failure", "severity": "HIGH",     "label": "Auth failure"},
    {"pattern": "select * from",          "severity": "CRITICAL", "label": "SQL injection attempt"},
    {"pattern": "union select",           "severity": "CRITICAL", "label": "SQL injection (UNION)"},
    {"pattern": "../",                    "severity": "HIGH",     "label": "Path traversal"},
    {"pattern": "<script",                "severity": "HIGH",     "label": "XSS attempt"},
    {"pattern": "port scan",              "severity": "MEDIUM",   "label": "Port scan detected"},
    {"pattern": "connection refused",     "severity": "LOW",      "label": "Connection refused"},
    {"pattern": "root login",             "severity": "CRITICAL", "label": "Root login attempt"},
    {"pattern": "\\x00",                  "severity": "HIGH",     "label": "Null byte injection"},
    {"pattern": "permission denied",      "severity": "MEDIUM",   "label": "Permission denied"},
    {"pattern": "invalid user",           "severity": "HIGH",     "label": "Invalid user login"},
]


def analyze_log_file(log_text: str) -> dict:
    lines = log_text.splitlines()
    findings = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for i, line in enumerate(lines, 1):
        lower = line.lower()
        for rule in LOG_RULES:
            if rule["pattern"] in lower:
                findings.append({
                    "line": i, "severity": rule["severity"],
                    "label": rule["label"], "excerpt": line[:120],
                })
                counts[rule["severity"]] += 1
    risk = "LOW"
    if counts["CRITICAL"] > 0:     risk = "CRITICAL"
    elif counts["HIGH"] > 2:       risk = "HIGH"
    elif counts["HIGH"] > 0:       risk = "MEDIUM"
    log_activity("log_analysis", f"{len(findings)} findings in {len(lines)} lines")
    return {
        "total_lines": len(lines), "findings": findings[:50],
        "counts": counts, "overall_risk": risk,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Network Analysis (simulation)
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS_NET = {22, 23, 3389, 4444, 5900, 6667, 31337, 8080, 9001}


def analyze_network_traffic(packets: list[dict]) -> dict:
    suspicious = []
    ip_counts: dict[str, int] = {}
    for pkt in packets:
        src = pkt.get("src", "")
        dst_port = int(pkt.get("port", 0))
        ip_counts[src] = ip_counts.get(src, 0) + 1
        if dst_port in SUSPICIOUS_PORTS_NET:
            suspicious.append({
                "type": "suspicious_port", "src": src, "port": dst_port,
                "detail": f"Traffic to high-risk port {dst_port}",
            })
    for ip, count in ip_counts.items():
        if count > 50:
            suspicious.append({
                "type": "port_scan_heuristic", "src": ip, "count": count,
                "detail": f"High packet rate: {count} packets from {ip}",
            })
    return {
        "total_packets": len(packets), "unique_sources": len(ip_counts),
        "suspicious_events": suspicious, "risk_score": min(len(suspicious) * 10, 100),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# AI Chat Assistant (rule-based)
# ---------------------------------------------------------------------------
FORENSICS_KB = {
    "ela": "Error Level Analysis (ELA) re-saves an image at a known compression quality "
           "and computes pixel-level differences. Tampered regions show higher error levels "
           "because they were compressed differently from the rest of the image.",
    "isolation forest": "Isolation Forest is an unsupervised ML algorithm that detects anomalies "
                        "by randomly partitioning data. Points isolated quickly (short paths) are "
                        "flagged as anomalies. DAFT uses it with 10% contamination factor.",
    "md5": "MD5 produces a 128-bit hash used for file integrity verification. It is fast but "
           "not collision-resistant for security use — prefer SHA-256 for evidence.",
    "sha256": "SHA-256 produces a 256-bit hash. It is the forensic standard for evidence integrity "
              "and chain of custody. DAFT generates SHA-256 for every registered evidence file.",
    "exif": "EXIF (Exchangeable Image File Format) stores metadata embedded in photos: GPS coordinates, "
            "device make/model, date/time, and camera settings. DAFT extracts this automatically.",
    "intrusion": "Intrusion Detection Systems (IDS) monitor network traffic for suspicious patterns. "
                 "DAFT uses a Random Forest classifier plus rule-based signatures for known attack types.",
    "dos": "A Denial of Service (DoS) attack floods a target to exhaust resources. Indicators: "
           "very high packet counts, oversized packets, high byte rates from a single source.",
    "sql injection": "SQL injection inserts malicious SQL into input fields. Look for patterns like "
                     "SELECT *, UNION SELECT, DROP TABLE in logs. DAFT's log analyzer flags these.",
    "chain of custody": "Chain of custody documents every person who handled evidence and what was done. "
                        "Cryptographic hashes (SHA-256) provide mathematical proof files were not altered.",
    "deepfake": "Deepfakes use GANs to swap faces in media. Detection looks for blending artifacts, "
                "unnatural blinking, and frequency-domain anomalies. DAFT has placeholder stubs ready.",
    "random forest": "Random Forest is an ensemble of 100 decision trees. DAFT uses it for intrusion "
                     "detection — trees vote on whether traffic is NORMAL or ATTACK.",
    "case": "Case management in DAFT lets you create forensic cases, attach evidence files, track status "
            "(open → investigating → closed), and add investigator notes.",
    "hash": "Hashing in DAFT generates MD5 and SHA-256 for every uploaded file. Run an integrity check "
            "later to confirm the file has not been tampered with since registration.",
}


def ask_assistant(question: str) -> dict:
    q_lower = question.lower()
    matched = [(kw, ans) for kw, ans in FORENSICS_KB.items() if kw in q_lower]
    if matched:
        kw, ans = matched[0]
        return {"question": question, "answer": ans, "topic": kw,
                "source": "DAFT Knowledge Base", "matched": len(matched)}
    return {
        "question": question,
        "answer": ("I can answer questions about: ELA, Isolation Forest, MD5, SHA-256, EXIF, "
                   "intrusion detection, DoS, SQL injection, chain of custody, deepfakes, "
                   "Random Forest, case management, and hashing. Try one of those topics."),
        "topic": "general", "source": "DAFT Knowledge Base", "matched": 0,
    }


# ---------------------------------------------------------------------------
# Supabase-ready storage stubs
# ---------------------------------------------------------------------------
def save_user(username: str, password_hash: str, role: str) -> dict:
    """STUB — replace with: supabase.table('users').insert({...}).execute()"""
    return {"table": "users", "username": username, "role": role, "status": "stub"}


def save_case(case: dict) -> dict:
    """STUB — replace with: supabase.table('cases').insert(case).execute()"""
    return {"table": "cases", "case_id": case.get("case_id"), "status": "stub"}


def save_evidence(evidence: dict) -> dict:
    """STUB — replace with: supabase.table('evidence').insert(evidence).execute()"""
    return {"table": "evidence", "evidence_id": evidence.get("evidence_id"), "status": "stub"}


# ---------------------------------------------------------------------------
# Pre-trained ML models (fitted at startup with synthetic data)
# ---------------------------------------------------------------------------
def build_isolation_forest():
    rng = np.random.RandomState(42)
    X = rng.randn(500, 6) * np.array([10, 5, 100, 50, 1000, 200])
    X += np.array([50, 20, 500, 100, 5000, 800])
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    model.fit(X)
    return model


def build_random_forest():
    rng = np.random.RandomState(0)
    X = rng.randn(600, 8)
    y = (X[:, 0] + X[:, 2] > 1.5).astype(int)
    model = RandomForestClassifier(n_estimators=100, random_state=0)
    model.fit(X, y)
    scaler = StandardScaler()
    scaler.fit(X)
    return model, scaler


ISO_FOREST = build_isolation_forest()
RF_MODEL, RF_SCALER = build_random_forest()

FEATURE_NAMES = [
    "packet_size", "duration", "byte_count",
    "port_number", "connection_count", "response_time"
]

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5900, 6667, 31337}

# ===========================================================================
# ROUTES — Auth
# ===========================================================================
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_record = USERS.get(username)
        if user_record and user_record["password"] == password:
            session["user"]       = username
            session["role"]       = user_record["role"]
            session["role_label"] = ROLE_LABELS[user_record["role"]]
            session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_activity("login", f"Login from {request.remote_addr}")
            activity_logs.append({
                "user": username,
                "action": "Logged in",
                "time": datetime.now().strftime("%H:%M:%S")
            })
            logger.info(f"User '{username}' (role={user_record['role']}) logged in.")
            session["user"] = username
            session["role"] = user_record["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials. Please try again."
        logger.warning(f"Failed login attempt for '{username}'")
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    log_activity("logout", "User logged out")
    session.clear()
    return redirect(url_for("login"))


# ===========================================================================
# ROUTES — Dashboard
# ===========================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    if "user" not in session:
        return redirect("/")
    role = session.get('role', 'student')  # safe fallback
    return render_template(
    "dashboard.html",
    analytics=analytics,
    user=session.get("user"),
    role=role,
    role_label=session.get("role_label", "Student")
)

# ===========================================================================
# ROUTES — Evidence Analyzer
# ===========================================================================
@app.route("/evidence")
@login_required
def evidence():
    return render_template("evidence.html", user=session["user"],
                           role=session.get("role"),
                           role_label=session.get("role_label", ""),
                           cases=list(cases_store.values()))


@app.route("/api/analyze-evidence", methods=["POST"])
@login_required
def analyze_evidence():
    records = []
    use_synthetic = False
    case_id = request.form.get("case_id", "")

    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        file_bytes = file.read()

        # Hash and register evidence
        mime = file.content_type or "text/csv"
        ev_record = register_evidence(file_bytes, file.filename, mime, case_id)

        try:
            df = pd.read_csv(BytesIO(file_bytes))
            numeric_cols = df.select_dtypes(include=[np.number]).columns[:6]
            if len(numeric_cols) < 2:
                return jsonify({"error": "CSV must have at least 2 numeric columns."}), 400
            X = df[numeric_cols].fillna(0).values
            if X.shape[1] < 6:
                pad = np.zeros((X.shape[0], 6 - X.shape[1]))
                X = np.hstack([X, pad])
            col_names = list(numeric_cols) + [f"feat_{i}" for i in range(6 - len(numeric_cols))]
        except Exception as e:
            return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400
    else:
        use_synthetic = True
        ev_record = None
        rng = np.random.RandomState()
        n = 40
        X_normal  = rng.randn(n - 5, 6) * np.array([10, 5, 100, 50, 1000, 200])
        X_normal  += np.array([50, 20, 500, 100, 5000, 800])
        X_anomaly = rng.randn(5, 6) * np.array([80, 40, 800, 400, 8000, 1600])
        X_anomaly += np.array([500, 200, 5000, 1000, 50000, 8000])
        X = np.vstack([X_normal, X_anomaly])
        col_names = FEATURE_NAMES

    preds  = ISO_FOREST.predict(X)
    scores = ISO_FOREST.score_samples(X)

    anomaly_count = int(np.sum(preds == -1))
    analytics["total_scans"]    += 1
    analytics["anomalies_found"] += anomaly_count

    for i, (pred, score) in enumerate(zip(preds, scores)):
        row = {col: float(round(X[i, j], 3)) for j, col in enumerate(col_names[:6])}
        row["anomaly_score"] = float(round(score, 4))
        row["status"]        = "ANOMALY" if pred == -1 else "NORMAL"
        row["record_id"]     = i + 1
        records.append(row)

    if anomaly_count > 0:
        analytics["alerts"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg":  f"Evidence scan: {anomaly_count} anomalies detected",
            "type": "warning"
        })
        analytics["alerts"] = analytics["alerts"][:20]

    log_activity("evidence_analysis",
                 f"{anomaly_count} anomalies in {len(records)} records",
                 case_id=case_id)

    return jsonify({
        "records": records, "total": len(records),
        "anomalies": anomaly_count, "synthetic": use_synthetic,
        "columns": col_names[:6],
        "evidence_id": ev_record["evidence_id"] if ev_record else None,
        "hashes": {"md5": ev_record["md5"], "sha256": ev_record["sha256"]} if ev_record else None,
    })


# ===========================================================================
# ROUTES — Intrusion Detection
# ===========================================================================
@app.route("/intrusion")
@login_required
@permission_required("intrusion")
def intrusion():
    return render_template("intrusion.html", user=session["user"],
                           role=session.get("role"),
                           role_label=session.get("role_label", ""))


@app.route("/api/detect-intrusion", methods=["POST"])
@login_required
@permission_required("intrusion")
def detect_intrusion():
    data = request.get_json(force=True)
    try:
        features = [
            float(data.get("src_port", 80)),
            float(data.get("dst_port", 443)),
            float(data.get("packet_size", 500)),
            float(data.get("duration", 1.0)),
            float(data.get("byte_count", 1000)),
            float(data.get("connection_count", 10)),
            float(data.get("protocol", 1)),
            float(data.get("flags", 0))
        ]
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400

    X = np.array([features])
    X_scaled = RF_SCALER.transform(X)
    pred       = int(RF_MODEL.predict(X_scaled)[0])
    proba      = RF_MODEL.predict_proba(X_scaled)[0]
    confidence = float(round(max(proba) * 100, 2))

    rule_triggered = None
    src_port = features[0]
    dst_port = features[1]
    pkt_size = features[2]
    flags    = features[7]

    if dst_port in SUSPICIOUS_PORTS:
        pred = 1
        rule_triggered = f"Suspicious destination port: {int(dst_port)}"
    elif pkt_size > 65000:
        pred = 1
        rule_triggered = "Oversized packet (potential DoS)"
    elif flags >= 60:
        pred = 1
        rule_triggered = "Unusual TCP flags (potential scan)"

    label    = "ATTACK" if pred == 1 else "NORMAL"
    severity = "HIGH" if pred == 1 and confidence > 80 else ("MEDIUM" if pred == 1 else "LOW")

    if pred == 1:
        analytics["intrusions_detected"] += 1
        analytics["alerts"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg":  f"Intrusion detected: {label} (confidence {confidence}%)",
            "type": "danger"
        })
        analytics["alerts"] = analytics["alerts"][:20]

    analytics["total_scans"] += 1
    log_activity("intrusion_detection", f"{label} — confidence {confidence}%")

    return jsonify({
        "prediction": label, "confidence": confidence,
        "severity": severity, "rule_triggered": rule_triggered,
        "features": {
            "src_port": int(features[0]), "dst_port": int(features[1]),
            "packet_size": features[2], "duration": features[3],
            "byte_count": features[4], "connection_count": features[5],
            "protocol": "TCP" if features[6] == 1 else "UDP",
            "flags": int(features[7])
        }
    })


# ===========================================================================
# ROUTES — Image Forgery Detection
# ===========================================================================
@app.route("/image-analysis")
@login_required
def image_analysis():
    return render_template("image_analysis.html", user=session["user"],
                           role=session.get("role"),
                           role_label=session.get("role_label", ""),
                           cases=list(cases_store.values()))


@app.route("/api/analyze-image", methods=["POST"])
@login_required
def analyze_image():
    if "image" not in request.files or not request.files["image"].filename:
        return jsonify({"error": "No image file provided."}), 400

    file = request.files["image"]
    allowed = {"png", "jpg", "jpeg", "bmp", "tiff"}
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in allowed:
        return jsonify({"error": f"Unsupported format. Allowed: {', '.join(allowed)}"}), 400

    case_id = request.form.get("case_id", "")

    try:
        img_bytes = file.read()

        # Hash & register
        ev_record = register_evidence(img_bytes, file.filename,
                                      f"image/{ext}", case_id)

        # Extract metadata
        meta = extract_image_metadata(img_bytes, file.filename)

        pil_img = Image.open(BytesIO(img_bytes)).convert("RGB")
        pil_img.thumbnail((800, 800), Image.LANCZOS)
        img_np = np.array(pil_img)
        gray   = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        ela_score    = _ela_score(pil_img)
        edges        = cv2.Canny(gray, 100, 200)
        edge_density = float(np.sum(edges > 0)) / edges.size
        laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        hist = cv2.calcHist([gray], [0], None, [256], [0, 256]).flatten()
        hist = hist / (hist.sum() + 1e-9)
        entropy = float(-np.sum(hist * np.log2(hist + 1e-9)))

        ela_norm     = min(ela_score * 2, 100)
        edge_norm    = min(edge_density * 500, 100)
        noise_norm   = min(laplacian_var / 500 * 100, 100)
        entropy_norm = min((entropy / 8) * 100, 100)

        tampering_pct = round(
            0.40 * ela_norm + 0.25 * edge_norm +
            0.20 * noise_norm + 0.15 * (100 - entropy_norm), 2
        )
        tampering_pct = max(0.0, min(100.0, tampering_pct))

        if tampering_pct >= 65:
            verdict = "HIGH RISK - Likely Forged"
            verdict_color = "#ef4444"
        elif tampering_pct >= 35:
            verdict = "MEDIUM RISK - Possibly Altered"
            verdict_color = "#f59e0b"
        else:
            verdict = "LOW RISK - Likely Authentic"
            verdict_color = "#10b981"

        analytics["images_analyzed"] += 1
        analytics["total_scans"]     += 1

        if tampering_pct >= 65:
            analytics["alerts"].insert(0, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "msg":  f"Image forgery: HIGH RISK detected ({tampering_pct:.0f}%)",
                "type": "danger"
            })
            analytics["alerts"] = analytics["alerts"][:20]

        ela_b64 = _generate_ela_image(pil_img)
        buf = BytesIO()
        pil_img.save(buf, format="JPEG", quality=85)
        orig_b64 = base64.b64encode(buf.getvalue()).decode()

        log_activity("image_analysis",
                     f"Tampering={tampering_pct}% — {verdict}",
                     file_name=file.filename, case_id=case_id)

        return jsonify({
            "tampering_score": tampering_pct,
            "verdict": verdict, "verdict_color": verdict_color,
            "metrics": {
                "ela_score":      round(ela_score, 3),
                "edge_density":   round(edge_density * 100, 3),
                "noise_variance": round(laplacian_var, 2),
                "entropy":        round(entropy, 3)
            },
            "ela_image":       ela_b64,
            "original_image":  orig_b64,
            "dimensions":      f"{pil_img.width} × {pil_img.height}",
            "format":          ext.upper(),
            "evidence_id":     ev_record["evidence_id"],
            "hashes":          {"md5": ev_record["md5"], "sha256": ev_record["sha256"]},
            "metadata":        meta,
        })

    except Exception as e:
        logger.error(f"Image analysis error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


def _ela_score(pil_img: Image.Image) -> float:
    buf = BytesIO()
    pil_img.save(buf, format="JPEG", quality=75)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")
    ela = np.abs(np.array(pil_img, dtype=np.float32) - np.array(compressed, dtype=np.float32))
    return float(ela.mean())


def _generate_ela_image(pil_img: Image.Image) -> str:
    buf = BytesIO()
    pil_img.save(buf, format="JPEG", quality=75)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")
    ela_arr    = np.abs(np.array(pil_img, dtype=np.float32) - np.array(compressed, dtype=np.float32))
    ela_scaled = (ela_arr / (ela_arr.max() + 1e-9) * 255).astype(np.uint8)
    ela_img    = Image.fromarray(ela_scaled)
    out_buf    = BytesIO()
    ela_img.save(out_buf, format="PNG")
    return base64.b64encode(out_buf.getvalue()).decode()


# ===========================================================================
# ROUTES — Case Management
# ===========================================================================
@app.route("/cases")
@login_required
def view_cases():
    return render_template("cases.html", cases=cases)


@app.route("/create_case", methods=["POST"])
@login_required
def create_case():
    case_name = request.form.get("case_name")
    case_id = len(cases) + 1
    cases.append({"id": case_id, "name": case_name, "status": "Open", "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    analytics["cases"].append(case_name)
    activity_logs.append({
        "user": session["user"],
        "action": f"Created case '{case_name}'",
        "time": datetime.now().strftime("%H:%M:%S")
    })
    return redirect("/cases")


@app.route("/logs")
@login_required
def logs():
    return render_template("logs.html", logs=activity_logs)


@app.route("/api/cases", methods=["GET"])
@login_required
@permission_required("cases")
def api_get_cases():
    return jsonify(list(cases_store.values()))


@app.route("/api/cases/create", methods=["POST"])
@login_required
@permission_required("cases")
def api_create_case():
    data  = request.get_json(force=True)
    title = data.get("title", "").strip()
    desc  = data.get("description", "").strip()
    if not title:
        return jsonify({"error": "Case title is required."}), 400
    case = create_case(title, desc, session["user"])
    analytics["total_scans"] += 1
    return jsonify(case), 201


@app.route("/api/cases/<case_id>", methods=["GET"])
@login_required
@permission_required("cases")
def api_get_case(case_id):
    case = cases_store.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case)


@app.route("/api/cases/<case_id>/status", methods=["PATCH"])
@login_required
@permission_required("cases")
def api_update_case_status(case_id):
    data   = request.get_json(force=True)
    result = update_case_status(case_id, data.get("status", ""))
    if not result:
        return jsonify({"error": "Invalid case ID or status"}), 400
    return jsonify(result)


@app.route("/api/cases/<case_id>/note", methods=["POST"])
@login_required
@permission_required("cases")
def api_add_case_note(case_id):
    data = request.get_json(force=True)
    note = data.get("note", "").strip()
    if not note:
        return jsonify({"error": "Note text required"}), 400
    ok = add_case_note(case_id, note)
    if not ok:
        return jsonify({"error": "Case not found"}), 404
    log_activity("note_added", f"Note on {case_id}", case_id=case_id)
    return jsonify({"status": "ok"})


# ===========================================================================
# ROUTES — Evidence Registry & Hashing
# ===========================================================================
@app.route("/api/evidence/register", methods=["POST"])
@login_required
def api_register_evidence():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file       = request.files["file"]
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400
    case_id    = request.form.get("case_id", "")
    file_bytes = file.read()
    mime       = file.content_type or "application/octet-stream"
    if len(file_bytes) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5 MB)"}), 400
    record = register_evidence(file_bytes, file.filename, mime, case_id)
    activity_logs.append({
        "user": session["user"],
        "action": f"Uploaded file: {file.filename}",
        "time": datetime.now().strftime("%H:%M:%S")
    })
    analytics["total_scans"] += 1
    return jsonify(record), 201


@app.route("/api/evidence/integrity", methods=["POST"])
@login_required
def api_check_integrity():
    evidence_id = request.form.get("evidence_id", "")
    if "file" not in request.files or not evidence_id:
        return jsonify({"error": "Provide file and evidence_id"}), 400
    result = check_integrity(evidence_id, request.files["file"].read())
    return jsonify(result)


@app.route("/api/evidence/list", methods=["GET"])
@login_required
def api_list_evidence():
    return jsonify(list(evidence_registry.values()))


@app.route("/api/evidence/metadata", methods=["POST"])
@login_required
def api_extract_metadata():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file       = request.files["file"]
    file_bytes = file.read()
    mime       = file.content_type or "application/octet-stream"
    meta = extract_file_metadata(file_bytes, file.filename, mime)
    log_activity("metadata_extracted", f"File: {file.filename}", file_name=file.filename)
    return jsonify(meta)


# ===========================================================================
# ROUTES — Log Analysis
# ===========================================================================
@app.route("/log-analysis")
@login_required
@permission_required("log_analysis")
def log_analysis():
    return render_template("log_analysis.html", user=session["user"],
                           role=session.get("role"),
                           role_label=session.get("role_label", ""))


@app.route("/api/analyze-log", methods=["POST"])
@login_required
@permission_required("log_analysis")
def api_analyze_log():
    if "file" in request.files and request.files["file"].filename:
        raw = request.files["file"].read().decode("utf-8", errors="replace")
    elif request.is_json:
        raw = request.get_json().get("text", "")
    else:
        return jsonify({"error": "Provide a log file or 'text' in JSON body"}), 400

    if not raw.strip():
        return jsonify({"error": "Empty log content"}), 400

    result = analyze_log_file(raw)
    analytics["total_scans"] += 1

    if result["overall_risk"] in ("HIGH", "CRITICAL"):
        analytics["alerts"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg":  f"Log analysis: {result['overall_risk']} risk — {len(result['findings'])} findings",
            "type": "danger"
        })
        analytics["alerts"] = analytics["alerts"][:20]

    return jsonify(result)


# ===========================================================================
# ROUTES — Network Analysis
# ===========================================================================
@app.route("/api/analyze-network", methods=["POST"])
@login_required
@permission_required("network_analysis")
def api_analyze_network():
    data    = request.get_json(force=True)
    packets = data.get("packets", [])
    if not isinstance(packets, list):
        return jsonify({"error": "Expected 'packets' as a list"}), 400
    result = analyze_network_traffic(packets)
    analytics["total_scans"] += 1
    return jsonify(result)


# ===========================================================================
# ROUTES — Extended Image Analysis
# ===========================================================================
@app.route("/api/analyze-image-extended", methods=["POST"])
@login_required
@role_required("police", "analyst")
def api_analyze_image_extended():
    if "image" not in request.files:
        return jsonify({"error": "No image provided"}), 400
    file_bytes    = request.files["image"].read()
    analysis_type = request.form.get("type", "all")
    result        = {"requested": analysis_type}
    if analysis_type in ("deepfake", "all"):
        result["deepfake"]            = detect_deepfake(file_bytes)
    if analysis_type in ("copy_move", "all"):
        result["copy_move"]           = detect_copy_move(file_bytes)
    if analysis_type in ("noise", "all"):
        result["noise_inconsistency"] = detect_noise_inconsistency(file_bytes)
    log_activity("extended_image_analysis", f"Type: {analysis_type}",
                 file_name=request.files["image"].filename)
    return jsonify(result)


# ===========================================================================
# ROUTES — AI Assistant
# ===========================================================================
@app.route("/api/ask", methods=["POST"])
@login_required
def api_ask():
    data     = request.get_json(force=True)
    question = data.get("question", "").strip()
    if not question:
        return jsonify({"error": "Question is required"}), 400
    if len(question) > 500:
        return jsonify({"error": "Question too long (max 500 chars)"}), 400
    log_activity("assistant_query", f"Q: {question[:80]}")
    return jsonify(ask_assistant(question))


# ===========================================================================
# ROUTES — Activity Log
# ===========================================================================
@app.route("/api/activity-log")
@login_required
@role_required("police")
def api_activity_log():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(activity_log_store[:limit])


# ===========================================================================
# ROUTES — Analytics API
# ===========================================================================
@app.route("/api/analytics")
@login_required
def get_analytics():
    return jsonify(analytics)


# ===========================================================================
# ROUTES — Exports
# ===========================================================================
@app.route("/api/export/cases.csv")
@login_required
@permission_required("reports")
def export_cases():
    buf    = StringIO()
    fields = ["case_id", "title", "description", "status",
              "created_by", "created_at", "updated_at"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(cases_store.values())
    return send_file(BytesIO(buf.getvalue().encode()), as_attachment=True,
                     download_name="daft_cases.csv", mimetype="text/csv")


@app.route("/api/export/evidence.json")
@login_required
@permission_required("reports")
def export_evidence():
    json_str = json.dumps(list(evidence_registry.values()), indent=2, default=str)
    return send_file(BytesIO(json_str.encode()), as_attachment=True,
                     download_name="daft_evidence.json", mimetype="application/json")


@app.route("/api/export/activity.csv")
@login_required
@role_required("police")
def export_activity():
    buf = StringIO()
    if not activity_log_store:
        buf.write("No activity recorded.")
    else:
        fields = list(activity_log_store[0].keys())
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(activity_log_store)
    return send_file(BytesIO(buf.getvalue().encode()), as_attachment=True,
                     download_name="daft_activity_log.csv", mimetype="text/csv")


# ===========================================================================
# ROUTES — Report Download (Enhanced)
# ===========================================================================
@app.route("/api/download-report")
@login_required
@permission_required("reports")
def download_report():
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=60, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#00d4ff"), spaceAfter=6)
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#1e293b"), spaceAfter=4)

    story = []
    story.append(Paragraph("Digital Forensics AI Toolkit", title_style))
    story.append(Paragraph("Automated Forensic Analysis Report", styles["Heading2"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#00d4ff")))
    story.append(Spacer(1, 12))

    meta = [
        ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Analyst:",          session.get("user", "Unknown")],
        ["Role:",             session.get("role_label", "Unknown")],
        ["Report ID:",        str(uuid.uuid4())[:8].upper()],
    ]
    meta_table = Table(meta, colWidths=[2 * inch, 4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",   (0, 0), (0, -1),  colors.HexColor("#475569")),
        ("TEXTCOLOR",   (1, 0), (1, -1),  colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    summary_data = [
        ["Metric", "Value", "Status"],
        ["Total Scans",       str(analytics["total_scans"]),       "OK"],
        ["Intrusions Detected", str(analytics["intrusions_detected"]),
         "ALERT" if analytics["intrusions_detected"] > 0 else "CLEAR"],
        ["Anomalies Found",  str(analytics["anomalies_found"]),
         "WARNING" if analytics["anomalies_found"] > 0 else "CLEAR"],
        ["Images Analyzed",  str(analytics["images_analyzed"]),    "OK"],
        ["Cases Created",    str(len(cases_store)),                "OK"],
        ["Evidence Registered", str(len(evidence_registry)),       "OK"],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Cases Section
    story.append(Paragraph("Active Cases", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    all_cases = list(cases_store.values())
    if all_cases:
        case_data = [["Case ID", "Title", "Status", "Created By", "Created At"]]
        for c in all_cases[:10]:
            case_data.append([c["case_id"], c["title"][:28], c["status"],
                               c["created_by"], c["created_at"]])
        case_table = Table(case_data,
                           colWidths=[1.2*inch, 2.2*inch, 1*inch, 1.2*inch, 1.4*inch])
        case_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(case_table)
    else:
        story.append(Paragraph("No cases created in this session.", body_style))
    story.append(Spacer(1, 16))

    # Evidence Registry Section
    story.append(Paragraph("Evidence Registry", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    all_ev = list(evidence_registry.values())
    if all_ev:
        ev_data = [["Evidence ID", "Filename", "MD5 (partial)", "SHA-256 (partial)", "Integrity"]]
        for ev in all_ev[:10]:
            ev_data.append([
                ev["evidence_id"], ev["filename"][:20],
                ev["md5"][:12] + "…",
                ev["sha256"][:20] + "…",
                ev["integrity"],
            ])
        ev_table = Table(ev_data,
                         colWidths=[1.0*inch, 1.4*inch, 1.2*inch, 1.8*inch, 0.8*inch])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fff4")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(ev_table)
    else:
        story.append(Paragraph("No evidence registered in this session.", body_style))
    story.append(Spacer(1, 16))

    # Alert Log
    story.append(Paragraph("Recent Alert Log", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    if analytics["alerts"]:
        alert_data = [["Time", "Alert Message", "Type"]]
        for alert in analytics["alerts"][:10]:
            alert_data.append([alert["time"], alert["msg"], alert["type"].upper()])
        alert_table = Table(alert_data, colWidths=[1.2*inch, 4.5*inch, 1*inch])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef9f0")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(alert_table)
    else:
        story.append(Paragraph("No alerts recorded in this session.", body_style))
    story.append(Spacer(1, 20))

    # Conclusions
    story.append(Paragraph("Conclusions & Recommendations", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    conclusions = []
    if analytics["intrusions_detected"] > 0:
        conclusions.append(
            f"• {analytics['intrusions_detected']} network intrusion(s) detected. "
            "Recommend immediate incident response and network isolation.")
    if analytics["anomalies_found"] > 0:
        conclusions.append(
            f"• {analytics['anomalies_found']} data anomaly/anomalies flagged. "
            "Review flagged records for policy violations or data corruption.")
    if analytics["images_analyzed"] > 0:
        conclusions.append(
            f"• {analytics['images_analyzed']} image(s) processed through ELA forgery detection. "
            "Review any HIGH RISK verdicts before use as evidence.")
    if not conclusions:
        conclusions.append("• No critical findings. System operating within normal parameters.")
    conclusions.append(
        "• All evidence hashes should be independently verified before court submission.")
    conclusions.append(
        "• This report is machine-generated. Human expert review is required for legal proceedings.")
    for line in conclusions:
        story.append(Paragraph(line, body_style))
    story.append(Spacer(1, 16))

    # Methodology
    story.append(Paragraph("Methodology", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Evidence Analyzer:</b> Isolation Forest (sklearn) unsupervised ML — contamination 10%.",
        body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Intrusion Detection:</b> Random Forest (100 estimators) + rule-based signatures "
        "for suspicious ports, oversized packets, and TCP flag anomalies.", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Image Forgery:</b> ELA + Canny edge inconsistency + Laplacian noise variance "
        "+ histogram entropy. Composite tampering score.", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Evidence Integrity:</b> MD5 + SHA-256 generated at upload. "
        "Re-hash and compare on demand for chain-of-custody verification.", body_style))
    story.append(Spacer(1, 20))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#00d4ff")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was automatically generated by the Digital Forensics AI Toolkit. "
        "All findings should be validated by a certified forensic analyst before legal use.",
        ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8,
                       textColor=colors.HexColor("#94a3b8"), italic=True)
    ))

    doc.build(story)
    buf.seek(0)
    filename = f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename,
                     mimetype="application/pdf")


# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)