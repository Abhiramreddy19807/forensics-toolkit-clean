"""
Digital Forensics AI Toolkit - Flask Backend
Author: Forensics AI Team
Description: Production-level full-stack web app for digital forensics analysis
"""

import os
import json
import uuid
import base64
import tempfile
import logging
from io import BytesIO
from datetime import datetime
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
app.secret_key = os.environ.get("SECRET_KEY", "forensics-ai-secret-2024-xK9mP")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory analytics counters (replace with DB in production)
# ---------------------------------------------------------------------------
analytics = {
    "total_scans": 0,
    "intrusions_detected": 0,
    "anomalies_found": 0,
    "images_analyzed": 0,
    "alerts": []
}

# ---------------------------------------------------------------------------
# Demo user store (replace with real DB + hashed passwords in production)
# ---------------------------------------------------------------------------
USERS = {
    "admin": "forensics2024",
    "analyst": "analyst123"
}

# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Pre-trained ML models (fitted at startup with synthetic data)
# ---------------------------------------------------------------------------
def build_isolation_forest():
    """Build and pre-fit an IsolationForest on synthetic normal network data."""
    rng = np.random.RandomState(42)
    X_normal = rng.randn(500, 6) * np.array([10, 5, 100, 50, 1000, 200])
    X_normal += np.array([50, 20, 500, 100, 5000, 800])
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    model.fit(X_normal)
    return model


def build_random_forest():
    """Build and pre-fit a RandomForestClassifier on synthetic intrusion data."""
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

# ---------------------------------------------------------------------------
# Routes - Auth
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and USERS[username] == password:
            session["user"] = username
            session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"User '{username}' logged in.")
            return redirect(url_for("dashboard"))
        error = "Invalid credentials. Please try again."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Routes - Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", analytics=analytics, user=session["user"])


# ---------------------------------------------------------------------------
# Routes - Evidence Analyzer
# ---------------------------------------------------------------------------
@app.route("/evidence")
@login_required
def evidence():
    return render_template("evidence.html", user=session["user"])


@app.route("/api/analyze-evidence", methods=["POST"])
@login_required
def analyze_evidence():
    """
    Accept CSV file upload, run IsolationForest, return anomaly results as JSON.
    If no file, generate synthetic data for demo purposes.
    """
    records = []
    use_synthetic = False

    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        try:
            df = pd.read_csv(file)
            # Use first 6 numeric columns
            numeric_cols = df.select_dtypes(include=[np.number]).columns[:6]
            if len(numeric_cols) < 2:
                return jsonify({"error": "CSV must have at least 2 numeric columns."}), 400
            X = df[numeric_cols].fillna(0).values
            # Pad columns if fewer than 6
            if X.shape[1] < 6:
                pad = np.zeros((X.shape[0], 6 - X.shape[1]))
                X = np.hstack([X, pad])
            col_names = list(numeric_cols) + [f"feat_{i}" for i in range(6 - len(numeric_cols))]
        except Exception as e:
            return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400
    else:
        # Generate synthetic demo data
        use_synthetic = True
        rng = np.random.RandomState()
        n = 40
        X_normal = rng.randn(n - 5, 6) * np.array([10, 5, 100, 50, 1000, 200])
        X_normal += np.array([50, 20, 500, 100, 5000, 800])
        X_anomaly = rng.randn(5, 6) * np.array([80, 40, 800, 400, 8000, 1600])
        X_anomaly += np.array([500, 200, 5000, 1000, 50000, 8000])
        X = np.vstack([X_normal, X_anomaly])
        col_names = FEATURE_NAMES

    preds = ISO_FOREST.predict(X)   # 1 = normal, -1 = anomaly
    scores = ISO_FOREST.score_samples(X)

    anomaly_count = int(np.sum(preds == -1))
    analytics["total_scans"] += 1
    analytics["anomalies_found"] += anomaly_count

    # Build result records
    for i, (pred, score) in enumerate(zip(preds, scores)):
        row = {col: float(round(X[i, j], 3)) for j, col in enumerate(col_names[:6])}
        row["anomaly_score"] = float(round(score, 4))
        row["status"] = "ANOMALY" if pred == -1 else "NORMAL"
        row["record_id"] = i + 1
        records.append(row)

    # Log alert if anomalies found
    if anomaly_count > 0:
        analytics["alerts"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg": f"Evidence scan: {anomaly_count} anomalies detected",
            "type": "warning"
        })
        analytics["alerts"] = analytics["alerts"][:20]  # Keep last 20

    return jsonify({
        "records": records,
        "total": len(records),
        "anomalies": anomaly_count,
        "synthetic": use_synthetic,
        "columns": col_names[:6]
    })


# ---------------------------------------------------------------------------
# Routes - Intrusion Detection
# ---------------------------------------------------------------------------
@app.route("/intrusion")
@login_required
def intrusion():
    return render_template("intrusion.html", user=session["user"])


@app.route("/api/detect-intrusion", methods=["POST"])
@login_required
def detect_intrusion():
    """
    Accept network traffic parameters, run RF model + rule-based logic.
    Returns classification and probability.
    """
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
    pred = int(RF_MODEL.predict(X_scaled)[0])
    proba = RF_MODEL.predict_proba(X_scaled)[0]
    confidence = float(round(max(proba) * 100, 2))

    # Rule-based override for obvious attack signatures
    rule_triggered = None
    src_port = features[0]
    dst_port = features[1]
    pkt_size = features[2]
    flags = features[7]

    SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5900, 6667, 31337}
    if dst_port in SUSPICIOUS_PORTS:
        pred = 1
        rule_triggered = f"Suspicious destination port: {int(dst_port)}"
    elif pkt_size > 65000:
        pred = 1
        rule_triggered = "Oversized packet (potential DoS)"
    elif flags >= 60:
        pred = 1
        rule_triggered = "Unusual TCP flags (potential scan)"

    label = "ATTACK" if pred == 1 else "NORMAL"
    severity = "HIGH" if pred == 1 and confidence > 80 else ("MEDIUM" if pred == 1 else "LOW")

    if pred == 1:
        analytics["intrusions_detected"] += 1
        analytics["alerts"].insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg": f"Intrusion detected: {label} (confidence {confidence}%)",
            "type": "danger"
        })
        analytics["alerts"] = analytics["alerts"][:20]

    analytics["total_scans"] += 1

    return jsonify({
        "prediction": label,
        "confidence": confidence,
        "severity": severity,
        "rule_triggered": rule_triggered,
        "features": {
            "src_port": int(features[0]),
            "dst_port": int(features[1]),
            "packet_size": features[2],
            "duration": features[3],
            "byte_count": features[4],
            "connection_count": features[5],
            "protocol": "TCP" if features[6] == 1 else "UDP",
            "flags": int(features[7])
        }
    })


# ---------------------------------------------------------------------------
# Routes - Image Forgery Detection
# ---------------------------------------------------------------------------
@app.route("/image-analysis")
@login_required
def image_analysis():
    return render_template("image_analysis.html", user=session["user"])


@app.route("/api/analyze-image", methods=["POST"])
@login_required
def analyze_image():
    """
    Detect image tampering using OpenCV edge analysis, ELA, and noise patterns.
    Returns a tampering score and visual analysis.
    """
    if "image" not in request.files or not request.files["image"].filename:
        return jsonify({"error": "No image file provided."}), 400

    file = request.files["image"]
    allowed = {"png", "jpg", "jpeg", "bmp", "tiff"}
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in allowed:
        return jsonify({"error": f"Unsupported format. Allowed: {', '.join(allowed)}"}), 400

    try:
        img_bytes = file.read()
        pil_img = Image.open(BytesIO(img_bytes)).convert("RGB")
        pil_img.thumbnail((800, 800), Image.LANCZOS)
        img_np = np.array(pil_img)
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        # --- ELA (Error Level Analysis) ---
        ela_score = _ela_score(pil_img)

        # --- Edge inconsistency ---
        edges = cv2.Canny(gray, 100, 200)
        edge_density = float(np.sum(edges > 0)) / edges.size

        # --- Noise analysis ---
        laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())

        # --- Histogram entropy ---
        hist = cv2.calcHist([gray], [0], None, [256], [0, 256]).flatten()
        hist = hist / (hist.sum() + 1e-9)
        entropy = float(-np.sum(hist * np.log2(hist + 1e-9)))

        # --- Composite tampering score ---
        # Normalize each signal to 0-100 and combine
        ela_norm = min(ela_score * 2, 100)
        edge_norm = min(edge_density * 500, 100)
        noise_norm = min(laplacian_var / 500 * 100, 100)
        entropy_norm = min((entropy / 8) * 100, 100)

        tampering_pct = round(
            0.40 * ela_norm +
            0.25 * edge_norm +
            0.20 * noise_norm +
            0.15 * (100 - entropy_norm),  # low entropy = uniform = suspicious
            2
        )
        tampering_pct = max(0.0, min(100.0, tampering_pct))

        # Verdict
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
        analytics["total_scans"] += 1

        # Generate ELA visualization
        ela_b64 = _generate_ela_image(pil_img)

        # Encode original (resized)
        buf = BytesIO()
        pil_img.save(buf, format="JPEG", quality=85)
        orig_b64 = base64.b64encode(buf.getvalue()).decode()

        return jsonify({
            "tampering_score": tampering_pct,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "metrics": {
                "ela_score": round(ela_score, 3),
                "edge_density": round(edge_density * 100, 3),
                "noise_variance": round(laplacian_var, 2),
                "entropy": round(entropy, 3)
            },
            "ela_image": ela_b64,
            "original_image": orig_b64,
            "dimensions": f"{pil_img.width} × {pil_img.height}",
            "format": ext.upper()
        })

    except Exception as e:
        logger.error(f"Image analysis error: {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


def _ela_score(pil_img: Image.Image) -> float:
    """Compute mean ELA difference as a tampering signal."""
    buf = BytesIO()
    pil_img.save(buf, format="JPEG", quality=75)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")
    ela = np.abs(np.array(pil_img, dtype=np.float32) - np.array(compressed, dtype=np.float32))
    return float(ela.mean())


def _generate_ela_image(pil_img: Image.Image) -> str:
    """Generate ELA visualization and return as base64 PNG."""
    buf = BytesIO()
    pil_img.save(buf, format="JPEG", quality=75)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")
    ela_arr = np.abs(np.array(pil_img, dtype=np.float32) - np.array(compressed, dtype=np.float32))
    # Scale to 0-255 for visibility
    ela_scaled = (ela_arr / (ela_arr.max() + 1e-9) * 255).astype(np.uint8)
    ela_img = Image.fromarray(ela_scaled)
    out_buf = BytesIO()
    ela_img.save(out_buf, format="PNG")
    return base64.b64encode(out_buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# Route - Report Download
# ---------------------------------------------------------------------------
@app.route("/api/download-report")
@login_required
def download_report():
    """Generate and serve a PDF forensics report."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             rightMargin=40, leftMargin=40,
                             topMargin=60, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#00d4ff"),
        spaceAfter=6
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#1e293b"),
        spaceAfter=4
    )

    story = []
    story.append(Paragraph("Digital Forensics AI Toolkit", title_style))
    story.append(Paragraph("Automated Forensic Analysis Report", styles["Heading2"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#00d4ff")))
    story.append(Spacer(1, 12))

    meta = [
        ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Analyst:", session.get("user", "Unknown")],
        ["Report ID:", str(uuid.uuid4())[:8].upper()],
    ]
    meta_table = Table(meta, colWidths=[2 * inch, 4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))

    summary_data = [
        ["Metric", "Value", "Status"],
        ["Total Scans Performed", str(analytics["total_scans"]), "OK"],
        ["Intrusions Detected", str(analytics["intrusions_detected"]),
         "ALERT" if analytics["intrusions_detected"] > 0 else "CLEAR"],
        ["Anomalies Found", str(analytics["anomalies_found"]),
         "WARNING" if analytics["anomalies_found"] > 0 else "CLEAR"],
        ["Images Analyzed", str(analytics["images_analyzed"]), "OK"],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Recent Alert Log", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))

    if analytics["alerts"]:
        alert_data = [["Time", "Alert Message", "Type"]]
        for alert in analytics["alerts"][:10]:
            alert_data.append([alert["time"], alert["msg"], alert["type"].upper()])
        alert_table = Table(alert_data, colWidths=[1.2 * inch, 4.5 * inch, 1 * inch])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef9f0")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(alert_table)
    else:
        story.append(Paragraph("No alerts recorded in this session.", body_style))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Methodology", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Evidence Analyzer:</b> Utilizes Isolation Forest (sklearn) — an unsupervised ML algorithm "
        "that isolates anomalies by randomly partitioning features. Contamination factor set to 10%.",
        body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Intrusion Detection:</b> Random Forest classifier (100 estimators) combined with rule-based "
        "logic for known attack signatures including suspicious ports, oversized packets, and TCP flag anomalies.",
        body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Image Forgery Detection:</b> Multi-signal approach using Error Level Analysis (ELA), "
        "Canny edge inconsistency mapping, Laplacian noise variance, and histogram entropy analysis. "
        "Composite tampering score weighted across all signals.",
        body_style))
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


# ---------------------------------------------------------------------------
# Route - Analytics API
# ---------------------------------------------------------------------------
@app.route("/api/analytics")
@login_required
def get_analytics():
    return jsonify(analytics)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
