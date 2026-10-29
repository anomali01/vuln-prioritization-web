"""
app.py - Aplikasi Web Flask Prioritisasi Kerentanan Berbasis Risiko
===================================================================
Aplikasi Web Skripsi:
"Prioritisasi Kerentanan Berbasis Risiko Menggunakan Data CVSS, EPSS,
dan Known Exploited Vulnerability (KEV)"
"""

import io
import csv
import time
import logging
import traceback
import os
from flask import Flask, render_template, request, jsonify, send_file, Response
from config import Config
from db import get_connection, execute_query
from api_service import fetch_single_cve, fetch_multiple_cves
from prioritization_engine import run_prioritization
from evaluation_engine import run_all_evaluations
from sample_data import SAMPLE_CVES_DATA, SAMPLE_CVE_IDS

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, "templates")
static_dir = os.path.join(base_dir, "static")

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY


@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    logger.error("Unhandled Exception: %s", traceback.format_exc())
    return jsonify({
        "status": "error",
        "error_type": type(e).__name__,
        "error_message": str(e),
        "traceback": traceback.format_exc()
    }), 500


@app.route("/")
def index():
    """Halaman Dashboard Utama (SPA)."""
    try:
        return render_template("index.html")
    except Exception as e:
        logger.error("Template rendering error: %s", traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": "Template rendering error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


@app.route("/api/health", methods=["GET"])
def health_check():
    """Endpoint status server dan database Cloud MySQL."""
    db_status = "Disconnected"
    table_counts = {}
    try:
        conn = get_connection()
        if conn and conn.is_connected():
            db_status = "Connected"
            res = execute_query("SELECT COUNT(*) AS cnt FROM vulnerabilities", fetch_one=True)
            table_counts["vulnerabilities"] = res["cnt"] if res else 0
            
            res_runs = execute_query("SELECT COUNT(*) AS cnt FROM prioritization_runs", fetch_one=True)
            table_counts["prioritization_runs"] = res_runs["cnt"] if res_runs else 0
            
            conn.close()
    except Exception as e:
        db_status = f"Error: {str(e)}"

    return jsonify({
        "status": "healthy",
        "database": db_status,
        "database_counts": table_counts,
        "nvd_api_configured": bool(Config.NVD_API_KEY)
    })


@app.route("/api/sample-cves", methods=["GET"])
def get_sample_cves():
    """Mengembalikan daftar 60 CVE sampel campuran KEV dan non-KEV."""
    return jsonify({
        "cve_ids": SAMPLE_CVE_IDS,
        "count": len(SAMPLE_CVE_IDS),
        "kev_count": sum(1 for x in SAMPLE_CVES_DATA if x["is_kev"] == 1),
        "non_kev_count": sum(1 for x in SAMPLE_CVES_DATA if x["is_kev"] == 0),
        "data": SAMPLE_CVES_DATA
    })


@app.route("/api/seed-database", methods=["POST"])
def seed_database():
    """Memasukkan 60 sampel data terverifikasi ke Cloud MySQL."""
    inserted = 0
    start = time.time()
    try:
        for item in SAMPLE_CVES_DATA:
            query = """
                INSERT INTO vulnerabilities
                    (cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_vector,
                     epss_score, epss_percentile, is_kev, kev_date_added, kev_due_date,
                     kev_ransomware_use)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    description       = VALUES(description),
                    cvss_v3_score     = VALUES(cvss_v3_score),
                    cvss_v3_severity  = VALUES(cvss_v3_severity),
                    cvss_vector       = VALUES(cvss_vector),
                    epss_score        = VALUES(epss_score),
                    epss_percentile   = VALUES(epss_percentile),
                    is_kev            = VALUES(is_kev),
                    kev_date_added    = VALUES(kev_date_added),
                    kev_due_date      = VALUES(kev_due_date),
                    kev_ransomware_use= VALUES(kev_ransomware_use)
            """
            params = (
                item["cve_id"], item["description"], item["cvss_v3_score"],
                item["cvss_v3_severity"], item["cvss_vector"], item["epss_score"],
                item["epss_percentile"], item["is_kev"], item["kev_date_added"],
                item["kev_due_date"], item["kev_ransomware_use"]
            )
            execute_query(query, params)
            inserted += 1
        elapsed = round(time.time() - start, 2)
        return jsonify({
            "status": "success",
            "message": f"Berhasil men-seed {inserted} CVE sampel ke Cloud MySQL dalam {elapsed} detik.",
            "count": inserted
        })
    except Exception as e:
        logger.error("Gagal melakukan seed database: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/fetch-cves", methods=["POST"])
def fetch_cves():
    """
    Mengambil data CVSS, EPSS, dan KEV untuk daftar CVE.
    Menerapkan pencarian cache MySQL dan fallback cepat.
    """
    data = request.get_json() or {}
    cve_list = data.get("cve_list", [])

    if not cve_list:
        return jsonify({"error": "Daftar CVE tidak boleh kosong."}), 400

    # Normalisasi format CVE-YYYY-NNNN
    cleaned_cves = []
    for c in cve_list:
        c_str = str(c).strip().upper()
        if c_str.startswith("CVE-") and c_str not in cleaned_cves:
            cleaned_cves.append(c_str)

    if not cleaned_cves:
        return jsonify({"error": "Tidak ada format CVE yang valid ditemukan."}), 400

    start_time = time.time()
    vulnerabilities = fetch_multiple_cves(cleaned_cves)
    elapsed = round(time.time() - start_time, 2)

    kev_count = sum(1 for v in vulnerabilities if v.get("is_kev", 0) == 1)

    return jsonify({
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "kev_count": kev_count,
        "non_kev_count": len(vulnerabilities) - kev_count,
        "elapsed_time_sec": elapsed
    })


@app.route("/api/prioritize", methods=["POST"])
def prioritize():
    """
    Menjalankan algoritma prioritisasi:
    - Metode Utama: Weighted Risk Scoring + Rule-Based Prioritization
    - Metode Pembanding: MCDM TOPSIS
    """
    data = request.get_json() or {}
    vuln_data = data.get("vulnerabilities", [])
    scenario = int(data.get("scenario", 3))
    weight_config = int(data.get("weight_config", 1))

    if not vuln_data:
        return jsonify({"error": "Data kerentanan kosong. Silakan fetch CVE terlebih dahulu."}), 400

    try:
        start_time = time.time()
        result = run_prioritization(vuln_data, scenario, weight_config)
        elapsed = round(time.time() - start_time, 3)
        result["elapsed_time_sec"] = elapsed
        return jsonify(result)
    except Exception as e:
        logger.error("Error pada proses prioritisasi: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/evaluate", methods=["POST"])
def evaluate():
    """Menjalankan seluruh 10 skema pengujian evaluasi Bab 4 skripsi."""
    data = request.get_json() or {}
    vuln_data = data.get("vulnerabilities", [])
    scenario = int(data.get("scenario", 3))
    weight_config = int(data.get("weight_config", 1))

    if not vuln_data:
        return jsonify({"error": "Data kerentanan kosong. Silakan fetch CVE terlebih dahulu."}), 400

    try:
        start_time = time.time()
        eval_results = run_all_evaluations(vuln_data, scenario, weight_config)
        elapsed = round(time.time() - start_time, 3)
        eval_results["elapsed_time_sec"] = elapsed
        return jsonify(eval_results)
    except Exception as e:
        logger.error("Error pada modul evaluasi: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/export-csv", methods=["POST"])
def export_csv():
    """Mengekspor hasil analisis atau pengujian ke format CSV."""
    data = request.get_json() or {}
    items = data.get("results", [])
    filename = data.get("filename", "prioritization_results.csv")

    if not items:
        return Response("Data kosong", mimetype="text/csv", status=400)

    # Buat CSV di memori
    output = io.StringIO()
    headers = list(items[0].keys())
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for row in items:
        writer.writerow(row)

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    csv_bytes.seek(0)

    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


if __name__ == "__main__":
    logger.info("Menjalankan aplikasi Flask di http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
