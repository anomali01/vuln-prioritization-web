"""
prioritization_engine.py - Mesin Kalkulasi Prioritas Kerentanan
================================================================
Mengimplementasikan dua metode prioritisasi:
  1. Weighted Risk Scoring + Rule-Based Enhancement (Metode Utama)
  2. TOPSIS (Metode Pembanding)

Mendukung 3 skenario dan 3 konfigurasi bobot untuk analisis
komprehensif prioritisasi kerentanan.
"""

import logging
import math

from db import execute_query, get_connection

# Konfigurasi logging
logger = logging.getLogger(__name__)

# ============================================================================
# Definisi skenario dan konfigurasi bobot
# ============================================================================

# Bobot dasar untuk setiap konfigurasi (CVSS : EPSS : KEV)
WEIGHT_CONFIGS = {
    1: {"cvss": 0.5, "epss": 0.3, "kev": 0.2},   # Config 1: 50:30:20
    2: {"cvss": 0.3, "epss": 0.4, "kev": 0.3},   # Config 2: 30:40:30
    3: {"cvss": 0.2, "epss": 0.4, "kev": 0.4},   # Config 3: 20:40:40
}

# Faktor aktif berdasarkan skenario
SCENARIO_FACTORS = {
    1: ["cvss"],                    # Skenario 1: CVSS saja
    2: ["cvss", "epss"],            # Skenario 2: CVSS + EPSS
    3: ["cvss", "epss", "kev"],     # Skenario 3: CVSS + EPSS + KEV
}

# Kategori prioritas berdasarkan skor
PRIORITY_THRESHOLDS = {
    "Critical": 80,
    "High": 60,
    "Medium": 40,
    "Low": 0,
}


# ============================================================================
# Fungsi utilitas
# ============================================================================

def _get_effective_weights(scenario, weight_config):
    """
    Menghitung bobot efektif berdasarkan skenario dan konfigurasi.
    
    Pada skenario dengan faktor lebih sedikit, bobot diredistribusi
    secara proporsional di antara faktor yang aktif saja.
    
    Args:
        scenario (int): Nomor skenario (1-3).
        weight_config (int): Nomor konfigurasi bobot (1-3).
    
    Returns:
        dict: Bobot efektif untuk setiap faktor aktif (total = 1.0).
    """
    base_weights = WEIGHT_CONFIGS[weight_config]
    active_factors = SCENARIO_FACTORS[scenario]

    # Hitung total bobot dari faktor aktif saja
    active_sum = sum(base_weights[f] for f in active_factors)

    # Redistribusi bobot proporsional agar total = 1.0
    effective = {}
    for factor in active_factors:
        effective[factor] = base_weights[factor] / active_sum

    logger.debug("Bobot efektif (skenario=%d, config=%d): %s",
                  scenario, weight_config, effective)
    return effective


def _normalize_cvss(score):
    """
    Normalisasi skor CVSS ke rentang 0.0-1.0.
    
    Args:
        score (float): Skor CVSS v3 (0.0 - 10.0).
    
    Returns:
        float: Skor ternormalisasi (0.0 - 1.0).
    """
    if score is None:
        return 0.0
    return float(score) / 10.0


def _get_priority_category(score):
    """
    Menentukan kategori prioritas berdasarkan skor.
    
    Args:
        score (float): Skor prioritas (0-100).
    
    Returns:
        str: Kategori prioritas (Critical/High/Medium/Low).
    """
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


# ============================================================================
# Metode 1: Weighted Risk Scoring + Rule-Based Enhancement
# ============================================================================

def _compute_weighted_score(vuln, weights):
    """
    Menghitung skor risiko terbobot (Weighted Risk Score).
    
    Formula: weighted_score = (w_cvss*cvss_norm + w_epss*epss_norm + w_kev*kev) * 100
    
    Args:
        vuln (dict): Data kerentanan (harus memiliki key cvss_v3_score,
                     epss_score, is_kev).
        weights (dict): Bobot efektif untuk setiap faktor.
    
    Returns:
        float: Skor terbobot (0-100).
    """
    score = 0.0

    if "cvss" in weights:
        cvss_norm = _normalize_cvss(vuln.get("cvss_v3_score", 0))
        score += weights["cvss"] * cvss_norm

    if "epss" in weights:
        epss_norm = float(vuln.get("epss_score", 0))
        score += weights["epss"] * epss_norm

    if "kev" in weights:
        kev_flag = int(vuln.get("is_kev", 0))
        score += weights["kev"] * kev_flag

    return score * 100


def _apply_rule_based_enhancement(weighted_score, is_kev):
    """
    Menerapkan rule-based enhancement untuk memastikan kerentanan KEV
    selalu mendapat eskalasi ke kategori Critical.
    
    Aturan: Jika is_kev == 1 DAN weighted_score < 85, maka:
        rule_based_score = max(85, weighted_score + 20), capped at 100.
    Ini memastikan semua KEV CVE berada di kategori Critical,
    terlepas dari penurunan skor EPSS seiring waktu (EPSS decay).
    
    Args:
        weighted_score (float): Skor terbobot awal (0-100).
        is_kev (int): Flag KEV (0 atau 1).
    
    Returns:
        float: Skor setelah penerapan aturan (0-100).
    """
    if is_kev == 1 and weighted_score < 85:
        return min(100.0, max(85.0, weighted_score + 20))
    return weighted_score


# ============================================================================
# Metode 2: TOPSIS (Technique for Order of Preference by Similarity)
# ============================================================================

def _compute_topsis(vuln_list, weights, scenario):
    """
    Menghitung skor TOPSIS untuk sekumpulan kerentanan.
    
    Langkah-langkah metode TOPSIS:
    1. Bangun matriks keputusan berdasarkan faktor aktif skenario
    2. Normalisasi matriks: r_ij = x_ij / sqrt(sum(x_ij^2))
    3. Pembobotan: v_ij = w_j * r_ij
    4. Tentukan solusi ideal positif (A+) dan negatif (A-)
    5. Hitung jarak D+ dan D- untuk setiap alternatif
    6. Hitung preference value: C_i = D_i- / (D_i+ + D_i-)
    7. Skalakan ke rentang 0-100
    
    Args:
        vuln_list (list[dict]): Daftar data kerentanan.
        weights (dict): Bobot efektif untuk setiap faktor.
        scenario (int): Nomor skenario (1-3).
    
    Returns:
        list[float]: Skor TOPSIS untuk setiap kerentanan (0-100).
    """
    n = len(vuln_list)
    if n == 0:
        return []

    active_factors = SCENARIO_FACTORS[scenario]
    m = len(active_factors)

    # Langkah 1: Bangun matriks keputusan
    matrix = []
    for vuln in vuln_list:
        row = []
        for factor in active_factors:
            if factor == "cvss":
                row.append(_normalize_cvss(vuln.get("cvss_v3_score", 0)))
            elif factor == "epss":
                row.append(float(vuln.get("epss_score", 0)))
            elif factor == "kev":
                row.append(float(vuln.get("is_kev", 0)))
        matrix.append(row)

    # Langkah 2: Normalisasi vektor kolom
    # r_ij = x_ij / sqrt(sum(x_ij^2))
    col_norms = []
    for j in range(m):
        sum_sq = sum(matrix[i][j] ** 2 for i in range(n))
        col_norms.append(math.sqrt(sum_sq) if sum_sq > 0 else 1.0)

    norm_matrix = []
    for i in range(n):
        norm_row = [matrix[i][j] / col_norms[j] for j in range(m)]
        norm_matrix.append(norm_row)

    # Langkah 3: Matriks terbobot
    weight_list = [weights[f] for f in active_factors]
    weighted_matrix = []
    for i in range(n):
        w_row = [norm_matrix[i][j] * weight_list[j] for j in range(m)]
        weighted_matrix.append(w_row)

    # Langkah 4: Solusi ideal positif (A+) dan negatif (A-)
    # Semua kriteria bersifat benefit (semakin tinggi semakin baik)
    a_pos = [max(weighted_matrix[i][j] for i in range(n)) for j in range(m)]
    a_neg = [min(weighted_matrix[i][j] for i in range(n)) for j in range(m)]

    # Langkah 5: Hitung jarak ke A+ dan A-
    d_pos = []
    d_neg = []
    for i in range(n):
        dp = math.sqrt(sum((weighted_matrix[i][j] - a_pos[j]) ** 2 for j in range(m)))
        dn = math.sqrt(sum((weighted_matrix[i][j] - a_neg[j]) ** 2 for j in range(m)))
        d_pos.append(dp)
        d_neg.append(dn)

    # Langkah 6: Preference value C_i = D_i- / (D_i+ + D_i-)
    topsis_scores = []
    for i in range(n):
        denom = d_pos[i] + d_neg[i]
        if denom > 0:
            c_i = d_neg[i] / denom
        else:
            c_i = 0.0
        # Langkah 7: Skalakan ke 0-100
        topsis_scores.append(c_i * 100)

    return topsis_scores


# ============================================================================
# Generator Explainability (Bahasa Indonesia)
# ============================================================================

def _generate_explanation(vuln, rule_based_score, scenario, weights):
    """
    Menghasilkan teks penjelasan prioritas dalam Bahasa Indonesia.
    
    Teks disesuaikan berdasarkan skenario yang digunakan dan
    faktor-faktor yang berkontribusi terhadap skor akhir.
    
    Args:
        vuln (dict): Data kerentanan.
        rule_based_score (float): Skor akhir setelah rule-based enhancement.
        scenario (int): Nomor skenario yang digunakan.
        weights (dict): Bobot efektif yang digunakan.
    
    Returns:
        str: Teks penjelasan prioritas dalam Bahasa Indonesia.
    """
    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    category = _get_priority_category(rule_based_score)
    cvss = vuln.get("cvss_v3_score", 0)
    epss = vuln.get("epss_score", 0)
    epss_pct = vuln.get("epss_percentile", 0)
    is_kev = vuln.get("is_kev", 0)
    kev_date = vuln.get("kev_date_added", None)

    parts = []
    part_num = 1

    # Bagian CVSS (selalu ada di semua skenario)
    if cvss >= 9.0:
        tingkat_cvss = "sangat serius"
    elif cvss >= 7.0:
        tingkat_cvss = "serius"
    elif cvss >= 4.0:
        tingkat_cvss = "moderat"
    else:
        tingkat_cvss = "rendah"

    bobot_cvss_pct = int(weights.get("cvss", 0) * 100)
    parts.append(
        f"({part_num}) Skor CVSS {cvss:.1f}/10 (bobot {bobot_cvss_pct}%) "
        f"menunjukkan kerentanan dengan dampak {tingkat_cvss}"
    )
    part_num += 1

    # Bagian EPSS (skenario 2 dan 3)
    if scenario >= 2:
        bobot_epss_pct = int(weights.get("epss", 0) * 100)
        epss_pct_display = epss_pct * 100

        if epss >= 0.7:
            tingkat_epss = "sangat tinggi"
        elif epss >= 0.4:
            tingkat_epss = "tinggi"
        elif epss >= 0.1:
            tingkat_epss = "moderat"
        else:
            tingkat_epss = "rendah"

        parts.append(
            f"({part_num}) Skor EPSS {epss:.4f} (persentil {epss_pct_display:.0f}%, "
            f"bobot {bobot_epss_pct}%) menandakan probabilitas eksploitasi "
            f"{tingkat_epss} dalam 30 hari ke depan"
        )
        part_num += 1

    # Bagian KEV (skenario 3)
    if scenario >= 3:
        bobot_kev_pct = int(weights.get("kev", 0) * 100)
        if is_kev == 1:
            tanggal_info = f" sejak {kev_date}" if kev_date else ""
            parts.append(
                f"({part_num}) Termasuk dalam katalog KEV CISA (bobot {bobot_kev_pct}%) - "
                f"aktif dieksploitasi{tanggal_info}, sehingga mendapat "
                f"eskalasi otomatis ke Critical"
            )
        else:
            parts.append(
                f"({part_num}) Tidak termasuk dalam katalog KEV CISA "
                f"(bobot {bobot_kev_pct}%), "
                f"sehingga tidak mendapat eskalasi tambahan"
            )

    alasan = "; ".join(parts) + "."

    explanation = (
        f"{cve_id} mendapat kategori {category} (skor: {rule_based_score:.2f}) "
        f"karena: {alasan}"
    )

    return explanation


# ============================================================================
# Fungsi utama: run_prioritization
# ============================================================================

def run_prioritization(vuln_data_list, scenario, weight_config):
    """
    Menjalankan prioritisasi kerentanan dengan kedua metode.
    
    Proses:
    1. Hitung bobot efektif berdasarkan skenario dan konfigurasi
    2. Untuk setiap CVE: hitung Weighted Score → Rule-Based Enhancement
    3. Hitung skor TOPSIS untuk seluruh CVE
    4. Tentukan peringkat dan kategori prioritas
    5. Generate teks penjelasan (explainability)
    6. Simpan hasil ke database
    
    Args:
        vuln_data_list (list[dict]): Daftar data kerentanan dari API.
        scenario (int): Nomor skenario (1, 2, atau 3).
        weight_config (int): Nomor konfigurasi bobot (1, 2, atau 3).
    
    Returns:
        dict: Berisi:
            - run_id (int): ID run yang disimpan di database
            - results (list[dict]): Hasil prioritisasi per CVE (terurut)
            - summary (dict): Statistik ringkasan
    
    Raises:
        ValueError: Jika skenario atau weight_config tidak valid.
    """
    # Validasi parameter
    if scenario not in SCENARIO_FACTORS:
        raise ValueError(f"Skenario tidak valid: {scenario}. Pilih 1, 2, atau 3.")
    if weight_config not in WEIGHT_CONFIGS:
        raise ValueError(f"Konfigurasi bobot tidak valid: {weight_config}. Pilih 1, 2, atau 3.")
    if not vuln_data_list:
        raise ValueError("Daftar kerentanan tidak boleh kosong.")

    logger.info("Memulai prioritisasi: skenario=%d, weight_config=%d, jumlah_cve=%d",
                 scenario, weight_config, len(vuln_data_list))

    weights = _get_effective_weights(scenario, weight_config)

    # ----------------------------------------------------------------
    # Tahap 1: Weighted Risk Scoring + Rule-Based Enhancement
    # ----------------------------------------------------------------
    results = []
    for vuln in vuln_data_list:
        cvss_norm = _normalize_cvss(vuln.get("cvss_v3_score", 0))
        epss_norm = float(vuln.get("epss_score", 0))
        kev_flag = int(vuln.get("is_kev", 0))

        # Weighted score
        weighted_score = _compute_weighted_score(vuln, weights)

        # Rule-based enhancement
        rule_based_score = _apply_rule_based_enhancement(weighted_score, kev_flag)

        results.append({
            "cve_id": vuln["cve_id"],
            "cvss_norm": cvss_norm,
            "epss_norm": epss_norm,
            "kev_flag": kev_flag,
            "weighted_score": round(weighted_score, 4),
            "rule_based_score": round(rule_based_score, 4),
            "topsis_score": 0.0,  # diisi setelah TOPSIS
            "final_rank_weighted": 0,
            "final_rank_topsis": 0,
            "priority_category": "",
            "explainability_text": "",
            # Simpan data asli untuk referensi
            "_vuln_data": vuln,
        })

    # ----------------------------------------------------------------
    # Tahap 2: TOPSIS
    # ----------------------------------------------------------------
    topsis_scores = _compute_topsis(vuln_data_list, weights, scenario)
    for i, score in enumerate(topsis_scores):
        results[i]["topsis_score"] = round(score, 4)

    # ----------------------------------------------------------------
    # Tahap 3: Peringkat (Ranking)
    # ----------------------------------------------------------------
    # Peringkat berdasarkan rule-based score (descending)
    sorted_by_weighted = sorted(
        range(len(results)),
        key=lambda i: results[i]["rule_based_score"],
        reverse=True
    )
    for rank, idx in enumerate(sorted_by_weighted, start=1):
        results[idx]["final_rank_weighted"] = rank

    # Peringkat berdasarkan TOPSIS score (descending)
    sorted_by_topsis = sorted(
        range(len(results)),
        key=lambda i: results[i]["topsis_score"],
        reverse=True
    )
    for rank, idx in enumerate(sorted_by_topsis, start=1):
        results[idx]["final_rank_topsis"] = rank

    # ----------------------------------------------------------------
    # Tahap 4: Kategori prioritas dan explainability
    # ----------------------------------------------------------------
    for r in results:
        r["priority_category"] = _get_priority_category(r["rule_based_score"])
        r["explainability_text"] = _generate_explanation(
            r["_vuln_data"], r["rule_based_score"], scenario, weights
        )

    # ----------------------------------------------------------------
    # Tahap 5: Simpan ke database
    # ----------------------------------------------------------------
    run_id = _save_run_to_db(results, scenario, weight_config)

    # Bersihkan data internal sebelum return
    for r in results:
        r.pop("_vuln_data", None)

    # Urutkan hasil berdasarkan peringkat weighted (utama)
    results.sort(key=lambda x: x["final_rank_weighted"])

    # ----------------------------------------------------------------
    # Tahap 6: Hitung ringkasan statistik
    # ----------------------------------------------------------------
    summary = _compute_summary(results)

    logger.info("Prioritisasi selesai. Run ID: %d", run_id)

    return {
        "run_id": run_id,
        "scenario": scenario,
        "weight_config": weight_config,
        "results": results,
        "summary": summary,
    }


# ============================================================================
# Fungsi pendukung penyimpanan dan statistik
# ============================================================================

def _save_run_to_db(results, scenario, weight_config):
    """
    Menyimpan hasil prioritisasi ke tabel database secara efisien (batch insert).
    
    Args:
        results (list[dict]): Hasil prioritisasi per CVE.
        scenario (int): Nomor skenario.
        weight_config (int): Nomor konfigurasi bobot.
    
    Returns:
        int: ID run yang baru dibuat.
    """
    weight_config_label = f"config_{weight_config}"

    # Simpan run header
    run_query = """
        INSERT INTO prioritization_runs (scenario, weight_config, cve_count)
        VALUES (%s, %s, %s)
    """
    run_result = execute_query(run_query, (scenario, weight_config_label, len(results)))
    run_id = run_result["last_insert_id"]

    # Simpan detail hasil dalam 1 batch transaksi dengan executemany
    detail_query = """
        INSERT INTO prioritization_results
            (run_id, cve_id, cvss_norm, epss_norm, kev_flag,
             weighted_score, rule_based_score, topsis_score,
             final_rank_weighted, final_rank_topsis,
             priority_category, explainability_text)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    batch_params = [
        (
            run_id,
            r["cve_id"],
            r["cvss_norm"],
            r["epss_norm"],
            r["kev_flag"],
            r["weighted_score"],
            r["rule_based_score"],
            r["topsis_score"],
            r["final_rank_weighted"],
            r["final_rank_topsis"],
            r["priority_category"],
            r["explainability_text"]
        )
        for r in results
    ]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany(detail_query, batch_params)
    conn.commit()
    cursor.close()
    conn.close()

    logger.info("Hasil prioritisasi disimpan ke database via batch (run_id=%d, %d hasil).",
                 run_id, len(results))
    return run_id


def _compute_summary(results):
    """
    Menghitung statistik ringkasan dari hasil prioritisasi.
    
    Args:
        results (list[dict]): Hasil prioritisasi per CVE.
    
    Returns:
        dict: Statistik ringkasan meliputi jumlah per kategori,
              rata-rata skor, dan distribusi.
    """
    total = len(results)
    if total == 0:
        return {"total": 0}

    # Hitung distribusi kategori
    category_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    weighted_scores = []
    topsis_scores = []
    kev_count = 0

    for r in results:
        cat = r.get("priority_category", "Low")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        weighted_scores.append(r["rule_based_score"])
        topsis_scores.append(r["topsis_score"])
        if r["kev_flag"] == 1:
            kev_count += 1

    return {
        "total": total,
        "category_distribution": category_counts,
        "kev_count": kev_count,
        "avg_weighted_score": round(sum(weighted_scores) / total, 2),
        "max_weighted_score": round(max(weighted_scores), 2),
        "min_weighted_score": round(min(weighted_scores), 2),
        "avg_topsis_score": round(sum(topsis_scores) / total, 2),
        "max_topsis_score": round(max(topsis_scores), 2),
        "min_topsis_score": round(min(topsis_scores), 2),
    }
