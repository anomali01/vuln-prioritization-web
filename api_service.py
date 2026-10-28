"""
api_service.py - Modul Integrasi API Eksternal
================================================
Mengintegrasikan data dari tiga sumber kerentanan:
  1. NVD (National Vulnerability Database) - skor CVSS v3
  2. FIRST EPSS - probabilitas eksploitasi
  3. CISA KEV - katalog kerentanan yang aktif dieksploitasi

Setiap fungsi menerapkan caching ke database MySQL agar tidak
memanggil API berulang kali untuk CVE yang sama.
"""

import logging
import time
from datetime import datetime, timedelta

import requests

from config import Config
from db import execute_query
from sample_data import SAMPLE_CVES_DATA

# Lookup map untuk data sampel pra-verifikasi
_SAMPLE_LOOKUP = {x["cve_id"]: x for x in SAMPLE_CVES_DATA}

# Konfigurasi logging
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Konstanta URL API
# ---------------------------------------------------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Cache in-memory untuk katalog KEV (agar tidak download ulang setiap kali)
_kev_cache = {
    "data": None,           # dict {cve_id: record, ...}
    "last_fetched": None,   # datetime kapan terakhir diunduh
    "ttl_hours": 6,         # masa berlaku cache dalam jam
}

# Delay antar request API NVD (sesuai rate limit)
_NVD_DELAY_WITH_KEY = 0.6   # detik (jika ada API key)
_NVD_DELAY_WITHOUT_KEY = 6  # detik (tanpa API key)

# Batas usia cache database (jam)
_DB_CACHE_MAX_AGE_HOURS = 24


# ============================================================================
# Fungsi pembantu internal
# ============================================================================

def _is_cache_fresh(last_updated_str):
    """
    Mengecek apakah data cache di database masih segar (< 24 jam).
    
    Args:
        last_updated_str: Timestamp string atau datetime object dari kolom
                          last_updated di tabel vulnerabilities.
    
    Returns:
        bool: True jika cache masih valid, False jika sudah kadaluarsa.
    """
    if last_updated_str is None:
        return False

    if isinstance(last_updated_str, str):
        try:
            last_updated = datetime.strptime(last_updated_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False
    elif isinstance(last_updated_str, datetime):
        last_updated = last_updated_str
    else:
        return False

    age = datetime.now() - last_updated
    return age < timedelta(hours=_DB_CACHE_MAX_AGE_HOURS)


def _get_cached_vulnerability(cve_id):
    """
    Mengambil data CVE dari cache database jika masih segar.
    
    Args:
        cve_id (str): ID kerentanan (misal CVE-2024-12345).
    
    Returns:
        dict | None: Data kerentanan dari database, atau None jika tidak
                     ditemukan atau cache sudah kadaluarsa.
    """
    query = "SELECT * FROM vulnerabilities WHERE cve_id = %s"
    row = execute_query(query, (cve_id,), fetch_one=True)

    if row and _is_cache_fresh(row.get("last_updated")):
        logger.debug("Cache HIT untuk %s (usia < %d jam).",
                      cve_id, _DB_CACHE_MAX_AGE_HOURS)
        return _row_to_dict(row)

    return None


def _row_to_dict(row):
    """
    Mengonversi baris database menjadi dict standar kerentanan.
    
    Args:
        row (dict): Baris dari tabel vulnerabilities.
    
    Returns:
        dict: Data kerentanan dalam format standar.
    """
    return {
        "cve_id": row["cve_id"],
        "description": row.get("description", ""),
        "cvss_v3_score": float(row["cvss_v3_score"]) if row.get("cvss_v3_score") is not None else 0.0,
        "cvss_v3_severity": row.get("cvss_v3_severity", ""),
        "cvss_vector": row.get("cvss_vector", ""),
        "epss_score": float(row["epss_score"]) if row.get("epss_score") is not None else 0.0,
        "epss_percentile": float(row["epss_percentile"]) if row.get("epss_percentile") is not None else 0.0,
        "is_kev": int(row.get("is_kev", 0)),
        "kev_date_added": str(row["kev_date_added"]) if row.get("kev_date_added") else None,
        "kev_due_date": str(row["kev_due_date"]) if row.get("kev_due_date") else None,
        "kev_ransomware_use": row.get("kev_ransomware_use", ""),
    }


def _upsert_vulnerability(data):
    """
    Menyimpan atau memperbarui data CVE di tabel vulnerabilities.
    
    Menggunakan INSERT ... ON DUPLICATE KEY UPDATE agar aman dijalankan
    berulang kali tanpa duplikasi.
    
    Args:
        data (dict): Data kerentanan dalam format standar.
    """
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
            kev_ransomware_use= VALUES(kev_ransomware_use),
            last_updated      = CURRENT_TIMESTAMP
    """
    params = (
        data["cve_id"],
        data.get("description", ""),
        data.get("cvss_v3_score"),
        data.get("cvss_v3_severity", ""),
        data.get("cvss_vector", ""),
        data.get("epss_score"),
        data.get("epss_percentile"),
        data.get("is_kev", 0),
        data.get("kev_date_added"),
        data.get("kev_due_date"),
        data.get("kev_ransomware_use", ""),
    )
    execute_query(query, params)
    logger.debug("Data CVE %s berhasil disimpan/diperbarui di database.", data["cve_id"])


# ============================================================================
# 1. NVD API - Mengambil data CVSS v3
# ============================================================================

def fetch_nvd_data(cve_id):
    """
    Mengambil data CVSS v3 dari NVD API untuk satu CVE.
    
    Melakukan parsing response NVD yang bersarang cukup dalam:
    vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData
    
    Args:
        cve_id (str): ID kerentanan (misal CVE-2024-12345).
    
    Returns:
        dict: Berisi 'cvss_v3_score', 'cvss_v3_severity', 'cvss_vector',
              dan 'description'. Mengembalikan nilai default jika gagal.
    """
    result = {
        "cvss_v3_score": 0.0,
        "cvss_v3_severity": "",
        "cvss_vector": "",
        "description": "",
    }

    try:
        headers = {}
        if Config.NVD_API_KEY:
            headers["apiKey"] = Config.NVD_API_KEY

        params = {"cveId": cve_id}
        response = requests.get(NVD_API_URL, params=params, headers=headers,
                                timeout=30)
        response.raise_for_status()
        data = response.json()

        # Navigasi ke data kerentanan
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning("NVD: Tidak ada data kerentanan untuk %s.", cve_id)
            return result

        cve_data = vulnerabilities[0].get("cve", {})

        # Ambil deskripsi (bahasa Inggris)
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                result["description"] = desc.get("value", "")
                break

        # Ambil metrik CVSS v3.1, fallback ke v3.0
        metrics = cve_data.get("metrics", {})
        cvss_data = None

        # Coba CVSS v3.1 terlebih dahulu
        cvss_v31_list = metrics.get("cvssMetricV31", [])
        if cvss_v31_list:
            cvss_data = cvss_v31_list[0].get("cvssData", {})

        # Fallback ke CVSS v3.0
        if not cvss_data:
            cvss_v30_list = metrics.get("cvssMetricV30", [])
            if cvss_v30_list:
                cvss_data = cvss_v30_list[0].get("cvssData", {})

        if cvss_data:
            result["cvss_v3_score"] = float(cvss_data.get("baseScore", 0.0))
            result["cvss_v3_severity"] = cvss_data.get("baseSeverity", "")
            result["cvss_vector"] = cvss_data.get("vectorString", "")

        logger.info("NVD: %s -> CVSS %.1f (%s)",
                     cve_id, result["cvss_v3_score"], result["cvss_v3_severity"])

    except requests.exceptions.Timeout:
        logger.error("NVD API timeout untuk %s.", cve_id)
    except requests.exceptions.HTTPError as e:
        logger.error("NVD API HTTP error untuk %s: %s", cve_id, e)
    except (KeyError, IndexError, ValueError) as e:
        logger.error("NVD API parsing error untuk %s: %s", cve_id, e)
    except requests.exceptions.RequestException as e:
        logger.error("NVD API request error untuk %s: %s", cve_id, e)

    return result


# ============================================================================
# 2. EPSS API - Mengambil skor probabilitas eksploitasi
# ============================================================================

def fetch_epss_data(cve_id, date=None):
    """
    Mengambil skor EPSS dari FIRST API untuk satu CVE.
    
    Args:
        cve_id (str): ID kerentanan (misal CVE-2024-12345).
        date (str, optional): Tanggal historis dalam format YYYY-MM-DD.
                              Jika None, mengambil skor terkini.
    
    Returns:
        dict: Berisi 'epss_score' dan 'epss_percentile'.
              Mengembalikan 0.0 untuk keduanya jika gagal.
    """
    result = {
        "epss_score": 0.0,
        "epss_percentile": 0.0,
    }

    try:
        params = {"cve": cve_id}
        if date:
            params["date"] = date

        response = requests.get(EPSS_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        epss_list = data.get("data", [])
        if epss_list:
            epss_entry = epss_list[0]
            result["epss_score"] = float(epss_entry.get("epss", 0.0))
            result["epss_percentile"] = float(epss_entry.get("percentile", 0.0))

        logger.info("EPSS: %s -> skor=%.6f persentil=%.4f%s",
                     cve_id, result["epss_score"], result["epss_percentile"],
                     f" (tanggal: {date})" if date else "")

    except requests.exceptions.Timeout:
        logger.error("EPSS API timeout untuk %s.", cve_id)
    except requests.exceptions.HTTPError as e:
        logger.error("EPSS API HTTP error untuk %s: %s", cve_id, e)
    except (KeyError, IndexError, ValueError) as e:
        logger.error("EPSS API parsing error untuk %s: %s", cve_id, e)
    except requests.exceptions.RequestException as e:
        logger.error("EPSS API request error untuk %s: %s", cve_id, e)

    return result


# ============================================================================
# 3. CISA KEV - Katalog kerentanan yang aktif dieksploitasi
# ============================================================================

def _load_kev_catalog():
    """
    Mengunduh dan meng-cache katalog KEV CISA secara in-memory.
    
    Katalog di-cache selama _kev_cache['ttl_hours'] jam.
    Data disimpan sebagai dict dengan cve_id sebagai key untuk
    lookup O(1).
    """
    now = datetime.now()

    # Cek apakah cache masih valid
    if (_kev_cache["data"] is not None and
            _kev_cache["last_fetched"] is not None and
            (now - _kev_cache["last_fetched"]).total_seconds() <
            _kev_cache["ttl_hours"] * 3600):
        return

    logger.info("Mengunduh katalog KEV CISA ...")
    try:
        response = requests.get(KEV_CATALOG_URL, timeout=60)
        response.raise_for_status()
        catalog = response.json()

        # Konversi list ke dict untuk pencarian cepat
        kev_dict = {}
        for vuln in catalog.get("vulnerabilities", []):
            kev_dict[vuln["cveID"]] = {
                "dateAdded": vuln.get("dateAdded"),
                "dueDate": vuln.get("dueDate"),
                "knownRansomwareCampaignUse": vuln.get(
                    "knownRansomwareCampaignUse", "Unknown"
                ),
            }

        _kev_cache["data"] = kev_dict
        _kev_cache["last_fetched"] = now
        logger.info("Katalog KEV berhasil dimuat: %d kerentanan.", len(kev_dict))

    except requests.exceptions.RequestException as e:
        logger.error("Gagal mengunduh katalog KEV: %s", e)
        # Jika gagal dan belum ada cache, set dict kosong
        if _kev_cache["data"] is None:
            _kev_cache["data"] = {}


def fetch_kev_data(cve_id):
    """
    Mengecek apakah CVE tertentu ada di katalog KEV CISA.
    
    Args:
        cve_id (str): ID kerentanan (misal CVE-2024-12345).
    
    Returns:
        dict: Berisi 'is_kev' (0 atau 1), 'kev_date_added',
              'kev_due_date', dan 'kev_ransomware_use'.
    """
    _load_kev_catalog()

    result = {
        "is_kev": 0,
        "kev_date_added": None,
        "kev_due_date": None,
        "kev_ransomware_use": "",
    }

    if _kev_cache["data"] and cve_id in _kev_cache["data"]:
        kev_entry = _kev_cache["data"][cve_id]
        result["is_kev"] = 1
        result["kev_date_added"] = kev_entry.get("dateAdded")
        result["kev_due_date"] = kev_entry.get("dueDate")
        result["kev_ransomware_use"] = kev_entry.get(
            "knownRansomwareCampaignUse", "Unknown"
        )
        logger.info("KEV: %s -> DITEMUKAN dalam katalog (ditambahkan: %s).",
                     cve_id, result["kev_date_added"])
    else:
        logger.debug("KEV: %s -> Tidak ditemukan dalam katalog.", cve_id)

    return result


# ============================================================================
# 4. Fungsi utama pengambilan data lengkap satu CVE
# ============================================================================

def fetch_cve_data(cve_id):
    """
    Mengambil data lengkap satu CVE dari semua sumber (NVD, EPSS, KEV).
    
    Menerapkan strategi caching:
    1. Cek cache database (< 24 jam) → jika ada, langsung return
    2. Jika tidak ada/kadaluarsa → panggil API, simpan ke database
    
    Args:
        cve_id (str): ID kerentanan (misal CVE-2024-12345).
    
    Returns:
        dict: Data kerentanan lengkap dalam format standar.
    """
    # Langkah 1: Cek cache database
    cached = _get_cached_vulnerability(cve_id)
    if cached:
        return cached

    # Langkah 1b: Cek data sampel bawaan (agar cepat dan bebas rate limit)
    if cve_id in _SAMPLE_LOOKUP:
        logger.info("Menggunakan data sampel pra-verifikasi untuk %s dan menyimpan ke cache MySQL ...", cve_id)
        sample_item = dict(_SAMPLE_LOOKUP[cve_id])
        _upsert_vulnerability(sample_item)
        return sample_item

    logger.info("Mengambil data dari API untuk %s ...", cve_id)

    # Langkah 2: Ambil data dari NVD
    nvd_data = fetch_nvd_data(cve_id)

    # Delay sesuai rate limit NVD
    delay = _NVD_DELAY_WITH_KEY if Config.NVD_API_KEY else _NVD_DELAY_WITHOUT_KEY
    time.sleep(delay)

    # Langkah 3: Ambil data dari EPSS
    epss_data = fetch_epss_data(cve_id)

    # Langkah 4: Cek status KEV
    kev_data = fetch_kev_data(cve_id)

    # Gabungkan semua data
    combined = {
        "cve_id": cve_id,
        "description": nvd_data.get("description", ""),
        "cvss_v3_score": nvd_data.get("cvss_v3_score", 0.0),
        "cvss_v3_severity": nvd_data.get("cvss_v3_severity", ""),
        "cvss_vector": nvd_data.get("cvss_vector", ""),
        "epss_score": epss_data.get("epss_score", 0.0),
        "epss_percentile": epss_data.get("epss_percentile", 0.0),
        "is_kev": kev_data.get("is_kev", 0),
        "kev_date_added": kev_data.get("kev_date_added"),
        "kev_due_date": kev_data.get("kev_due_date"),
        "kev_ransomware_use": kev_data.get("kev_ransomware_use", ""),
    }

    # Langkah 5: Simpan ke cache database
    _upsert_vulnerability(combined)

    return combined


# ============================================================================
# 5. Batch processing - Pengambilan data untuk banyak CVE sekaligus
# ============================================================================

def fetch_multiple_cves(cve_list, progress_callback=None):
    """
    Mengambil data lengkap untuk daftar CVE secara batch.
    
    Args:
        cve_list (list[str]): Daftar ID kerentanan yang akan diambil datanya.
        progress_callback (callable, optional): Fungsi callback untuk tracking
            progres. Menerima parameter (current_index, total, cve_id, status).
    
    Returns:
        list[dict]: List berisi data kerentanan untuk setiap CVE.
                    CVE yang gagal diambil tetap disertakan dengan nilai default.
    """
    results = []
    total = len(cve_list)

    logger.info("Memulai batch processing untuk %d CVE ...", total)

    for idx, cve_id in enumerate(cve_list, start=1):
        cve_id = cve_id.strip().upper()

        try:
            data = fetch_cve_data(cve_id)
            status = "success"
        except Exception as e:
            logger.error("Gagal mengambil data untuk %s: %s", cve_id, e)
            # Kembalikan data default jika gagal
            data = {
                "cve_id": cve_id,
                "description": "",
                "cvss_v3_score": 0.0,
                "cvss_v3_severity": "",
                "cvss_vector": "",
                "epss_score": 0.0,
                "epss_percentile": 0.0,
                "is_kev": 0,
                "kev_date_added": None,
                "kev_due_date": None,
                "kev_ransomware_use": "",
            }
            status = "error"

        results.append(data)

        # Laporan progres
        if progress_callback:
            progress_callback(idx, total, cve_id, status)
        else:
            logger.info("Progres: %d/%d - %s (%s)", idx, total, cve_id, status)

    logger.info("Batch processing selesai: %d/%d CVE berhasil.",
                 sum(1 for r in results if r.get("cvss_v3_score", 0) > 0),
                 total)

    return results


# ============================================================================
# 6. Utilitas tambahan
# ============================================================================

def fetch_historical_epss(cve_id, date_str):
    """
    Mengambil skor EPSS historis untuk tanggal tertentu.
    
    Berguna untuk backtesting - membandingkan skor EPSS sebelum
    suatu CVE ditambahkan ke katalog KEV.
    
    Args:
        cve_id (str): ID kerentanan.
        date_str (str): Tanggal dalam format YYYY-MM-DD.
    
    Returns:
        dict: Berisi 'epss_score' dan 'epss_percentile' untuk tanggal tsb.
    """
    return fetch_epss_data(cve_id, date=date_str)


def get_kev_catalog():
    """
    Mengembalikan seluruh katalog KEV yang sudah di-cache.
    
    Returns:
        dict: Katalog KEV dengan cve_id sebagai key.
    """
    _load_kev_catalog()
    return _kev_cache.get("data", {})


# Alias untuk fleksibilitas pemanggilan
fetch_single_cve = fetch_cve_data

