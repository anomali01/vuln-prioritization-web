"""
init_db.py - Skrip Inisialisasi Database
==========================================
Membuat tabel-tabel yang diperlukan oleh aplikasi prioritisasi kerentanan.
Jalankan skrip ini sekali untuk menyiapkan skema database.

Tabel yang dibuat:
  - vulnerabilities      : Data kerentanan (CVE) beserta skor CVSS, EPSS, KEV
  - prioritization_runs  : Riwayat eksekusi prioritisasi
  - prioritization_results: Hasil detail setiap CVE dalam suatu run
"""

import logging
import sys

from db import get_connection

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# Definisi DDL untuk setiap tabel
# ============================================================================

CREATE_VULNERABILITIES = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id          VARCHAR(20)   NOT NULL PRIMARY KEY
        COMMENT 'ID kerentanan dalam format CVE-YYYY-NNNNN',
    description     TEXT          NULL
        COMMENT 'Deskripsi singkat kerentanan dari NVD',
    cvss_v3_score   FLOAT         NULL
        COMMENT 'Skor dasar CVSS v3 (0.0 - 10.0)',
    cvss_v3_severity VARCHAR(20)  NULL
        COMMENT 'Tingkat keparahan CVSS v3 (LOW/MEDIUM/HIGH/CRITICAL)',
    cvss_vector     VARCHAR(200)  NULL
        COMMENT 'Vector string CVSS v3',
    epss_score      FLOAT         NULL
        COMMENT 'Skor EPSS (probabilitas eksploitasi dalam 30 hari, 0.0-1.0)',
    epss_percentile FLOAT         NULL
        COMMENT 'Persentil EPSS relatif terhadap seluruh CVE',
    is_kev          TINYINT       NOT NULL DEFAULT 0
        COMMENT 'Flag apakah CVE ada di katalog KEV CISA (0=tidak, 1=ya)',
    kev_date_added  DATE          NULL
        COMMENT 'Tanggal CVE ditambahkan ke katalog KEV',
    kev_due_date    DATE          NULL
        COMMENT 'Batas waktu remediasi menurut CISA KEV',
    kev_ransomware_use VARCHAR(20) NULL
        COMMENT 'Apakah digunakan dalam kampanye ransomware (Known/Unknown)',
    last_updated    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                  ON UPDATE CURRENT_TIMESTAMP
        COMMENT 'Waktu terakhir data diperbarui'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Tabel utama data kerentanan dari NVD, EPSS, dan CISA KEV';
"""

CREATE_PRIORITIZATION_RUNS = """
CREATE TABLE IF NOT EXISTS prioritization_runs (
    id              INT           NOT NULL AUTO_INCREMENT PRIMARY KEY
        COMMENT 'ID unik untuk setiap eksekusi prioritisasi',
    scenario        INT           NOT NULL
        COMMENT 'Nomor skenario (1=CVSS, 2=CVSS+EPSS, 3=CVSS+EPSS+KEV)',
    weight_config   VARCHAR(50)   NOT NULL
        COMMENT 'Konfigurasi bobot yang digunakan (config_1/config_2/config_3)',
    cve_count       INT           NOT NULL DEFAULT 0
        COMMENT 'Jumlah CVE yang diproses dalam run ini',
    created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
        COMMENT 'Waktu eksekusi prioritisasi'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Riwayat setiap eksekusi prioritisasi';
"""

CREATE_PRIORITIZATION_RESULTS = """
CREATE TABLE IF NOT EXISTS prioritization_results (
    id                  INT           NOT NULL AUTO_INCREMENT PRIMARY KEY
        COMMENT 'ID unik hasil prioritisasi',
    run_id              INT           NOT NULL
        COMMENT 'Referensi ke prioritization_runs.id',
    cve_id              VARCHAR(20)   NOT NULL
        COMMENT 'ID kerentanan yang diprioritisasi',
    cvss_norm           FLOAT         NULL
        COMMENT 'Skor CVSS ternormalisasi (0.0 - 1.0)',
    epss_norm           FLOAT         NULL
        COMMENT 'Skor EPSS ternormalisasi (0.0 - 1.0)',
    kev_flag            TINYINT       NULL
        COMMENT 'Flag KEV (0 atau 1)',
    weighted_score      FLOAT         NULL
        COMMENT 'Skor prioritas metode Weighted Scoring (0-100)',
    rule_based_score    FLOAT         NULL
        COMMENT 'Skor setelah penerapan Rule-Based Enhancement (0-100)',
    topsis_score        FLOAT         NULL
        COMMENT 'Skor prioritas metode TOPSIS (0-100)',
    final_rank_weighted INT           NULL
        COMMENT 'Peringkat akhir berdasarkan metode Weighted+RuleBased',
    final_rank_topsis   INT           NULL
        COMMENT 'Peringkat akhir berdasarkan metode TOPSIS',
    priority_category   VARCHAR(20)   NULL
        COMMENT 'Kategori prioritas (Critical/High/Medium/Low)',
    explainability_text TEXT          NULL
        COMMENT 'Teks penjelasan prioritas dalam Bahasa Indonesia',
    CONSTRAINT fk_results_run
        FOREIGN KEY (run_id) REFERENCES prioritization_runs(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Hasil detail prioritisasi per CVE untuk setiap run';
"""


def init_database():
    """
    Membuat seluruh tabel yang diperlukan di database.
    
    Fungsi ini aman untuk dijalankan berulang kali karena menggunakan
    CREATE TABLE IF NOT EXISTS.
    """
    conn = None
    cursor = None
    tables = [
        ("vulnerabilities", CREATE_VULNERABILITIES),
        ("prioritization_runs", CREATE_PRIORITIZATION_RUNS),
        ("prioritization_results", CREATE_PRIORITIZATION_RESULTS),
    ]

    try:
        conn = get_connection()
        cursor = conn.cursor()

        for table_name, ddl in tables:
            logger.info("Membuat tabel '%s' ...", table_name)
            cursor.execute(ddl)
            logger.info("Tabel '%s' berhasil dibuat / sudah ada.", table_name)

        conn.commit()
        logger.info("Inisialisasi database selesai. Semua tabel siap digunakan.")

    except Exception as e:
        logger.error("Gagal menginisialisasi database: %s", e)
        if conn and conn.is_connected():
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# ============================================================================
# Jalankan langsung jika skrip dieksekusi sebagai __main__
# ============================================================================
if __name__ == "__main__":
    try:
        init_database()
    except Exception:
        logger.exception("Proses inisialisasi database gagal.")
        sys.exit(1)
