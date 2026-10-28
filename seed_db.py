"""
seed_db.py - Skrip Seeding Cepat 60 Data Sampel ke Cloud MySQL
==============================================================
Menggunakan batch insert (executemany) agar proses selesai dalam hitungan detik.
"""

import time
import logging
from sample_data import SAMPLE_CVES_DATA
from db import get_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def seed():
    logging.info("Memulai seeding 60 data sampel ke Cloud MySQL...")
    start = time.time()
    
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

    params_list = [
        (
            item["cve_id"], item["description"], item["cvss_v3_score"],
            item["cvss_v3_severity"], item["cvss_vector"], item["epss_score"],
            item["epss_percentile"], item["is_kev"], item["kev_date_added"],
            item["kev_due_date"], item["kev_ransomware_use"]
        )
        for item in SAMPLE_CVES_DATA
    ]

    conn = get_connection()
    cursor = conn.cursor()
    cursor.executemany(query, params_list)
    conn.commit()
    cursor.close()
    conn.close()

    elapsed = round(time.time() - start, 2)
    logging.info("Berhasil men-seed %d CVE ke Cloud MySQL dalam %.2f detik!", len(params_list), elapsed)

if __name__ == "__main__":
    seed()
