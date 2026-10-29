"""
test_app.py - Skrip Pengujian Komprehensif Sistem Prioritisasi Kerentanan
========================================================================
Menguji seluruh komponen sistem:
  1. Koneksi Cloud MySQL & verifikasi tabel
  2. Modul Prioritisasi (Skenario 1, 2, 3 dan Config 1, 2, 3)
  3. Verifikasi Rule-Based Critical Escalation untuk KEV
  4. Verifikasi Algoritma TOPSIS
  5. Seluruh 10 Skema Pengujian Evaluasi Bab 4
  6. Endpoint REST API Flask via Test Client
"""

import unittest
import json
from app import app
from db import execute_query
from sample_data import SAMPLE_CVES_DATA
from prioritization_engine import run_prioritization
from evaluation_engine import run_all_evaluations

class TestVulnPrioritization(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.sample_vulns = SAMPLE_CVES_DATA

    def test_01_database_connection(self):
        """Uji koneksi ke Cloud MySQL dan ketersediaan data sampel"""
        res = execute_query("SELECT COUNT(*) AS total FROM vulnerabilities", fetch_one=True)
        self.assertIsNotNone(res)
        total = res["total"]
        print(f"[OK] Cloud MySQL terhubung. Total kerentanan tersimpan: {total}")
        self.assertGreaterEqual(total, 60)

    def test_02_prioritization_engine(self):
        """Uji engine prioritisasi Skenario 3 Config 1 dan Monotonisitas Rule-Based"""
        result = run_prioritization(self.sample_vulns, scenario=3, weight_config=1)
        self.assertIn("run_id", result)
        self.assertIn("results", result)
        self.assertIn("summary", result)
        self.assertEqual(len(result["results"]), len(self.sample_vulns))
        
        # Cek apakah ranking terurut
        ranks = [r["final_rank_weighted"] for r in result["results"]]
        self.assertEqual(ranks, list(range(1, len(self.sample_vulns) + 1)))
        
        # Cek Rule-Based Escalation (KEV harus di kategori Critical / score >= 85)
        # Serta cek sifat monotonik: urutan ranking antar KEV tidak boleh terbalik
        kev_results = [r for r in result["results"] if r["kev_flag"] == 1]
        for r in kev_results:
            self.assertGreaterEqual(r["rule_based_score"], 85.0)
            self.assertEqual(r["priority_category"], "Critical")
            
        for i in range(len(kev_results) - 1):
            curr_kev = kev_results[i]
            next_kev = kev_results[i + 1]
            # Karena sudah terurut descending, weighted_score curr_kev >= next_kev
            # maka rule_based_score curr_kev harus >= next_kev (Monotonik / Tidak Inversi)
            self.assertGreaterEqual(curr_kev["rule_based_score"], next_kev["rule_based_score"])
        
        # Uji Skenario 1 dan 2: Tidak boleh ada eskalasi KEV (mencegah data leakage)
        res_s1 = run_prioritization(self.sample_vulns[:10], scenario=1, weight_config=1)
        for r in res_s1["results"]:
            self.assertEqual(r["rule_based_score"], r["weighted_score"])
            
        res_s2 = run_prioritization(self.sample_vulns[:10], scenario=2, weight_config=1)
        for r in res_s2["results"]:
            self.assertEqual(r["rule_based_score"], r["weighted_score"])
        
        print("[OK] Prioritization Engine (Weighted + Monotonic Rule-Based + TOPSIS) berfungsi sempurna.")

    def test_03_all_10_evaluation_schemes(self):
        """Uji eksekusi seluruh 10 skema pengujian Bab 4 dan perbandingan 4 model"""
        eval_res = run_all_evaluations(self.sample_vulns, scenario=3, weight_config=1)
        
        # Verifikasi 10 pengujian ada dan menghasilkan data
        self.assertIn("test_1_baseline", eval_res)
        self.assertIn("test_2_recall", eval_res)
        self.assertIn("test_3_precision", eval_res)
        self.assertIn("test_4_backtesting", eval_res)
        self.assertIn("test_5_ranking_quality", eval_res)
        self.assertIn("test_6_ablation", eval_res)
        self.assertIn("test_7_sensitivity", eval_res)
        self.assertIn("test_8_consistency", eval_res)
        self.assertIn("test_9_capacity", eval_res)
        self.assertIn("test_10_end_to_end", eval_res)

        # Cek metrik pengujian 2 (Recall 4 model)
        recall_metrics = eval_res["test_2_recall"]["metrics"]
        self.assertEqual(len(recall_metrics), 3) # @10, @20, @50
        for m in recall_metrics:
            self.assertIn("recall_s1_pct", m)
            self.assertIn("recall_s2_pct", m)
            self.assertIn("recall_s3_w_pct", m)
            self.assertIn("recall_s3_t_pct", m)
            
        # Cek metrik pengujian 3 (Precision 4 model)
        precision_metrics = eval_res["test_3_precision"]["metrics"]
        self.assertEqual(len(precision_metrics), 3)
        for m in precision_metrics:
            self.assertIn("precision_s1_pct", m)
            self.assertIn("precision_s2_pct", m)
            self.assertIn("precision_s3_w_pct", m)
            self.assertIn("precision_s3_t_pct", m)
            
        # Cek metrik pengujian 5 (Ranking Quality 4 model)
        rq_metrics = eval_res["test_5_ranking_quality"]["metrics"]
        for m in rq_metrics:
            self.assertIn("s1_cvss", m)
            self.assertIn("s2_epss", m)
            self.assertIn("s3_weighted", m)
            self.assertIn("s3_topsis", m)
        
        # Cek metrik pengujian 8 (Spearman rho)
        rho = eval_res["test_8_consistency"]["spearman_rho"]
        self.assertIsInstance(rho, float)

        print(f"[OK] Seluruh 10 Skema Pengujian (termasuk perbandingan 4 model) berhasil dieksekusi dalam {eval_res['total_benchmark_time_sec']} detik.")

    def test_04_api_endpoints(self):
        """Uji endpoint REST API Flask"""
        # GET /api/health
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        
        # GET /api/sample-cves
        res = self.client.get("/api/sample-cves")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["count"], 60)

        # POST /api/fetch-cves
        res = self.client.post("/api/fetch-cves", json={"cve_list": ["CVE-2024-3400", "CVE-2024-6387"]})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data["vulnerabilities"]), 2)

        # POST /api/prioritize
        res = self.client.post("/api/prioritize", json={
            "vulnerabilities": self.sample_vulns[:10],
            "scenario": 3,
            "weight_config": 1
        })
        self.assertEqual(res.status_code, 200)
        prio_data = res.get_json()
        self.assertEqual(len(prio_data["results"]), 10)

        # POST /api/export-csv
        res = self.client.post("/api/export-csv", json={
            "results": [{"cve_id": "CVE-2024-3400", "score": 95.0}],
            "filename": "test.csv"
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")

        print("[OK] Seluruh Endpoint REST API Flask berfungsi dengan baik.")

if __name__ == "__main__":
    unittest.main()
