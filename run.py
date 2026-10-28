"""
run.py - Runner Script Aplikasi Web Prioritisasi Kerentanan
===========================================================
Menjalankan server web Flask pada port 5000.
"""

from app import app

if __name__ == "__main__":
    print("=" * 70)
    print(" Sistem Prioritisasi Kerentanan Berbasis Risiko")
    print(" Menggunakan Data CVSS, EPSS, dan Known Exploited Vulnerability (KEV)")
    print("=" * 70)
    print(" Membuka server di: http://127.0.0.1:5000")
    print(" Tekan CTRL+C untuk menghentikan server.")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True)
