# Aplikasi Web Prioritisasi Kerentanan Berbasis Risiko Menggunakan Data CVSS, EPSS, dan KEV

Aplikasi Web sistem pendukung keputusan keamanan siber untuk memprioritaskan penanganan kerentanan perangkat lunak (*Vulnerability Prioritization*) berbasis risiko holistik tiga dimensi:
1. **Dampak Teknis Intrinsik**: CVSS v3.1 (*Common Vulnerability Scoring System*) via NVD REST API v2.0
2. **Probabilitas Eksploitasi 30 Hari**: FIRST EPSS (*Exploit Prediction Scoring System*) v1 REST API
3. **Status Eksploitasi Aktif di Dunia Nyata**: CISA KEV (*Known Exploited Vulnerabilities*) Catalog JSON

Dilengkapi dengan metode pembanding **MCDM TOPSIS**, **Rule-Based Critical Escalation**, dan **10 Skema Pengujian Evaluasi Khusus Bab 4 Skripsi**.

---

## 1. Arsitektur & Struktur Direktori

```
d:\Project Skripsi\vuln-prioritization-web\
├── .env                          # Kredensial Cloud MySQL & NVD API Key
├── .gitignore                    # File yang diabaikan Git
├── config.py                     # Modul konfigurasi aplikasi & load .env
├── db.py                         # Pool koneksi MySQL (mysql-connector-python)
├── init_db.py                    # Skrip inisialisasi skema tabel Cloud MySQL
├── seed_db.py                    # Skrip batch seeding 60 data sampel
├── sample_data.py                # Dataset 60 CVE terverifikasi (25 KEV + 35 Non-KEV)
├── api_service.py                # Modul integrasi NVD, FIRST EPSS, CISA KEV & Caching
├── prioritization_engine.py      # Algoritma Weighted Scoring, Rule-Based, TOPSIS, Explainability
├── evaluation_engine.py          # Modul 10 Skema Pengujian Evaluasi Bab 4
├── app.py                        # REST API Flask & Route Controller
├── run.py                        # Entry point runner server Flask
├── start.bat                     # Shortcut Windows runner
├── test_app.py                   # Automated Unit & Integration Testing
├── templates/
│   └── index.html                # Frontend Modern Dashboard SPA (Tailwind CSS + Chart.js)
└── venv/                         # Python Virtual Environment
```

---

## 2. Fitur Utama Sistem

### A. Dashboard Analisis Prioritas
- **Input Fleksibel**: Input teks manual CVE, unggah file `.csv` atau `.txt`, dan tombol instant *Load Sample Dataset (60 CVE)*.
- **3 Skenario Eksperimen**:
  - Skenario 1: CVSS Saja
  - Skenario 2: CVSS + EPSS
  - Skenario 3: CVSS + EPSS + KEV (Utama)
- **3 Konfigurasi Bobot Sensitivitas**:
  - Konfigurasi 1 (50 : 30 : 20)
  - Konfigurasi 2 (30 : 40 : 30)
  - Konfigurasi 3 (20 : 40 : 40)
- **Komparasi Dual-Metode**: Menampilkan perbandingan berdampingan antara **Metode Utama (Weighted Scoring + Rule-Based)** dan **Metode Pembanding (MCDM TOPSIS)**.
- **Rule-Based Critical Escalation**: Kerentanan KEV otomatis dieskalasi ke kategori *Critical* (skor $\ge 85$) untuk menangkal fenomena *prediction lag* dan *EPSS decay*.
- **Explainability Otomatis**: Penjelasan naratif berbasis aturan dalam Bahasa Indonesia yang merinci kontribusi tiap parameter terhadap skor dan kategori kerentanan.
- **Ekspor CSV**: Mengunduh seluruh hasil analisis ke format spreadsheet CSV.

### B. Laboratorium 10 Skema Pengujian Evaluasi Bab 4
Halaman khusus laboratorium yang menjalankan dan memvisualisasikan 10 skema pengujian empiris secara interaktif:
1. **Baseline Ranking Comparison**: Mengukur pergeseran peringkat (*rank displacement*) dan persentase irisan (*overlap*) Top-10 / Top-20.
2. **KEV Recall Testing**: Mengukur Recall@10, Recall@20, dan Recall@50 untuk menguji daya jaring terhadap ancaman nyata.
3. **Precision@K Testing**: Mengukur Precision@10, Precision@20, dan Precision@50 untuk efisiensi slot remediasi.
4. **Historical Backtesting**: Menarik skor EPSS historis pra-kejadian (14 hari sebelum masuk KEV) untuk membuktikan kemampuan deteksi dini.
5. **Ranking Quality Testing**: Metrik Information Retrieval komprehensif (**NDCG@10, NDCG@20, NDCG@50**, **MRR / Mean Reciprocal Rank**, dan **Average KEV Rank**).
6. **Ablation Testing**: Membandingkan kontribusi bertahap antara Skenario 1, Skenario 2, dan Skenario 3.
7. **Sensitivity Testing**: Analisis stabilitas dan korelasi Spearman peringkat terhadap 3 variasi bobot.
8. **Priority Consistency Testing**: Uji signifikansi korelasi peringkat Spearman ($\rho$ dan $p\text{-value}$) antara Metode Utama dan TOPSIS.
9. **Capacity-Based Remediation Simulation**: Simulasi kapasitas penanganan tim keamanan (10, 20, dan 50 CVE) vs Baseline CVSS dan Random.
10. **End-to-End Application Testing**: Pengujian latensi sistem, integritas data, dan jaminan eskalasi KEV 100%.

---

## 3. Cara Menjalankan Aplikasi

1. Aktifkan Virtual Environment:
   ```powershell
   .\venv\Scripts\activate
   ```
2. Jalankan aplikasi web:
   ```powershell
   python run.py
   ```
   *(Atau cukup klik dua kali file `start.bat` di Windows Explorer)*
3. Buka browser di alamat:
   ```
   http://127.0.0.1:5000
   ```

---

## 4. Menjalankan Unit Testing Otomatis

Untuk memverifikasi seluruh komponen secara menyeluruh:
```powershell
.\venv\Scripts\python.exe -m unittest test_app.py
```
Semua 4 unit test mencakup pengujian koneksi basis data, algoritma perangkingan, eskalasi rule-based, ke-10 skema evaluasi, dan seluruh endpoint REST API.
