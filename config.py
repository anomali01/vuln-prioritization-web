"""
config.py - Modul Konfigurasi Aplikasi
=======================================
Memuat variabel environment dari file .env dan menyediakan
kelas Config untuk seluruh konfigurasi aplikasi.
"""

import os
from dotenv import load_dotenv

# Muat variabel environment dari file .env
load_dotenv()


class Config:
    """Kelas konfigurasi utama aplikasi."""

    # Kunci rahasia Flask untuk session dan CSRF
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')

    # Konfigurasi koneksi database MySQL
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_NAME = os.getenv('DB_NAME')

    # API Key untuk NVD (National Vulnerability Database)
    NVD_API_KEY = os.getenv('NVD_API_KEY')
