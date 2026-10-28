"""
db.py - Utilitas Koneksi Database
==================================
Menyediakan fungsi-fungsi helper untuk koneksi dan operasi database MySQL
menggunakan connection pooling untuk performa optimal.
"""

import logging
import mysql.connector
from mysql.connector import pooling, Error as MySQLError

from config import Config

# Konfigurasi logging
logger = logging.getLogger(__name__)

# Pool koneksi database (dibuat saat modul pertama kali dimuat)
_connection_pool = None


def _init_pool():
    """
    Inisialisasi connection pool MySQL.
    
    Pool dibuat satu kali dan digunakan ulang untuk seluruh request
    guna mengurangi overhead pembuatan koneksi baru.
    """
    global _connection_pool
    if _connection_pool is not None:
        return

    try:
        pool_config = {
            "pool_name": "vuln_pool",
            "pool_size": 5,
            "pool_reset_session": True,
            "host": Config.DB_HOST,
            "port": Config.DB_PORT,
            "user": Config.DB_USER,
            "password": Config.DB_PASSWORD,
            "database": Config.DB_NAME,
            "charset": "utf8mb4",
            "collation": "utf8mb4_general_ci",
            "autocommit": True,
        }
        _connection_pool = pooling.MySQLConnectionPool(**pool_config)
        logger.info("Connection pool MySQL berhasil dibuat (pool_size=5).")
    except MySQLError as e:
        logger.error("Gagal membuat connection pool MySQL: %s", e)
        raise


def get_connection():
    """
    Mengambil koneksi dari connection pool.
    
    Returns:
        mysql.connector.connection.MySQLConnection: Objek koneksi database.
    
    Raises:
        mysql.connector.Error: Jika gagal mendapatkan koneksi dari pool.
    """
    _init_pool()
    try:
        conn = _connection_pool.get_connection()
        # Pastikan koneksi masih aktif
        if not conn.is_connected():
            conn.reconnect(attempts=3, delay=1)
        return conn
    except MySQLError as e:
        logger.error("Gagal mendapatkan koneksi dari pool: %s", e)
        raise


def execute_query(query, params=None, fetch_one=False):
    """
    Menjalankan query SQL dan mengembalikan hasil.
    
    Args:
        query (str): String query SQL yang akan dijalankan.
        params (tuple, optional): Parameter untuk query parameterized.
        fetch_one (bool): Jika True, hanya mengembalikan satu baris hasil.
    
    Returns:
        list[dict] | dict | None: Hasil query dalam bentuk list of dict,
            single dict (jika fetch_one=True), atau None jika tidak ada hasil.
            Untuk query INSERT/UPDATE/DELETE, mengembalikan dict berisi
            'affected_rows' dan 'last_insert_id'.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)

        # Jika query menghasilkan result set (SELECT, SHOW, dll.)
        if cursor.description is not None:
            if fetch_one:
                result = cursor.fetchone()
            else:
                result = cursor.fetchall()
            return result

        # Untuk query modifikasi data (INSERT, UPDATE, DELETE)
        conn.commit()
        return {
            "affected_rows": cursor.rowcount,
            "last_insert_id": cursor.lastrowid,
        }

    except MySQLError as e:
        logger.error("Error menjalankan query: %s | Query: %s", e, query)
        if conn and conn.is_connected():
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()  # Mengembalikan koneksi ke pool


def execute_many(query, data_list):
    """
    Menjalankan query batch untuk banyak baris data sekaligus.
    
    Args:
        query (str): String query SQL dengan placeholder %s.
        data_list (list[tuple]): List of tuple berisi data untuk setiap baris.
    
    Returns:
        dict: Dict berisi 'affected_rows' (jumlah baris terpengaruh).
    
    Raises:
        mysql.connector.Error: Jika terjadi error saat eksekusi batch.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.executemany(query, data_list)
        conn.commit()
        logger.info("Batch execute berhasil: %d baris terpengaruh.", cursor.rowcount)
        return {"affected_rows": cursor.rowcount}

    except MySQLError as e:
        logger.error("Error menjalankan batch query: %s", e)
        if conn and conn.is_connected():
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
