import os
import re
import csv
import io
import json
import base64
import secrets
import shutil
import sqlite3
import functools
import threading
import time
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests
from flask import Flask, request, session, redirect, jsonify, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from openpyxl import Workbook

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ================================================================
# SCHOOLPAY V10
# Secure Flask + SQLite school fees management system
# ================================================================

BASE_DIR = Path(__file__).resolve().parent
DB = BASE_DIR / "schoolpay.db"
BACKUP_DIR = BASE_DIR / "backups"
BACKUP_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

SECRET_FILE = BASE_DIR / ".schoolpay_secret"
def load_secret():
    value = os.environ.get("SECRET_KEY")
    if value:
        return value
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    value = secrets.token_hex(32)
    SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return value

app.secret_key = load_secret()
app.permanent_session_lifetime = timedelta(hours=8)

# ----------------------------------------------------------------
# Encryption at rest for M-Pesa/Daraja credentials stored in SQLite.
# Derives a Fernet key from the app secret so no separate key file is
# needed; falls back to plaintext (with a UI warning) if the
# `cryptography` package isn't installed.
# ----------------------------------------------------------------
_ENC_PREFIX = "enc:"


def _fernet():
    key = base64.urlsafe_b64encode(hashlib_sha256(app.secret_key))
    return Fernet(key)


def hashlib_sha256(value):
    import hashlib
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).digest()


def encrypt_secret(value):
    if not value:
        return value
    if not CRYPTO_AVAILABLE:
        return value
    return _ENC_PREFIX + _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value):
    if not value:
        return value
    if not str(value).startswith(_ENC_PREFIX):
        # Plaintext from before encryption was enabled, or crypto unavailable.
        return value
    if not CRYPTO_AVAILABLE:
        # Encrypted previously but the package is missing now: can't read it.
        return ""
    try:
        return _fernet().decrypt(value[len(_ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        return ""

SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "120"))


# ================================================================
# DATABASE
# ================================================================

def db():
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def column_names(conn, table):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def add_column_if_missing(conn, table, column, definition):
    if column not in column_names(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS students (
        adm_no TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        class TEXT NOT NULL,
        parent_phone TEXT,
        pay_code TEXT UNIQUE NOT NULL,
        balance REAL NOT NULL DEFAULT 0,
        total_paid REAL NOT NULL DEFAULT 0,
        total_fees REAL NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        adm_no TEXT,
        pay_code TEXT,
        amount REAL NOT NULL,
        mpesa_code TEXT UNIQUE,
        method TEXT NOT NULL DEFAULT 'MANUAL',
        phone TEXT,
        checkout_request_id TEXT,
        merchant_request_id TEXT,
        status TEXT NOT NULL DEFAULT 'SUCCESS',
        date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT,
        raw_data TEXT,
        reversed_at TEXT,
        reversed_by TEXT,
        reversal_reason TEXT,
        FOREIGN KEY(adm_no) REFERENCES students(adm_no)
    );

    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','bursar')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        role TEXT,
        action TEXT NOT NULL,
        adm_no TEXT,
        old_data TEXT,
        new_data TEXT,
        date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS term_fees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        term TEXT NOT NULL,
        grade TEXT NOT NULL,
        amount REAL NOT NULL,
        date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS daraja_config (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        ckey TEXT,
        csecret TEXT,
        shortcode TEXT,
        passkey TEXT,
        callback_url TEXT,
        env TEXT DEFAULT 'sandbox',
        c2b_validation_url TEXT,
        c2b_confirmation_url TEXT,
        c2b_registered INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS unmatched_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mpesa_code TEXT,
        amount REAL,
        phone TEXT,
        pay_code TEXT,
        adm_no TEXT,
        raw_data TEXT,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'UNRESOLVED',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        resolved_by TEXT,
        resolved_at TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS mpesa_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        adm_no TEXT NOT NULL,
        mpesa_code TEXT NOT NULL,
        expected_amount REAL NOT NULL,
        initiated_by TEXT,
        status TEXT NOT NULL DEFAULT 'PENDING',
        originator_conversation_id TEXT,
        conversation_id TEXT,
        payment_id INTEGER,
        raw_request TEXT,
        raw_result TEXT,
        attempts INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        FOREIGN KEY(adm_no) REFERENCES students(adm_no),
        FOREIGN KEY(payment_id) REFERENCES payments(id)
    );
    CREATE INDEX IF NOT EXISTS idx_mpesa_verif_status ON mpesa_verifications(status);
    CREATE INDEX IF NOT EXISTS idx_mpesa_verif_oconv ON mpesa_verifications(originator_conversation_id);
    CREATE INDEX IF NOT EXISTS idx_mpesa_verif_code ON mpesa_verifications(mpesa_code);

    CREATE TABLE IF NOT EXISTS academic_years (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, start_date TEXT, end_date TEXT, active INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS enrollments (id INTEGER PRIMARY KEY AUTOINCREMENT, adm_no TEXT NOT NULL, academic_year_id INTEGER NOT NULL, grade TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(adm_no, academic_year_id), FOREIGN KEY(adm_no) REFERENCES students(adm_no), FOREIGN KEY(academic_year_id) REFERENCES academic_years(id));
    CREATE TABLE IF NOT EXISTS fee_items (id INTEGER PRIMARY KEY AUTOINCREMENT, academic_year_id INTEGER NOT NULL, term TEXT NOT NULL, grade TEXT NOT NULL, category TEXT NOT NULL, amount REAL NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(academic_year_id) REFERENCES academic_years(id));
    CREATE INDEX IF NOT EXISTS idx_enrollments_year_grade ON enrollments(academic_year_id,grade);
    CREATE INDEX IF NOT EXISTS idx_enrollments_adm ON enrollments(adm_no);
    CREATE INDEX IF NOT EXISTS idx_fee_items_year ON fee_items(academic_year_id,term,grade);

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        notification_type TEXT NOT NULL DEFAULT 'INFO',
        adm_no TEXT,
        payment_id INTEGER,
        mpesa_code TEXT,
        amount REAL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(adm_no) REFERENCES students(adm_no),
        FOREIGN KEY(payment_id) REFERENCES payments(id)
    );

    CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read);
    CREATE INDEX IF NOT EXISTS idx_notifications_date ON notifications(created_at);

    CREATE TABLE IF NOT EXISTS ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        adm_no TEXT NOT NULL,
        entry_type TEXT NOT NULL,
        reference_type TEXT,
        reference_id INTEGER,
        description TEXT NOT NULL,
        debit REAL NOT NULL DEFAULT 0,
        credit REAL NOT NULL DEFAULT 0,
        running_balance REAL,
        academic_year_id INTEGER,
        created_by TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(adm_no) REFERENCES students(adm_no)
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_adm ON ledger(adm_no, id);
    CREATE INDEX IF NOT EXISTS idx_ledger_date ON ledger(created_at);
    CREATE INDEX IF NOT EXISTS idx_students_name ON students(name);
    CREATE INDEX IF NOT EXISTS idx_students_class ON students(class);
    CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(date);
    CREATE INDEX IF NOT EXISTS idx_payments_adm ON payments(adm_no);
    CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
    CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_checkout_request
        ON payments(checkout_request_id)
        WHERE checkout_request_id IS NOT NULL;
    """)

    # Migrations for older SchoolPay databases.
    add_column_if_missing(conn, "students", "total_fees", "REAL NOT NULL DEFAULT 0")
    add_column_if_missing(conn, "students", "active", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(conn, "students", "created_at", "TEXT")
    add_column_if_missing(conn, "students", "updated_at", "TEXT")

    add_column_if_missing(conn, "payments", "phone", "TEXT")
    add_column_if_missing(conn, "payments", "checkout_request_id", "TEXT")
    add_column_if_missing(conn, "payments", "merchant_request_id", "TEXT")
    add_column_if_missing(conn, "payments", "status", "TEXT NOT NULL DEFAULT 'SUCCESS'")
    add_column_if_missing(conn, "payments", "created_by", "TEXT")
    add_column_if_missing(conn, "payments", "raw_data", "TEXT")
    add_column_if_missing(conn, "payments", "reversed_at", "TEXT")
    add_column_if_missing(conn, "payments", "reversed_by", "TEXT")
    add_column_if_missing(conn, "payments", "reversal_reason", "TEXT")

    add_column_if_missing(conn, "daraja_config", "c2b_validation_url", "TEXT")
    add_column_if_missing(conn, "daraja_config", "c2b_confirmation_url", "TEXT")
    add_column_if_missing(conn, "daraja_config", "c2b_registered", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(conn, "daraja_config", "initiator_name", "TEXT")
    add_column_if_missing(conn, "daraja_config", "initiator_password", "TEXT")
    add_column_if_missing(conn, "daraja_config", "certificate_pem", "TEXT")
    add_column_if_missing(conn, "daraja_config", "ts_result_url", "TEXT")
    add_column_if_missing(conn, "daraja_config", "ts_timeout_url", "TEXT")
    add_column_if_missing(conn, "mpesa_verifications", "reason", "TEXT")

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS whatsapp_config (
        id INTEGER PRIMARY KEY CHECK (id=1),
        access_token TEXT,
        phone_number_id TEXT,
        api_version TEXT NOT NULL DEFAULT 'v20.0',
        enabled INTEGER NOT NULL DEFAULT 0,
        use_template_for_receipt INTEGER NOT NULL DEFAULT 0,
        receipt_template TEXT,
        receipt_template_lang TEXT NOT NULL DEFAULT 'en_US',
        use_template_for_reminder INTEGER NOT NULL DEFAULT 1,
        reminder_template TEXT,
        reminder_template_lang TEXT NOT NULL DEFAULT 'en_US',
        auto_reminder_enabled INTEGER NOT NULL DEFAULT 0,
        auto_reminder_interval_days INTEGER NOT NULL DEFAULT 7,
        auto_reminder_min_balance REAL NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS whatsapp_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        adm_no TEXT,
        phone TEXT,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        payment_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_whatsapp_log_adm ON whatsapp_log(adm_no, kind, created_at);
    """)

    add_column_if_missing(conn, "users", "must_change_password",
                          "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(conn, "users", "created_at", "TEXT")

    # For old records, reconstruct total fees from outstanding + paid.
    conn.execute("""
        UPDATE students
        SET total_fees = COALESCE(balance,0) + COALESCE(total_paid,0)
        WHERE COALESCE(total_fees,0)=0
          AND (COALESCE(balance,0) != 0 OR COALESCE(total_paid,0) != 0)
    """)
    conn.execute("""
        UPDATE students
        SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
            updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)
    """)

    # Default school settings.
    defaults = {
        "school_name": os.environ.get("SCHOOL_NAME", "SchoolPay"),
        "school_address": os.environ.get("SCHOOL_ADDRESS", "Kenya"),
        "school_phone": os.environ.get("SCHOOL_PHONE", ""),
        "currency": "KES",
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

    # One-time ledger seed for existing databases. This reconstructs each student's
    # current fee obligation and historical confirmed payments without changing balances.
    seeded = conn.execute("SELECT value FROM settings WHERE key='ledger_seeded'").fetchone()
    if not seeded:
        for st in conn.execute("SELECT adm_no,total_fees FROM students").fetchall():
            adm = st["adm_no"]
            if conn.execute("SELECT 1 FROM ledger WHERE adm_no=? LIMIT 1", (adm,)).fetchone():
                continue
            total_fees = float(st["total_fees"] or 0)
            if total_fees:
                conn.execute("INSERT INTO ledger(adm_no,entry_type,description,debit,credit,running_balance,created_by) VALUES(?,?,?,?,?,?,?)",
                             (adm, "OPENING", "Opening fee balance from existing SchoolPay records", total_fees, 0, total_fees - float(st["total_fees"] or 0) + total_fees, "SYSTEM"))
            running = total_fees
            for pay in conn.execute("SELECT id,amount,method,mpesa_code,date,created_by,status FROM payments WHERE adm_no=? ORDER BY id", (adm,)).fetchall():
                if pay["status"] == "REVERSED":
                    continue
                running -= float(pay["amount"] or 0)
                conn.execute("INSERT INTO ledger(adm_no,entry_type,reference_type,reference_id,description,debit,credit,running_balance,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (adm, "PAYMENT", "payment", pay["id"], "Historical payment" + (f" • {pay['mpesa_code']}" if pay["mpesa_code"] else ""), 0, float(pay["amount"] or 0), running, pay["created_by"] or "SYSTEM", pay["date"] or now()))
        conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('ledger_seeded','1')")

    current_year = datetime.now().year
    year_name = str(current_year)
    conn.execute("INSERT OR IGNORE INTO academic_years(name,active) VALUES(?,1)", (year_name,))
    conn.execute("UPDATE academic_years SET active=0 WHERE name<>?", (year_name,))
    year_id = conn.execute("SELECT id FROM academic_years WHERE name=?", (year_name,)).fetchone()["id"]
    for st in conn.execute("SELECT adm_no,class FROM students WHERE active=1").fetchall():
        conn.execute("INSERT OR IGNORE INTO enrollments(adm_no,academic_year_id,grade,status) VALUES(?,?,?,'ACTIVE')", (st["adm_no"], year_id, st["class"]))

    # Compatibility defaults. These accounts are forced to change password.
    count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count == 0:
        admin_pw = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")
        bursar_pw = os.environ.get("DEFAULT_BURSAR_PASSWORD", "bursar123")
        conn.execute("""
            INSERT INTO users(username,password_hash,role,must_change_password)
            VALUES(?,?,?,1)
        """, ("admin", generate_password_hash(admin_pw), "admin"))
        conn.execute("""
            INSERT INTO users(username,password_hash,role,must_change_password)
            VALUES(?,?,?,1)
        """, ("bursar", generate_password_hash(bursar_pw), "bursar"))

    conn.commit()
    conn.close()


init_db()


# ================================================================
# SETTINGS / HELPERS
# ================================================================

def setting(key, default=""):
    conn = db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = db()
    conn.execute("""
        INSERT INTO settings(key,value) VALUES(?,?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, value))
    conn.commit()
    conn.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def money(value):
    try:
        return f"KES {float(value or 0):,.2f}"
    except Exception:
        return "KES 0.00"


def normalize_phone(value):
    s = re.sub(r"\D", "", value or "")
    if s.startswith("00"):
        s = s[2:]
    if s.startswith("254"):
        return s
    if s.startswith("0") and len(s) == 10:
        return "254" + s[1:]
    if len(s) == 9 and s.startswith(("7", "1")):
        return "254" + s
    return s


def valid_msisdn(value):
    return bool(re.fullmatch(r"254[17]\d{8}", value or ""))


def safe_json(value):
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return "{}"


# ----------------------------------------------------------------
# Login rate limiting (in-memory, per username+IP).
# Not cluster-safe, but this app runs as a single process.
# ----------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "900"))  # 15 min
_login_attempts = {}
_login_lock = threading.Lock()


def _login_key():
    username = (request.form.get("username") or "").strip().lower()
    return f"{username}|{request.remote_addr or 'unknown'}"


def login_is_locked():
    key = _login_key()
    with _login_lock:
        entry = _login_attempts.get(key)
        if not entry:
            return False, 0
        count, first_fail, locked_until = entry
        if locked_until and time.time() < locked_until:
            return True, int(locked_until - time.time())
        if locked_until and time.time() >= locked_until:
            _login_attempts.pop(key, None)
    return False, 0


def login_record_failure():
    key = _login_key()
    now_ts = time.time()
    with _login_lock:
        count, first_fail, locked_until = _login_attempts.get(key, (0, now_ts, None))
        if now_ts - first_fail > LOGIN_LOCKOUT_SECONDS:
            count, first_fail = 0, now_ts
        count += 1
        if count >= LOGIN_MAX_ATTEMPTS:
            locked_until = now_ts + LOGIN_LOCKOUT_SECONDS
        _login_attempts[key] = (count, first_fail, locked_until)


def login_clear_failures():
    key = _login_key()
    with _login_lock:
        _login_attempts.pop(key, None)


def log_action(action, adm_no=None, old=None, new=None, username=None, role=None):
    conn = db()
    conn.execute("""
        INSERT INTO logs(username,role,action,adm_no,old_data,new_data)
        VALUES(?,?,?,?,?,?)
    """, (
        username or session.get("username"),
        role or session.get("role"),
        action,
        adm_no,
        safe_json(old) if old is not None else None,
        safe_json(new) if new is not None else None
    ))
    conn.commit()
    conn.close()


def csrf():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def csrf_input():
    return f'<input type="hidden" name="_csrf" value="{escape(csrf())}">'


def check_csrf():
    _j = request.get_json(silent=True) or {}
    supplied = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or _j.get("_csrf")
    expected = session.get("_csrf")
    if not supplied or not expected or not secrets.compare_digest(supplied, expected):
        abort(400, description="Invalid CSRF token")


def current_user():
    if not session.get("username"):
        return None
    return {
        "username": session.get("username"),
        "role": session.get("role"),
        "must_change_password": session.get("must_change_password", 0)
    }


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            if request.is_json or request.path.startswith("/stk_push") or request.headers.get("X-Requested-With")=="XMLHttpRequest":
                return jsonify(ok=False, error="Session expired - please reload page"), 401
            return redirect("/login")
        last_seen = session.get("last_seen")
        if last_seen:
            try:
                if datetime.now() - datetime.fromisoformat(last_seen) > timedelta(
                    minutes=SESSION_TIMEOUT_MINUTES
                ):
                    session.clear()
                    if request.is_json or request.path.startswith("/stk_push") or request.headers.get("X-Requested-With")=="XMLHttpRequest":
                        return jsonify(ok=False, error="Session expired - please reload page"), 401
                    return redirect("/login?msg=Session expired")
            except ValueError:
                pass
        session["last_seen"] = datetime.now().isoformat(timespec="seconds")


        endpoint = request.endpoint or ""
        if session.get("must_change_password") and endpoint not in {
            "change_password", "logout", "static"
        }:
            return redirect("/change_password")
        return fn(*args, **kwargs)
    return wrapper


def roles(*allowed):
    def decorator(fn):
        @functools.wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("role") not in allowed:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def layout(title, body, active=""):
    user = current_user()
    nav = ""
    if user:
        nav_items = [
            ("/", "Dashboard", "HOME"),
            ("/notifications", "Notifications", "ALERTS"),
            ("/students", "Students", "LIST"),
            ("/promote", "Promote", "MOVE"),
            ("/academic", "Academic Years", "YEAR"),
            ("/fee_structure", "Fee Structure", "FEES+"),
            ("/register", "Register", "ADD"),
            ("/new_term", "Fees", "FEES"),
            ("/pay", "Pay", "PAY"),
            ("/payments", "Payments", "HISTORY"),
            ("/reports", "Reports", "REPORT"),
            ("/reports/arrears", "Arrears", "OWED"),
            ("/reconciliation", "Reconcile", "MATCH"),
            ("/unmatched", "Unmatched", "CHECK"),
            ("/logs", "Logs", "AUDIT"),
            ("/daraja", "M-Pesa", "STK"),
            ("/whatsapp", "WhatsApp", "CHAT"),
            ("/settings", "Settings", "CONFIG"),
        ]
        if user["role"] == "admin":
            nav_items.append(("/users", "Users", "STAFF"))

        links = []
        for href, label, tag in nav_items:
            cls = "active" if active == label else ""
            links.append(f'<a class="{cls}" href="{href}"><span class="nav-main">{escape(label)}</span><span class="nav-tag">{escape(tag)}</span></a>')
        nav = f"""
        <aside>
          <div class="brand">SCHOOL<span>PAY</span><small>V10.4</small></div>
          <div class="userbox">
            <b>{escape(user["username"])}</b>
            <span>{escape(user["role"].upper())}</span>
          </div>
          <nav>{''.join(links)}</nav>
          <a class="logout" href="/logout">Logout</a>
        </aside>
        """

    school = escape(setting("school_name", "SchoolPay"))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} - {school}</title>
<style>
:root {{
 --bg:#0b1220; --panel:#111c2e; --panel2:#17243a; --line:#26364f;
 --text:#eef5ff; --muted:#9fb0c8; --accent:#ff7a45; --green:#23c483;
 --red:#ff5d73; --blue:#5da9ff; --yellow:#f6c85f;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:linear-gradient(135deg,#08101d,#101a2b);color:var(--text);
font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}}
a{{color:inherit;text-decoration:none}}
aside{{position:fixed;left:0;top:0;bottom:0;width:230px;background:#09111e;border-right:1px solid var(--line);
padding:22px 14px;display:flex;flex-direction:column;z-index:5}}
.brand{{font-size:24px;font-weight:900;letter-spacing:1px;padding:5px 10px 20px}}
.brand span{{color:var(--accent)}} .brand small{{font-size:10px;color:var(--muted);margin-left:5px}}
.userbox{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:12px;margin-bottom:14px}}
.userbox b{{display:block}} .userbox span{{font-size:11px;color:var(--accent)}}
nav{{display:flex;flex-direction:column;gap:5px;overflow:auto}}
nav a,.logout{{padding:10px 12px;border-radius:10px;color:var(--muted);font-weight:650}}
nav a{{display:flex;align-items:center;justify-content:space-between;gap:8px}}
nav a:hover,nav a.active{{background:var(--panel2);color:#fff}}
.nav-main{{font-size:13px}}
.nav-tag{{font-size:9px;font-weight:800;letter-spacing:.7px;padding:3px 6px;border:1px solid var(--line);border-radius:6px;color:#7f93ae;background:#0c1727}}
nav a.active .nav-tag{{color:var(--accent);border-color:rgba(255,122,69,.35)}}
.logout{{margin-top:auto;background:#1b1720;color:#ff9aaa}}
main{{margin-left:230px;padding:26px;min-height:100vh}}
.top{{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:22px}}
h1{{margin:0;font-size:27px}} h2{{margin-top:0}} h3{{margin-bottom:8px}}
.muted{{color:var(--muted)}} .small{{font-size:12px}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}}
.card,.panel{{background:rgba(17,28,46,.92);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 12px 30px rgba(0,0,0,.18)}}
.stat .label{{color:var(--muted);font-size:12px}} .stat .value{{font-size:25px;font-weight:850;margin-top:8px}}
.panel{{margin-top:16px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:11px 9px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}}
th{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
input,select,textarea{{width:100%;background:#0b1525;color:#fff;border:1px solid var(--line);border-radius:10px;padding:11px 12px;outline:none}}
input:focus,select:focus,textarea:focus{{border-color:var(--accent)}}
label{{font-size:12px;color:var(--muted);display:block;margin:12px 0 6px}}
.formgrid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 14px}}
button,.btn{{display:inline-block;border:0;border-radius:10px;padding:11px 15px;background:var(--accent);color:#10151d;
font-weight:800;cursor:pointer;margin-top:12px}}
.btn.secondary{{background:#24344d;color:#fff}} .btn.green{{background:var(--green);color:#07150f}}
.btn.red{{background:var(--red);color:#fff}} .btn.blue{{background:var(--blue);color:#07101c}}
.actions{{display:flex;gap:7px;flex-wrap:wrap}}
.badge{{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}}
.success{{background:rgba(35,196,131,.14);color:#66e0ae}} .danger{{background:rgba(255,93,115,.14);color:#ff91a1}}
.warn{{background:rgba(246,200,95,.14);color:#f7d77e}} .info{{background:rgba(93,169,255,.14);color:#91c5ff}}
.alert{{padding:12px 14px;border-radius:10px;background:#1b2b43;border:1px solid var(--line);margin-bottom:14px}}
.search{{display:flex;gap:8px;margin-bottom:12px;position:relative}} .search input{{flex:1}}
.autocomplete{{position:absolute;left:0;right:58px;top:calc(100% + 4px);background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 18px 40px rgba(0,0,0,.38);z-index:50;overflow:hidden;display:none}}
.autocomplete.show{{display:block}} .ac-item{{display:flex;gap:10px;align-items:center;padding:11px 13px;border-bottom:1px solid var(--line);cursor:pointer}}
.ac-item:last-child{{border-bottom:0}} .ac-item:hover,.ac-item.active{{background:var(--panel2)}} .ac-icon{{width:28px;height:28px;border-radius:8px;background:#1d2d47;display:grid;place-items:center;color:var(--accent);font-size:13px;font-weight:900}}
.ac-main{{min-width:0;flex:1}} .ac-title{{font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .ac-sub{{font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .ac-empty{{padding:13px;color:var(--muted);font-size:12px}}
@media(max-width:600px){{.autocomplete{{right:0}}}}
.kpi{{display:flex;justify-content:space-between;gap:15px;align-items:center}}
.progress{{height:8px;background:#0a1320;border-radius:20px;overflow:hidden;margin-top:8px}}
.progress>i{{display:block;height:100%;background:var(--green)}}
.loginwrap{{min-height:100vh;display:grid;place-items:center;padding:20px}}
.login{{width:min(420px,100%);background:var(--panel);border:1px solid var(--line);padding:28px;border-radius:20px}}
.login .brand{{padding-left:0}} .login h1{{font-size:24px;margin-bottom:5px}}
footer{{margin-top:25px;color:var(--muted);font-size:11px}}
@media(max-width:900px){{aside{{width:78px;padding:12px 7px}}.brand{{font-size:0;text-align:center}}.brand:after{{content:"SP";font-size:20px;color:var(--accent)}}.brand span,.brand small,.userbox span,.userbox b{{display:none}}nav a{{font-size:0;text-align:center;justify-content:center;padding:11px 5px}}.nav-main{{display:none}}.nav-tag{{font-size:8px;padding:4px 3px;min-width:48px;text-align:center}}.logout{{font-size:0;text-align:center}}.logout:before{{content:"↪ LOGOUT";font-size:9px}}main{{margin-left:78px;padding:16px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
@media(max-width:600px){{.grid,.formgrid{{grid-template-columns:1fr}}.top{{align-items:flex-start;flex-direction:column}}table{{display:block;overflow:auto;white-space:nowrap}}}}
@media print{{aside,.top .actions,.noprint{{display:none!important}}main{{margin:0;padding:0}}body{{background:#fff;color:#000}}.panel,.card{{box-shadow:none;color:#000;background:#fff}}}}
</style>
</head>
<body>
{nav}
<main>
{body}
<footer>{school} • SchoolPay V10.4 • SQLite</footer>
</main>
<script>
(function(){{
  const inputs=document.querySelectorAll('.search input[name="q"]');
  inputs.forEach(input=>{{
    const form=input.closest('form'); if(!form) return;
    form.style.position='relative';
    const box=document.createElement('div'); box.className='autocomplete'; form.appendChild(box);
    let timer=null, controller=null, active=-1, lastResults=[];
    function hide(){{box.classList.remove('show');box.innerHTML='';active=-1;}}
    function render(results){{
      lastResults=results||[]; active=-1;
      if(!input.value.trim()){{hide();return;}}
      if(!results.length){{box.innerHTML='<div class="ac-empty">No matching students or payments</div>';box.classList.add('show');return;}}
      box.innerHTML=results.map((r,i)=>'<div class="ac-item" data-i="'+i+'"><div class="ac-icon">'+r.icon+'</div><div class="ac-main"><div class="ac-title">'+esc(r.title)+'</div><div class="ac-sub">'+esc(r.subtitle)+'</div></div></div>').join('');
      box.querySelectorAll('.ac-item').forEach(item=>item.addEventListener('mousedown',e=>{{e.preventDefault();go(Number(item.dataset.i));}}));
      box.classList.add('show');
    }}
    function esc(v){{return String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));}}
    function go(i){{const r=lastResults[i];if(!r)return;window.location.href=r.url;}}
    async function search(){{
      const q=input.value.trim(); if(q.length<1){{hide();return;}}
      if(controller) controller.abort(); controller=new AbortController();
      try{{const res=await fetch('/api/smart-search?q='+encodeURIComponent(q),{{signal:controller.signal}});const d=await res.json();if(input.value.trim()===q)render(d.results||[]);}}catch(e){{if(e.name!=='AbortError')hide();}}
    }}
    input.addEventListener('input',()=>{{clearTimeout(timer);timer=setTimeout(search,120);}});
    input.addEventListener('keydown',e=>{{
      if(!box.classList.contains('show')||!lastResults.length)return;
      if(e.key==='ArrowDown'){{e.preventDefault();active=Math.min(active+1,lastResults.length-1);}}
      else if(e.key==='ArrowUp'){{e.preventDefault();active=Math.max(active-1,0);}}
      else if(e.key==='Enter'&&active>=0){{e.preventDefault();go(active);return;}}
      else if(e.key==='Escape'){{hide();return;}}
      box.querySelectorAll('.ac-item').forEach((x,i)=>x.classList.toggle('active',i===active));
    }});
    input.addEventListener('focus',()=>{{if(input.value.trim())search();}});
    document.addEventListener('click',e=>{{if(!form.contains(e.target))hide();}});
  }});
}})();
</script>
</body>
</html>"""


def page(title, content, active=""):
    return layout(title, content, active)


def login_page(message=""):
    alert = f'<div class="alert">{escape(message)}</div>' if message else ""
    body = f"""
    <div class="loginwrap">
      <div class="login">
        <div class="brand">SCHOOL<span>PAY</span><small>V10.4</small></div>
        <h1>Secure school fees management</h1>
        <p class="muted">Sign in to continue.</p>
        {alert}
        <form method="post">
          {csrf_input()}
          <label>Username</label><input name="username" required autocomplete="username">
          <label>Password</label><input name="password" type="password" required autocomplete="current-password">
          <button type="submit" style="width:100%">Sign in</button>
        </form>
        <p class="small muted">First-run compatibility accounts: admin/admin123 and bursar/bursar123. You will be forced to change the password.</p>
      </div>
    </div>
    """
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Login - SchoolPay</title>
    <style>
    body{{margin:0;background:#09111e;color:#eef5ff;font-family:system-ui}}.loginwrap{{min-height:100vh;display:grid;place-items:center;padding:20px}}
    .login{{width:min(420px,100%);background:#111c2e;border:1px solid #26364f;padding:28px;border-radius:20px}}
    .brand{{font-size:25px;font-weight:900}}.brand span{{color:#ff7a45}}.brand small{{font-size:10px;color:#9fb0c8}}
    .muted{{color:#9fb0c8}}label{{display:block;font-size:12px;color:#9fb0c8;margin:12px 0 6px}}
    input{{width:100%;box-sizing:border-box;background:#0b1525;color:#fff;border:1px solid #26364f;border-radius:10px;padding:11px}}
    button{{width:100%;border:0;border-radius:10px;padding:12px;background:#ff7a45;font-weight:800;margin-top:16px}}
    .alert{{padding:11px;border:1px solid #26364f;border-radius:10px;background:#1b2b43}}.small{{font-size:11px}}
    </style></head><body>{body}</body></html>"""


# ================================================================
# AUTH
# ================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect("/")
    if request.method == "POST":
        check_csrf()
        locked, retry_after = login_is_locked()
        if locked:
            minutes = max(1, retry_after // 60)
            return login_page(f"Too many failed attempts. Try again in about {minutes} minute(s).")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        ok = bool(user and check_password_hash(user["password_hash"], password))
        conn.close()
        if not ok:
            login_record_failure()
            log_action("FAILED_LOGIN", username=username, role=None)
            return login_page("Invalid username or password.")
        login_clear_failures()
        session.clear()
        session.permanent = True
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["must_change_password"] = int(user["must_change_password"])
        session["last_seen"] = datetime.now().isoformat(timespec="seconds")
        session["_csrf"] = secrets.token_urlsafe(32)
        log_action("LOGIN", username=user["username"], role=user["role"])
        if user["must_change_password"]:
            return redirect("/change_password")
        return redirect("/")
    return login_page(request.args.get("msg", ""))


@app.route("/logout")
def logout():
    if session.get("username"):
        log_action("LOGOUT")
    session.clear()
    return redirect("/login")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        check_csrf()
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username=?",
                            (session["username"],)).fetchone()
        if not user or not check_password_hash(user["password_hash"], current):
            conn.close()
            return page("Change password", '<div class="alert">Current password is incorrect.</div>', "")
        if len(new) < 10:
            conn.close()
            return page("Change password", '<div class="alert">Use at least 10 characters.</div>')
        if new != confirm:
            conn.close()
            return page("Change password", '<div class="alert">Passwords do not match.</div>')
        conn.execute("""
            UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?
        """, (generate_password_hash(new), session["username"]))
        conn.commit()
        conn.close()
        session["must_change_password"] = 0
        log_action("PASSWORD_CHANGED")
        return redirect("/")
    body = f"""
    <div class="top"><div><h1>Change password</h1><p class="muted">Your account requires a new password.</p></div></div>
    <div class="panel" style="max-width:520px">
      <form method="post">{csrf_input()}
        <label>Current password</label><input type="password" name="current_password" required>
        <label>New password</label><input type="password" name="new_password" required>
        <label>Confirm new password</label><input type="password" name="confirm_password" required>
        <button>Change password</button>
      </form>
    </div>"""
    return page("Change password", body)


# ================================================================
# NOTIFICATIONS
# ================================================================

def create_mpesa_notification(conn, payment_id, adm_no, student_name, amount, mpesa_code):
    conn.execute("""
        INSERT INTO notifications(title,message,notification_type,adm_no,payment_id,mpesa_code,amount)
        VALUES(?,?,?,?,?,?,?)
    """, (
        "M-Pesa Payment Received",
        f"{student_name or 'Student'} paid {money(amount)} by M-Pesa" +
        (f" • Receipt: {mpesa_code}" if mpesa_code else ""),
        "MPESA", adm_no, payment_id, mpesa_code, float(amount)
    ))


@app.route("/notifications")
@login_required
def notifications():
    conn = db()
    rows = conn.execute("""
        SELECT n.*, s.name AS student_name, s.class AS student_class
        FROM notifications n LEFT JOIN students s ON s.adm_no=n.adm_no
        ORDER BY n.id DESC LIMIT 200
    """).fetchall()
    unread = conn.execute("SELECT COUNT(*) n FROM notifications WHERE is_read=0").fetchone()["n"]
    conn.close()
    trs = ""
    for n in rows:
        cls = "success" if n["notification_type"] == "MPESA" else "info"
        read_cls = "" if n["is_read"] else "alert"
        action = "" if n["is_read"] else f'<form method="post" action="/notifications/{n["id"]}/read" class="noprint">{csrf_input()}<button class="btn secondary" style="margin:0">Mark read</button></form>'
        trs += f"""<tr class=\"{read_cls}\"><td>{escape(n["created_at"] or "")}</td>
          <td><span class=\"badge {cls}\">{escape(n["notification_type"] or "INFO")}</span></td>
          <td><b>{escape(n["title"])}</b><br><span class=\"small muted\">{escape(n["message"])}</span></td>
          <td>{escape(n["adm_no"] or "-")}</td><td>{money(n["amount"]) if n["amount"] is not None else "-"}</td>
          <td>{escape(n["mpesa_code"] or "-")}</td><td>{action}</td></tr>"""
    body = f"""
    <div class=\"top\"><div><h1>Notifications</h1><p class=\"muted\">Payment and system alerts. Unread: <b>{unread}</b></p></div>
      <form method=\"post\" action=\"/notifications/read-all\" class=\"noprint\">{csrf_input()}<button class=\"btn secondary\">Mark all read</button></form></div>
    <div class=\"panel\"><table><thead><tr><th>Date</th><th>Type</th><th>Notification</th><th>ADM</th><th>Amount</th><th>M-Pesa Receipt</th><th></th></tr></thead>
    <tbody>{trs or '<tr><td colspan=7>No notifications yet.</td></tr>'}</tbody></table></div>"""
    return page("Notifications", body, "Notifications")


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def notification_read(notification_id):
    check_csrf()
    conn = db()
    conn.execute("UPDATE notifications SET is_read=1 WHERE id=?", (notification_id,))
    conn.commit(); conn.close()
    return redirect(request.referrer or "/notifications")


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    check_csrf()
    conn = db(); conn.execute("UPDATE notifications SET is_read=1 WHERE is_read=0"); conn.commit(); conn.close()
    return redirect(request.referrer or "/notifications")


# ================================================================
# DASHBOARD
# ================================================================

@app.route("/")
@login_required
def dashboard():
    conn = db()
    students = conn.execute("""
        SELECT COUNT(*) n FROM students WHERE active=1
    """).fetchone()["n"]
    totals = conn.execute("""
        SELECT
          COALESCE(SUM(total_fees),0) fees,
          COALESCE(SUM(total_paid),0) paid,
          COALESCE(SUM(CASE WHEN total_fees-total_paid > 0 THEN total_fees-total_paid ELSE 0 END),0) owed
        FROM students WHERE active=1
    """).fetchone()
    today_paid = conn.execute("""
        SELECT COALESCE(SUM(amount),0) n FROM payments
        WHERE status='SUCCESS' AND reversed_at IS NULL
        AND date(date)=date('now','localtime')
    """).fetchone()["n"]
    pending = conn.execute("""
        SELECT COUNT(*) n FROM payments WHERE status='PENDING'
    """).fetchone()["n"]
    unread_notifications = conn.execute("SELECT COUNT(*) n FROM notifications WHERE is_read=0").fetchone()["n"]
    notifications_recent = conn.execute("""
        SELECT n.*, s.name AS student_name
        FROM notifications n LEFT JOIN students s ON s.adm_no=n.adm_no
        ORDER BY n.id DESC LIMIT 6
    """).fetchall()
    recent = conn.execute("""
        SELECT p.*, s.name
        FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no
        ORDER BY p.id DESC LIMIT 8
    """).fetchall()
    high = conn.execute("""
        SELECT * FROM students
        WHERE active=1 ORDER BY balance DESC LIMIT 6
    """).fetchall()
    conn.close()

    fees = float(totals["fees"] or 0)
    paid = float(totals["paid"] or 0)
    pct = min(100, max(0, paid / fees * 100)) if fees else 0

    rows = ""
    for p in recent:
        status = p["status"]
        cls = "success" if status == "SUCCESS" else "warn" if status == "PENDING" else "danger"
        rows += f"""
        <tr><td>{escape(p["date"] or "")}</td>
        <td>{escape(p["adm_no"] or "-")}</td><td>{escape(p["name"] or "-")}</td>
        <td>{money(p["amount"])}</td><td>{escape(p["method"] or "")}</td>
        <td><span class="badge {cls}">{escape(status)}</span></td></tr>"""

    high_rows = "".join(
        f'<tr><td>{escape(s["adm_no"])}</td><td>{escape(s["name"])}</td>'
        f'<td>{escape(s["class"])}</td><td>{money(s["balance"])}</td></tr>'
        for s in high
    )

    body = f"""
    <div class="top"><div><h1>Dashboard</h1><p class="muted">Welcome, {escape(session["username"])}.</p></div>
      <div class="actions"><a class="btn secondary" href="/export/payments">Export payments</a><a class="btn" href="/backup">Backup DB</a></div>
    </div>
    <div class="grid">
      <div class="card stat"><div class="label">Active Students</div><div class="value">{students:,}</div></div>
      <div class="card stat"><div class="label">Total Fees</div><div class="value">{money(fees)}</div></div>
      <div class="card stat"><div class="label">Collected</div><div class="value">{money(paid)}</div></div>
      <div class="card stat"><div class="label">Outstanding</div><div class="value">{money(totals["owed"])}</div></div>
    </div>
    <div class="panel">
      <div class="kpi"><b>Collection progress</b><span>{pct:.1f}%</span></div>
      <div class="progress"><i style="width:{pct:.1f}%"></i></div>
      <p class="small muted">Today's confirmed collections: {money(today_paid)} • Pending STK: {pending}</p>
    </div>
    <div class="panel" id="notifications">
      <div class="kpi"><div><h3 style="margin:0">Notifications <span class="badge info">{unread_notifications} unread</span></h3><p class="small muted">M-Pesa payments appear here automatically.</p></div><a class="btn secondary" href="/notifications">View all</a></div>
      <table><thead><tr><th>Date</th><th>Type</th><th>Student</th><th>Amount</th><th>Receipt</th><th>Status</th></tr></thead>
      <tbody>{''.join(f'<tr><td>{escape(n["created_at"] or "")}</td><td><span class="badge success">M-PESA</span></td><td>{escape(n["student_name"] or n["adm_no"] or "-")}</td><td>{money(n["amount"])}</td><td>{escape(n["mpesa_code"] or "-")}</td><td>{"NEW" if not n["is_read"] else "READ"}</td></tr>' for n in notifications_recent) or '<tr><td colspan="6">No notifications yet.</td></tr>'}</tbody></table>
    </div>
    <div class="panel"><h3>Recent payments</h3>
      <table><thead><tr><th>Date</th><th>ADM</th><th>Student</th><th>Amount</th><th>Method</th><th>Status</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="6">No payments yet.</td></tr>'}</tbody></table>
    </div>
    <div class="panel"><h3>Highest outstanding balances</h3>
      <table><thead><tr><th>ADM</th><th>Name</th><th>Class</th><th>Balance</th></tr></thead>
      <tbody>{high_rows or '<tr><td colspan="4">No students.</td></tr>'}</tbody></table>
    </div>
    """
    return page("Dashboard", body, "Dashboard")


# ================================================================
# ACADEMIC YEARS / FEE STRUCTURE
# ================================================================

def current_academic_year(conn=None):
    own = conn is None
    if own: conn = db()
    row = conn.execute("SELECT * FROM academic_years WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone()
    if not row: row = conn.execute("SELECT * FROM academic_years ORDER BY id DESC LIMIT 1").fetchone()
    if own: conn.close()
    return row

@app.route("/academic", methods=["GET", "POST"])
@roles("admin")
def academic_years():
    conn=db()
    if request.method == "POST":
        check_csrf(); action=request.form.get("action")
        if action == "create":
            name=request.form.get("name","").strip(); start=request.form.get("start_date","").strip() or None; end=request.form.get("end_date","").strip() or None
            if not re.fullmatch(r"20\d{2}(-20\d{2})?",name): conn.close(); return page("Academic Years",'<div class="alert">Use a year such as 2027 or 2027-2028.</div>',"Academic Years")
            try:
                conn.execute("INSERT INTO academic_years(name,start_date,end_date,active) VALUES(?,?,?,0)",(name,start,end)); conn.commit(); log_action("CREATE_ACADEMIC_YEAR",new={"name":name})
            except sqlite3.IntegrityError:
                conn.rollback(); conn.close(); return page("Academic Years",'<div class="alert">That academic year already exists.</div>',"Academic Years")
        elif action == "activate":
            aid=int(request.form.get("year_id",0) or 0); row=conn.execute("SELECT * FROM academic_years WHERE id=?",(aid,)).fetchone()
            if row:
                conn.execute("UPDATE academic_years SET active=0"); conn.execute("UPDATE academic_years SET active=1 WHERE id=?",(aid,)); conn.commit(); log_action("ACTIVATE_ACADEMIC_YEAR",new={"year_id":aid,"name":row["name"]})
    rows=conn.execute("SELECT * FROM academic_years ORDER BY name DESC").fetchall(); active=current_academic_year(conn); conn.close()
    trs = ""
    for x in rows:
        status = '<span class="badge success">ACTIVE</span>' if x["active"] else '<span class="badge info">INACTIVE</span>'
        action = "" if x["active"] else f'<form method="post" style="display:inline">{csrf_input()}<input type="hidden" name="action" value="activate"><input type="hidden" name="year_id" value="{x["id"]}"><button class="btn secondary">Set Active</button></form>'
        trs += f'<tr><td>{escape(x["name"])}</td><td>{escape(x["start_date"] or "-")}</td><td>{escape(x["end_date"] or "-")}</td><td>{status}</td><td>{action}</td></tr>'

    body=f"""<div class="top"><div><h1>Academic Years</h1><p class="muted">Keep each year's enrollment history separate.</p></div></div><div class="alert">Current active year: <b>{escape(active["name"] if active else "None")}</b></div><div class="panel" style="max-width:760px"><h3>Create academic year</h3><form method="post">{csrf_input()}<input type="hidden" name="action" value="create"><div class="formgrid"><div><label>Year</label><input name="name" placeholder="2027" required></div><div><label>Start date</label><input type="date" name="start_date"></div><div><label>End date</label><input type="date" name="end_date"></div></div><button>Create year</button></form></div><div class="panel"><h3>Academic years</h3><table><thead><tr><th>Year</th><th>Start</th><th>End</th><th>Status</th><th></th></tr></thead><tbody>{trs}</tbody></table></div>"""
    return page("Academic Years",body,"Academic Years")

@app.route("/fee_structure", methods=["GET", "POST"])
@roles("admin", "bursar")
def fee_structure():
    conn=db(); years=conn.execute("SELECT * FROM academic_years ORDER BY name DESC").fetchall(); active=current_academic_year(conn)
    if request.method == "POST":
        check_csrf()
        try: year_id=int(request.form.get("academic_year_id") or active["id"]); term=request.form.get("term","").strip(); grade=request.form.get("grade","").strip() or "ALL"; category=request.form.get("category","").strip(); amount=float(request.form.get("amount") or 0)
        except (ValueError,TypeError): conn.close(); return page("Fee Structure",'<div class="alert">Enter valid fee details.</div>',"Fee Structure")
        if not term or not category or amount<=0: conn.close(); return page("Fee Structure",'<div class="alert">Term, category and a positive amount are required.</div>',"Fee Structure")
        if conn.execute("SELECT id FROM fee_items WHERE academic_year_id=? AND term=? AND grade=? AND category=?",(year_id,term,grade,category)).fetchone(): conn.close(); return page("Fee Structure",'<div class="alert">That fee category already exists for this year, term and grade.</div>',"Fee Structure")
        sql="SELECT adm_no,total_fees,total_paid FROM students WHERE active=1"+(" AND class=?" if grade!="ALL" else ""); students=conn.execute(sql,(grade,) if grade!="ALL" else ()).fetchall()
        conn.execute("INSERT INTO fee_items(academic_year_id,term,grade,category,amount) VALUES(?,?,?,?,?)",(year_id,term,grade,category,amount))
        for st in students:
            nf=float(st["total_fees"] or 0)+amount; nb=nf-float(st["total_paid"] or 0); conn.execute("UPDATE students SET total_fees=?,balance=?,updated_at=CURRENT_TIMESTAMP WHERE adm_no=?",(nf,nb,st["adm_no"]))
        conn.execute("INSERT INTO term_fees(term,grade,amount) VALUES(?,?,?)",(term,grade,amount)); conn.commit(); conn.close(); log_action("APPLY_FEE_CATEGORY",new={"academic_year_id":year_id,"term":term,"grade":grade,"category":category,"amount":amount,"students":len(students)}); return redirect("/fee_structure?msg=Fee+category+applied")
    items=conn.execute("SELECT f.*,a.name year_name FROM fee_items f JOIN academic_years a ON a.id=f.academic_year_id ORDER BY f.id DESC LIMIT 200").fetchall(); grades=conn.execute("SELECT DISTINCT class FROM students WHERE active=1 ORDER BY class").fetchall(); msg=request.args.get("msg")
    year_opts="".join(f'<option value="{x["id"]}" {"selected" if active and x["id"]==active["id"] else ""}>{escape(x["name"])}</option>' for x in years); grade_opts='<option value="ALL">All active students</option>'+"".join(f'<option value="{escape(x["class"])}">{escape(x["class"])}</option>' for x in grades); trs="".join(f'<tr><td>{escape(x["year_name"])}</td><td>{escape(x["term"])}</td><td>{escape(x["grade"])}</td><td>{escape(x["category"])}</td><td>{money(x["amount"])}</td><td>{escape(x["created_at"])}</td></tr>' for x in items); conn.close()
    body=f"""<div class="top"><div><h1>Fee Structure</h1><p class="muted">Set tuition, transport, lunch, activity, exam and other categories by year and term.</p></div></div>{f'<div class="alert success">{escape(msg)}</div>' if msg else ""}<div class="panel" style="max-width:820px"><form method="post">{csrf_input()}<div class="formgrid"><div><label>Academic year</label><select name="academic_year_id">{year_opts}</select></div><div><label>Term</label><input name="term" placeholder="Term 1" required></div><div><label>Grade</label><select name="grade">{grade_opts}</select></div><div><label>Category</label><input name="category" list="fee-cats" placeholder="Tuition" required></div><div><label>Amount (KES)</label><input name="amount" type="number" min="0.01" step="0.01" required></div></div><datalist id="fee-cats"><option value="Tuition"><option value="Activity"><option value="Transport"><option value="Lunch"><option value="Exam"><option value="Uniform"><option value="Other"></datalist><button>Apply Fee Category</button></form></div><div class="panel"><h3>Fee history</h3><table><thead><tr><th>Year</th><th>Term</th><th>Grade</th><th>Category</th><th>Amount</th><th>Date</th></tr></thead><tbody>{trs or '<tr><td colspan="6">No fee categories yet.</td></tr>'}</tbody></table></div>"""
    return page("Fee Structure",body,"Fee Structure")

# ================================================================
# STUDENTS
# ================================================================

@app.route("/api/smart-search")
@roles("admin", "bursar")
def smart_search():
    q = request.args.get("q", "").strip()
    if len(q) < 1:
        return jsonify(ok=True, results=[])
    # Escape LIKE wildcards so the search behaves predictably.
    term = q
    like = f"%{term}%"
    starts = f"{term}%"
    conn = db()
    try:
        students = conn.execute("""
            SELECT adm_no,name,class,parent_phone,pay_code,balance,total_paid,active
            FROM students
            WHERE active=1 AND (adm_no LIKE ? OR name LIKE ? OR class LIKE ? OR pay_code LIKE ? OR parent_phone LIKE ?)
            ORDER BY CASE WHEN adm_no LIKE ? THEN 0 WHEN pay_code LIKE ? THEN 1 WHEN name LIKE ? THEN 2 ELSE 3 END, name
            LIMIT 8
        """, (like,like,like,like,like,starts,starts,starts)).fetchall()
        payments = conn.execute("""
            SELECT p.id,p.mpesa_code,p.amount,p.status,p.adm_no,s.name
            FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no
            WHERE p.mpesa_code LIKE ? OR p.adm_no LIKE ?
            ORDER BY p.id DESC LIMIT 4
        """, (like,like)).fetchall()
    finally:
        conn.close()
    results=[]
    for x in students:
        results.append({"type":"student","icon":"S","title":x["name"],"subtitle":f'ADM {x["adm_no"]} • {x["class"] or "No class"} • {x["pay_code"]}',"url":f'/student/{x["adm_no"]}',"adm_no":x["adm_no"]})
    for x in payments:
        results.append({"type":"payment","icon":"₿","title":f'Payment {x["mpesa_code"] or "Pending"}',"subtitle":f'{x["name"] or x["adm_no"]} • {money(x["amount"])} • {x["status"]}',"url":f'/payment/{x["id"]}/receipt' if str(x["status"]).upper() in ("SUCCESS","CONFIRMED") else f'/payments?q={x["mpesa_code"] or x["adm_no"]}'})
    return jsonify(ok=True, results=results[:10])


@app.route("/students")
@login_required
def students():
    q = request.args.get("q", "").strip()
    include_inactive = request.args.get("inactive") == "1"
    conn = db()
    if q:
        like = f"%{q}%"
        sql = """
        SELECT * FROM students
        WHERE (adm_no LIKE ? OR name LIKE ? OR class LIKE ? OR pay_code LIKE ?)
        """
        args = [like, like, like, like]
        if not include_inactive:
            sql += " AND active=1"
        sql += " ORDER BY name"
        rows = conn.execute(sql, args).fetchall()
    else:
        sql = "SELECT * FROM students"
        if not include_inactive:
            sql += " WHERE active=1"
        sql += " ORDER BY name"
        rows = conn.execute(sql).fetchall()
    conn.close()

    trs = ""
    for s in rows:
        status = '<span class="badge success">ACTIVE</span>' if s["active"] else '<span class="badge danger">ARCHIVED</span>'
        trs += f"""
        <tr>
          <td>{escape(s["adm_no"])}</td><td>{escape(s["name"])}</td><td>{escape(s["class"])}</td>
          <td>{escape(s["parent_phone"] or "-")}</td><td>{escape(s["pay_code"])}</td>
          <td>{money(s["total_fees"])}</td><td>{money(s["total_paid"])}</td><td>{money(s["balance"])}</td>
          <td>{status}</td>
          <td><a class="btn secondary" href="/student/{escape(s["adm_no"])}">View</a></td>
        </tr>"""
    body = f"""
    <div class="top"><div><h1>Students</h1><p class="muted">{len(rows)} record(s)</p></div>
      <div class="actions"><a class="btn" href="/register">Register student</a><a class="btn secondary" href="/register/import">Import CSV</a></div>
    </div>
    <form class="search"><input name="q" value="{escape(q)}" placeholder="Search ADM, name, class or pay code">
      <button>Search</button><a class="btn secondary" href="/students">Clear</a>
    </form>
    <div class="panel"><table><thead><tr>
      <th>ADM</th><th>Name</th><th>Class</th><th>Phone</th><th>Pay Code</th><th>Fees</th><th>Paid</th><th>Balance</th><th>Status</th><th></th>
    </tr></thead><tbody>{trs or '<tr><td colspan="10">No students found.</td></tr>'}</tbody></table></div>
    """
    return page("Students", body, "Students")


@app.route("/promote", methods=["GET", "POST"])
@roles("admin", "bursar")
def promote_students():
    """Bulk move active students from one grade/class to another."""
    conn = db()
    try:
        classes = [r["class"] for r in conn.execute(
            "SELECT DISTINCT class FROM students WHERE active=1 AND class IS NOT NULL AND TRIM(class)<>'' ORDER BY class"
        ).fetchall()]

        if request.method == "POST":
            check_csrf()
            from_grade = request.form.get("from_grade", "").strip()
            to_grade = request.form.get("to_grade", "").strip()
            selected = [x.strip() for x in request.form.getlist("adm_no") if x.strip()]
            try: target_year_id=int(request.form.get("target_year_id") or 0)
            except ValueError: target_year_id=0
            target_year=conn.execute("SELECT * FROM academic_years WHERE id=?",(target_year_id,)).fetchone() if target_year_id else current_academic_year(conn)

            if not from_grade or not to_grade:
                return page("Promote Students", '<div class="alert">Select both the current grade and the new grade.</div>', "Promote")
            if from_grade == to_grade:
                return page("Promote Students", '<div class="alert">The current grade and new grade cannot be the same.</div>', "Promote")
            if not selected:
                return page("Promote Students", '<div class="alert">Select at least one student to promote.</div>', "Promote")
            if not target_year:
                return page("Promote Students", '<div class="alert">Select a valid target academic year.</div>', "Promote")

            placeholders = ",".join("?" for _ in selected)
            rows = conn.execute(
                f"SELECT adm_no,name,class FROM students WHERE active=1 AND class=? AND adm_no IN ({placeholders}) ORDER BY name",
                [from_grade, *selected]
            ).fetchall()
            if not rows:
                return page("Promote Students", '<div class="alert">No selected active students are currently in the chosen grade.</div>', "Promote")

            adms = [r["adm_no"] for r in rows]
            placeholders = ",".join("?" for _ in adms)
            conn.execute("BEGIN")
            conn.execute(
                f"UPDATE students SET class=?, updated_at=CURRENT_TIMESTAMP WHERE active=1 AND class=? AND adm_no IN ({placeholders})",
                [to_grade, from_grade, *adms]
            )
            for adm in adms:
                conn.execute("UPDATE enrollments SET status='PROMOTED' WHERE adm_no=? AND academic_year_id=?",(adm,target_year["id"]))
                conn.execute("INSERT INTO enrollments(adm_no,academic_year_id,grade,status) VALUES(?,?,?,'ACTIVE') ON CONFLICT(adm_no,academic_year_id) DO UPDATE SET grade=excluded.grade,status='ACTIVE'",(adm,target_year["id"],to_grade))
            conn.execute(
                "INSERT INTO logs(username,role,action,adm_no,old_data,new_data) VALUES(?,?,?,?,?,?)",
                (
                    session.get("username"), session.get("role"), "BULK_GRADE_PROMOTION", None,
                    safe_json({"from_grade": from_grade, "to_grade": to_grade, "target_year": target_year["name"], "students": adms}),
                    safe_json({"from_grade": from_grade, "to_grade": to_grade, "target_year": target_year["name"], "count": len(adms), "admission_numbers": adms})
                )
            )
            conn.commit()
            return redirect(f"/promote?msg={len(adms)} student(s) moved from {from_grade} to {to_grade} for {target_year["name"]}")

        from_grade = request.args.get("from_grade", "").strip()
        msg = request.args.get("msg", "")
        academic_years_list = conn.execute("SELECT * FROM academic_years ORDER BY name DESC").fetchall()
        active_year = current_academic_year(conn)
        rows = []
        if from_grade:
            rows = conn.execute(
                "SELECT adm_no,name,class,parent_phone,pay_code,balance FROM students WHERE active=1 AND class=? ORDER BY name",
                (from_grade,)
            ).fetchall()

        options = ''.join(
            f'<option value="{escape(c)}" {"selected" if c == from_grade else ""}>{escape(c)}</option>'
            for c in classes
        )
        student_rows = ''.join(
            f"""<tr>
              <td><input type="checkbox" name="adm_no" value="{escape(r['adm_no'])}" form="promotion-form" class="student-check"></td>
              <td>{escape(r['adm_no'])}</td><td><b>{escape(r['name'])}</b></td>
              <td>{escape(r['class'])}</td><td>{escape(r['parent_phone'] or '-')}</td>
              <td>{escape(r['pay_code'])}</td><td>{money(r['balance'])}</td>
            </tr>"""
            for r in rows
        )

        table_form = ''
        if from_grade:
            table_form = f"""
            <form method="post" id="promotion-form">{csrf_input()}
            <input type="hidden" name="from_grade" value="{escape(from_grade)}">
            <div class="panel" style="margin-bottom:12px"><label>Target academic year</label><select name="target_year_id" required>{''.join(f'<option value="{y["id"]}" {"selected" if active_year and y["id"]==active_year["id"] else ""}>{escape(y["name"])}</option>' for y in academic_years_list)}</select><p class="small muted">The promotion is also saved in the selected year's enrollment history.</p></div>
            <div class="panel">
              <div class="top"><div><h3>2. Select students</h3><p class="muted">{len(rows)} active student(s) in {escape(from_grade)}.</p></div>
                <div class="actions"><button type="button" class="btn secondary" onclick="toggleStudents(true)">Select All</button>
                <button type="button" class="btn secondary" onclick="toggleStudents(false)">Clear</button></div>
              </div>
              <div style="overflow:auto"><table><thead><tr><th><input type="checkbox" onclick="toggleStudents(this.checked)"></th><th>ADM</th><th>Name</th><th>Current Grade</th><th>Phone</th><th>Pay Code</th><th>Balance</th></tr></thead>
              <tbody>{student_rows or '<tr><td colspan="7">No active students found in this grade.</td></tr>'}</tbody></table></div>
            </div>
            <div class="panel" style="max-width:760px"><h3>3. Choose the new grade</h3>
              <div class="formgrid"><div><label>Current grade</label><input value="{escape(from_grade)}" disabled></div>
              <div><label>New grade</label><input name="to_grade" list="grade-list" placeholder="e.g. Grade 7" required></div></div>
              <datalist id="grade-list">{''.join(f'<option value="{escape(c)}">' for c in classes)}</datalist>
              <p class="small muted">Payment history, balances, ADM numbers and pay codes will not be changed.</p>
              <button type="submit" onclick="return confirmPromotion()">Promote Selected Students</button>
            </div></form>
            """

        body = f"""
        <div class="top"><div><h1>Student Promotion</h1><p class="muted">Move students to their next grade without changing payment history.</p></div></div>
        {f'<div class="alert success">{escape(msg)}</div>' if msg else ''}
        <div class="panel"><h3>1. Choose the current grade</h3>
          <form method="get" class="search"><select name="from_grade" required><option value="">Select current grade</option>{options}</select><button>Load Students</button></form>
        </div>
        {table_form}
        <script>
        function toggleStudents(checked) {{ document.querySelectorAll('.student-check').forEach(function(cb) {{ cb.checked = checked; }}); }}
        function confirmPromotion() {{
          const selected=document.querySelectorAll('.student-check:checked').length;
          const to=document.querySelector('input[name="to_grade"]').value.trim();
          const from=document.querySelector('input[name="from_grade"]').value.trim();
          if(!selected){{alert('Select at least one student.');return false;}}
          if(!to){{alert('Enter the new grade.');return false;}}
          return confirm('Move '+selected+' student(s) from '+from+' to '+to+'?\n\nTheir payment history, balances, ADM numbers and pay codes will remain unchanged.');
        }}
        </script>
        """
        return page("Promote Students", body, "Promote")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/register", methods=["GET", "POST"])
@roles("admin", "bursar")
def register():
    if request.method == "POST":
        check_csrf()
        adm = request.form.get("adm_no", "").strip()
        name = request.form.get("name", "").strip()
        grade = request.form.get("class", "").strip()
        phone = normalize_phone(request.form.get("parent_phone", ""))
        try:
            initial_fee = float(request.form.get("initial_fee", "0") or 0)
        except ValueError:
            initial_fee = -1
        if not adm or not name or not grade or initial_fee < 0:
            return page("Register", '<div class="alert">Enter valid student details and a non-negative fee.</div>', "Register")
        if phone and not valid_msisdn(phone):
            return page("Register", '<div class="alert">Use a valid Kenyan phone number.</div>', "Register")
        pay_code = "SCH-" + re.sub(r"[^A-Za-z0-9]", "", adm)[-4:].upper() + "-" + secrets.token_hex(2).upper()
        conn = db()
        try:
            conn.execute("""
                INSERT INTO students(adm_no,name,class,parent_phone,pay_code,balance,total_paid,total_fees)
                VALUES(?,?,?,?,?,?,?,?)
            """, (adm, name, grade, phone, pay_code, initial_fee, 0, initial_fee))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            conn.close()
            return page("Register", '<div class="alert">ADM number or generated pay code already exists.</div>', "Register")
        conn.close()
        log_action("REGISTER_STUDENT", adm_no=adm, new={
            "name": name, "class": grade, "parent_phone": phone,
            "pay_code": pay_code, "total_fees": initial_fee
        })
        return redirect(f"/student/{adm}?msg=Student registered")
    body = f"""
    <div class="top"><div><h1>Register student</h1><p class="muted">A unique SCH pay code is generated automatically.</p></div></div>
    <div class="panel" style="max-width:760px"><form method="post">{csrf_input()}
      <div class="formgrid">
        <div><label>Admission number</label><input name="adm_no" required></div>
        <div><label>Student name</label><input name="name" required></div>
        <div><label>Class / Grade</label><input name="class" required></div>
        <div><label>Parent phone</label><input name="parent_phone" placeholder="0712345678"></div>
        <div><label>Initial fees charged</label><input name="initial_fee" type="number" min="0" step="0.01" value="0"></div>
      </div>
      <button>Register student</button>
    </form></div>"""
    return page("Register", body, "Register")


@app.route("/register/import", methods=["GET", "POST"])
@roles("admin", "bursar")
def import_students():
    if request.method == "POST":
        check_csrf()
        f = request.files.get("file")
        if not f:
            return page("Import CSV", '<div class="alert">Choose a CSV file.</div>', "Students")
        try:
            text = f.read().decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            required = {"adm_no", "name", "class", "parent_phone", "balance"}
            if not required.issubset(set(reader.fieldnames or [])):
                return page("Import CSV", '<div class="alert">CSV headers must include: adm_no,name,class,parent_phone,balance</div>', "Students")
            conn = db()
            added = 0
            skipped = 0
            for row in reader:
                adm = (row.get("adm_no") or "").strip()
                name = (row.get("name") or "").strip()
                grade = (row.get("class") or "").strip()
                phone = normalize_phone(row.get("parent_phone") or "")
                try:
                    fee = float(row.get("balance") or 0)
                except ValueError:
                    skipped += 1
                    continue
                if not adm or not name or not grade or fee < 0:
                    skipped += 1
                    continue
                code = "SCH-" + re.sub(r"[^A-Za-z0-9]", "", adm)[-4:].upper() + "-" + secrets.token_hex(2).upper()
                try:
                    conn.execute("""
                        INSERT INTO students(adm_no,name,class,parent_phone,pay_code,balance,total_paid,total_fees)
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (adm,name,grade,phone,code,fee,0,fee))
                    added += 1
                except sqlite3.IntegrityError:
                    skipped += 1
            conn.commit()
            conn.close()
            log_action("IMPORT_STUDENTS", new={"added": added, "skipped": skipped})
            return page("Import CSV", f'<div class="alert">Imported {added}; skipped {skipped}.</div><a class="btn" href="/students">View students</a>', "Students")
        except Exception as e:
            return page("Import CSV", f'<div class="alert">Import failed: {escape(str(e))}</div>', "Students")
    body = f"""
    <div class="top"><div><h1>Import students</h1><p class="muted">Existing ADM numbers are skipped.</p></div></div>
    <div class="panel" style="max-width:700px"><p>Required CSV headers:</p>
    <code>adm_no,name,class,parent_phone,balance</code>
    <form method="post" enctype="multipart/form-data">{csrf_input()}
      <label>CSV file</label><input type="file" name="file" accept=".csv" required>
      <button>Import</button>
    </form></div>"""
    return page("Import CSV", body, "Students")


@app.route("/student/<adm>")
@login_required
def student_detail(adm):
    conn = db()
    s = conn.execute("SELECT * FROM students WHERE adm_no=?", (adm,)).fetchone()
    payments = conn.execute("""
        SELECT * FROM payments WHERE adm_no=? ORDER BY id DESC LIMIT 30
    """, (adm,)).fetchall()
    enrollment = conn.execute("""
        SELECT e.*, a.name AS year_name FROM enrollments e JOIN academic_years a ON a.id=e.academic_year_id
        WHERE e.adm_no=? ORDER BY a.name DESC, e.id DESC
    """, (adm,)).fetchall()
    conn.close()
    if not s:
        abort(404)
    msg = request.args.get("msg")
    alert = f'<div class="alert">{escape(msg)}</div>' if msg else ""
    rows = "".join(
        f'<tr><td>{escape(p["date"] or "")}</td><td>{money(p["amount"])}</td>'
        f'<td>{escape(p["method"] or "")}</td><td>{escape(p["mpesa_code"] or "-")}</td>'
        f'<td><span class="badge {"success" if p["status"]=="SUCCESS" else "warn"}">{escape(p["status"])}</span></td></tr>'
        for p in payments
    )
    body = f"""
    <div class="top"><div><h1>{escape(s["name"])}</h1><p class="muted">{escape(s["adm_no"])} • {escape(s["class"])}</p></div>
      <div class="actions"><a class="btn secondary" href="/student/{escape(adm)}/edit">Edit</a>
      <a class="btn blue" href="/student/{escape(adm)}/statement" target="_blank">Statement / Print</a>
      <a class="btn" href="/pay?adm_no={escape(adm)}">Record payment</a></div>
    </div>
    {alert}
    <div class="grid">
      <div class="card stat"><div class="label">Pay Code</div><div class="value" style="font-size:19px">{escape(s["pay_code"])}</div></div>
      <div class="card stat"><div class="label">Total Fees</div><div class="value">{money(s["total_fees"])}</div></div>
      <div class="card stat"><div class="label">Paid</div><div class="value">{money(s["total_paid"])}</div></div>
      <div class="card stat"><div class="label">Balance</div><div class="value">{money(s["balance"])}</div></div>
    </div>
    <div class="panel"><div class="formgrid">
      <div><b>Parent phone</b><div class="muted">{escape(s["parent_phone"] or "-")}</div></div>
      <div><b>Status</b><div>{'<span class="badge success">ACTIVE</span>' if s["active"] else '<span class="badge danger">ARCHIVED</span>'}</div></div>
    </div></div>
    <div class="panel"><h3>Academic history</h3><table><thead><tr><th>Academic Year</th><th>Grade</th><th>Status</th></tr></thead><tbody>{''.join(f'<tr><td>{escape(e["year_name"])}</td><td>{escape(e["grade"])}</td><td>{escape(e["status"])}</td></tr>' for e in enrollment) or '<tr><td colspan="3">No academic enrollment history.</td></tr>'}</tbody></table></div>
    <div class="panel"><h3>Payment history</h3>
      <table><thead><tr><th>Date</th><th>Amount</th><th>Method</th><th>Reference</th><th>Status</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="5">No payments.</td></tr>'}</tbody></table>
    </div>
    """
    return page("Student", body, "Students")


@app.route("/student/<adm>/statement")
@login_required
def student_statement(adm):
    conn = db()
    s = conn.execute("SELECT * FROM students WHERE adm_no=?", (adm,)).fetchone()
    ledger = conn.execute("SELECT * FROM ledger WHERE adm_no=? ORDER BY id", (adm,)).fetchall()
    conn.close()
    if not s:
        abort(404)
    rows = ''.join(
        f"""<tr><td>{escape(x["created_at"] or "")}</td><td>{escape(x["entry_type"] or "")}</td><td>{escape(x["description"] or "")}</td>
        <td>{money(x["debit"]) if x["debit"] else "-"}</td><td>{money(x["credit"]) if x["credit"] else "-"}</td><td>{money(x["running_balance"])}</td></tr>"""
        for x in ledger
    )
    body = f"""<div class="top noprint"><div><h1>Student Statement</h1><p class="muted">{escape(s["name"])} • {escape(s["adm_no"])} • {escape(s["class"])}</p></div><div class="actions"><button onclick="window.print()">Print</button><a class="btn secondary" href="/student/{escape(adm)}">Back</a></div></div>
    <div class="panel"><h2>{escape(setting("school_name", "SchoolPay"))}</h2><div class="formgrid"><div><b>Student</b><div>{escape(s["name"])}</div></div><div><b>ADM</b><div>{escape(s["adm_no"])}</div></div><div><b>Grade</b><div>{escape(s["class"])}</div></div><div><b>Pay Code</b><div>{escape(s["pay_code"])}</div></div></div></div>
    <div class="grid"><div class="card stat"><div class="label">Fees</div><div class="value">{money(s["total_fees"])}</div></div><div class="card stat"><div class="label">Paid</div><div class="value">{money(s["total_paid"])}</div></div><div class="card stat"><div class="label">Outstanding</div><div class="value">{money(s["balance"])}</div></div><div class="card stat"><div class="label">Entries</div><div class="value">{len(ledger)}</div></div></div>
    <div class="panel"><h3>Financial ledger</h3><table><thead><tr><th>Date</th><th>Type</th><th>Description</th><th>Debit</th><th>Credit</th><th>Balance</th></tr></thead><tbody>{rows or '<tr><td colspan="6">No ledger entries.</td></tr>'}</tbody></table></div>"""
    return page("Student Statement", body, "Students")


@app.route("/student/<adm>/edit", methods=["GET", "POST"])
@roles("admin", "bursar")
def edit_student(adm):
    conn = db()
    s = conn.execute("SELECT * FROM students WHERE adm_no=?", (adm,)).fetchone()
    conn.close()
    if not s:
        abort(404)
    if request.method == "POST":
        check_csrf()
        name = request.form.get("name", "").strip()
        grade = request.form.get("class", "").strip()
        phone = normalize_phone(request.form.get("parent_phone", ""))
        active = 1 if request.form.get("active") == "1" else 0
        if not name or not grade:
            return page("Edit student", '<div class="alert">Name and class are required.</div>', "Students")
        if phone and not valid_msisdn(phone):
            return page("Edit student", '<div class="alert">Invalid Kenyan phone number.</div>', "Students")
        old = dict(s)
        conn = db()
        conn.execute("""
            UPDATE students SET name=?,class=?,parent_phone=?,active=?,updated_at=CURRENT_TIMESTAMP
            WHERE adm_no=?
        """, (name, grade, phone, active, adm))
        conn.commit()
        conn.close()
        log_action("EDIT_STUDENT", adm_no=adm, old=old,
                   new={"name":name,"class":grade,"parent_phone":phone,"active":active})
        return redirect(f"/student/{adm}?msg=Student updated")
    body = f"""
    <div class="top"><div><h1>Edit student</h1><p class="muted">{escape(s["adm_no"])}</p></div></div>
    <div class="panel" style="max-width:700px"><form method="post">{csrf_input()}
      <label>Name</label><input name="name" value="{escape(s["name"])}" required>
      <label>Class / Grade</label><input name="class" value="{escape(s["class"])}" required>
      <label>Parent phone</label><input name="parent_phone" value="{escape(s["parent_phone"] or "")}">
      <label>Status</label><select name="active"><option value="1" {"selected" if s["active"] else ""}>Active</option>
      <option value="0" {"selected" if not s["active"] else ""}>Archived</option></select>
      <button>Save changes</button>
    </form></div>"""
    return page("Edit student", body, "Students")


# ================================================================
# FEES / TERMS
# ================================================================

@app.route("/new_term", methods=["GET", "POST"])
@roles("admin", "bursar")
def new_term():
    if request.method == "POST":
        check_csrf()
        term = request.form.get("term", "").strip()
        grade = request.form.get("grade", "").strip()
        try:
            amount = float(request.form.get("amount", "0") or 0)
        except ValueError:
            amount = -1
        if not term or amount <= 0:
            return page("Fees", '<div class="alert">Enter a term and a positive amount.</div>', "Fees")
        conn = db()
        existing = conn.execute(
            "SELECT id FROM term_fees WHERE term=? AND grade=? LIMIT 1",
            (term, grade or "ALL")
        ).fetchone()
        if existing:
            conn.close()
            return page("Fees", '<div class="alert">That fee has already been applied for this term/class. This prevents accidental double charging.</div>', "Fees")

        if grade:
            students = conn.execute("SELECT adm_no,total_fees,total_paid FROM students WHERE class=? AND active=1", (grade,)).fetchall()
        else:
            students = conn.execute("SELECT adm_no,total_fees,total_paid FROM students WHERE active=1").fetchall()

        conn.execute("INSERT INTO term_fees(term,grade,amount) VALUES(?,?,?)", (term, grade or "ALL", amount))
        for s in students:
            new_fees = float(s["total_fees"] or 0) + amount
            new_balance = new_fees - float(s["total_paid"] or 0)
            conn.execute("""
                UPDATE students SET total_fees=?,balance=?,updated_at=CURRENT_TIMESTAMP
                WHERE adm_no=?
            """, (new_fees, new_balance, s["adm_no"]))
            add_ledger_entry(conn, s["adm_no"], "FEE", f"{term} fee applied" + (f" • {grade}" if grade else ""),
                             debit=amount, reference_type="term_fee")
        conn.commit()
        conn.close()
        log_action("APPLY_TERM_FEES", new={"term":term,"grade":grade or "ALL","amount":amount,"students":len(students)})
        return redirect("/new_term?msg=Fees applied")
    conn = db()
    history = conn.execute("SELECT * FROM term_fees ORDER BY id DESC LIMIT 30").fetchall()
    classes = conn.execute("SELECT DISTINCT class FROM students WHERE active=1 ORDER BY class").fetchall()
    conn.close()
    msg = request.args.get("msg")
    alert = f'<div class="alert">{escape(msg)}</div>' if msg else ""
    rows = "".join(
        f'<tr><td>{escape(x["term"])}</td><td>{escape(x["grade"])}</td><td>{money(x["amount"])}</td><td>{escape(x["date"])}</td></tr>'
        for x in history
    )
    options = '<option value="">All active students</option>' + ''.join(
        f'<option value="{escape(c["class"])}">{escape(c["class"])}</option>' for c in classes
    )
    body = f"""
    <div class="top"><div><h1>New term / fees</h1><p class="muted">Fees are added to total fees; existing payments are preserved.</p></div></div>
    {alert}
    <div class="panel" style="max-width:700px"><form method="post">{csrf_input()}
      <label>Term name</label><input name="term" placeholder="Term 1 2027" required>
      <label>Class (optional)</label><select name="grade">{options}</select>
      <label>Fee amount</label><input name="amount" type="number" min="0.01" step="0.01" required>
      <button>Apply fees</button>
    </form></div>
    <div class="panel"><h3>Fee applications</h3><table><thead><tr><th>Term</th><th>Class</th><th>Amount</th><th>Date</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="4">No fee applications.</td></tr>'}</tbody></table></div>
    """
    return page("Fees", body, "Fees")


# ================================================================
# PAYMENTS
# ================================================================

def add_ledger_entry(conn, adm_no, entry_type, description, debit=0, credit=0,
                     reference_type=None, reference_id=None, academic_year_id=None, created_by=None):
    student = conn.execute("SELECT total_fees,total_paid FROM students WHERE adm_no=?", (adm_no,)).fetchone()
    balance = None
    if student:
        balance = float(student["total_fees"] or 0) - float(student["total_paid"] or 0)
    cur = conn.execute("""
        INSERT INTO ledger(adm_no,entry_type,reference_type,reference_id,description,debit,credit,running_balance,academic_year_id,created_by)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (adm_no, entry_type, reference_type, reference_id, description, float(debit or 0),
          float(credit or 0), balance, academic_year_id, created_by or session.get("username")))
    return cur.lastrowid


def record_success_payment(adm_no, amount, method, mpesa_code=None, phone=None,
                           checkout_request_id=None, merchant_request_id=None,
                           raw_data=None, created_by=None):
    """
    Atomically applies a confirmed payment exactly once.
    Returns (payment_id, created).
    """
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if mpesa_code:
            existing = conn.execute(
                "SELECT id,status FROM payments WHERE mpesa_code=?",
                (mpesa_code,)
            ).fetchone()
            if existing:
                conn.rollback()
                return existing["id"], False

        if checkout_request_id:
            existing = conn.execute(
                "SELECT id,status FROM payments WHERE checkout_request_id=?",
                (checkout_request_id,)
            ).fetchone()
            if existing and existing["status"] == "SUCCESS":
                conn.rollback()
                return existing["id"], False

        student = conn.execute(
            "SELECT * FROM students WHERE adm_no=?",
            (adm_no,)
        ).fetchone()
        if not student:
            raise ValueError("Student not found")

        cur = conn.execute("""
            INSERT INTO payments(
              adm_no,pay_code,amount,mpesa_code,method,phone,
              checkout_request_id,merchant_request_id,status,date,created_by,raw_data
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            adm_no, student["pay_code"], float(amount), mpesa_code, method, phone,
            checkout_request_id, merchant_request_id, "SUCCESS", now(),
            created_by or session.get("username"), raw_data
        ))
        payment_id = cur.lastrowid

        if str(method or "").upper().startswith("MPESA"):
            create_mpesa_notification(
                conn, payment_id, adm_no, student["name"], amount, mpesa_code
            )

        new_paid = float(student["total_paid"] or 0) + float(amount)
        new_balance = float(student["total_fees"] or 0) - new_paid
        conn.execute("""
            UPDATE students SET total_paid=?,balance=?,updated_at=CURRENT_TIMESTAMP
            WHERE adm_no=?
        """, (new_paid, new_balance, adm_no))
        add_ledger_entry(conn, adm_no, "PAYMENT",
                         f"Payment received via {method}" + (f" • {mpesa_code}" if mpesa_code else ""),
                         credit=float(amount), reference_type="payment", reference_id=payment_id)
        conn.commit()
        dispatch_whatsapp_receipt(adm_no, student["name"], student["parent_phone"], float(amount), method, mpesa_code, new_balance, payment_id)
        return payment_id, True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/pay", methods=["GET", "POST"])
@roles("admin", "bursar")
def pay():
    if request.method == "POST":
        check_csrf()
        account_no = (request.form.get("account_no") or "").strip().upper()
        method = request.form.get("method", "MANUAL").strip().upper()
        code = request.form.get("mpesa_code", "").strip().upper() or None
        phone = normalize_phone(request.form.get("phone", ""))
        try:
            amount = float(request.form.get("amount", "0") or 0)
        except ValueError:
            amount = -1

        if amount <= 0 or not account_no:
            return page("Pay", '<div class="alert">Select a student and enter a positive amount.</div>', "Pay")
        if phone and not valid_msisdn(phone):
            return page("Pay", '<div class="alert">Invalid phone number.</div>', "Pay")
        if method == "MPESA" and not code:
            return page("Pay", '<div class="alert">Enter the M-Pesa receipt/reference for a manual M-Pesa entry.</div>', "Pay")

        conn = db()
        student = conn.execute(
            "SELECT adm_no,pay_code FROM students WHERE UPPER(pay_code)=? AND active=1",
            (account_no,)
        ).fetchone()
        conn.close()
        if not student:
            return page("Pay", '<div class="alert">Student Account No / Pay Code not found. Search and select the student first.</div>', "Pay")

        adm = student["adm_no"]

        if method == "MPESA":
            # Never trust a manually typed M-Pesa code at face value: verify it
            # against Safaricom's Transaction Status API and let the callback
            # update the ledger once Safaricom confirms it. This prevents a
            # bursar (accidentally or otherwise) crediting a balance with a
            # reused, mistyped, or fabricated receipt number.
            conn = db()
            dup = conn.execute(
                "SELECT id FROM payments WHERE mpesa_code=? AND status='SUCCESS'", (code,)
            ).fetchone()
            pending = None
            if not dup:
                pending = conn.execute(
                    "SELECT id FROM mpesa_verifications WHERE mpesa_code=? AND status='PENDING' ORDER BY id DESC LIMIT 1",
                    (code,)
                ).fetchone()
            conn.close()
            if dup:
                return page("Pay", '<div class="alert">That M-Pesa reference has already been recorded.</div><a class="btn" href="/payments">Payments</a>', "Pay")
            if pending:
                # Already awaiting Safaricom for this exact receipt — don't fire a second
                # query, just point the bursar at the existing check.
                return page(
                    "Pay",
                    f'<div class="alert">Receipt <b>{escape(code)}</b> is already awaiting verification from Safaricom.</div>'
                    f'<a class="btn" href="/mpesa/verification/{pending["id"]}">Check its status</a>',
                    "Pay"
                )

            cfg = daraja_config()
            ts_ready = CRYPTO_AVAILABLE and all(cfg.get(k) for k in (
                "ckey", "csecret", "shortcode", "initiator_name",
                "initiator_password", "certificate_pem", "ts_result_url", "ts_timeout_url"
            ))

            if not ts_ready:
                return page(
                    "Pay",
                    '<div class="alert">Transaction verification is not fully configured yet. '
                    'Set up the Initiator Name, Initiator Password, M-Pesa certificate and result/timeout URLs on the '
                    '<a href="/daraja">M-Pesa settings</a> page before recording manual M-Pesa payments.</div>',
                    "Pay"
                )

            conn = db()
            cur = conn.execute("""
                INSERT INTO mpesa_verifications(adm_no,mpesa_code,expected_amount,initiated_by,status)
                VALUES(?,?,?,?,'PENDING')
            """, (adm, code, amount, session["username"]))
            vid = cur.lastrowid
            conn.commit()
            conn.close()

            try:
                result, req_payload = transaction_status_query(
                    cfg, code,
                    with_callback_token(cfg["ts_result_url"]),
                    with_callback_token(cfg["ts_timeout_url"]),
                )
            except Exception as e:
                conn = db()
                conn.execute("""
                    UPDATE mpesa_verifications SET status='FAILED', raw_result=?, resolved_at=? WHERE id=?
                """, (safe_json({"error": str(e)}), now(), vid))
                conn.commit()
                conn.close()
                log_action("MPESA_VERIFY_REQUEST_FAILED", adm_no=adm, new={"verification_id": vid, "error": str(e)})
                return page("Pay", f'<div class="alert">Could not reach Safaricom to verify this transaction: {escape(str(e))}</div>', "Pay")

            accepted = str(result.get("ResponseCode", "")) == "0"
            conn = db()
            conn.execute("""
                UPDATE mpesa_verifications
                SET originator_conversation_id=?, conversation_id=?, raw_request=?, status=?, resolved_at=?
                WHERE id=?
            """, (
                result.get("OriginatorConversationID"), result.get("ConversationID"),
                safe_json({"request": req_payload, "ack": result}),
                "PENDING" if accepted else "FAILED",
                None if accepted else now(),
                vid
            ))
            conn.commit()
            conn.close()

            if not accepted:
                log_action("MPESA_VERIFY_REJECTED", adm_no=adm, new={"verification_id": vid, "response": result})
                return page("Pay", f'<div class="alert">Safaricom rejected the verification request: {escape(str(result.get("ResponseDescription") or result))}</div>', "Pay")

            log_action("MPESA_VERIFY_REQUESTED", adm_no=adm, new={
                "verification_id": vid, "mpesa_code": code, "amount": amount,
                "originator_conversation_id": result.get("OriginatorConversationID")
            })
            return page(
                "Pay",
                f'''<div class="alert success">Verification request sent to Safaricom for receipt <b>{escape(code)}</b>
                    ({money(amount)}).<br>The student's ledger updates automatically once Safaricom confirms the
                    transaction — usually within a minute or two. No balance has been changed yet.</div>
                    <a class="btn" href="/mpesa/verification/{vid}">Check verification status</a>''',
                "Pay"
            )

        # Non-M-Pesa methods (cash, bank, cheque, etc.) are recorded immediately —
        # there's no third-party transaction to verify.
        try:
            pid, created = record_success_payment(
                adm, amount, method, code, phone, created_by=session["username"]
            )
            if not created:
                return page("Pay", '<div class="alert">That payment reference has already been recorded.</div><a class="btn" href="/payments">Payments</a>', "Pay")
        except ValueError as e:
            return page("Pay", f'<div class="alert">{escape(str(e))}</div>', "Pay")
        except sqlite3.IntegrityError:
            return page("Pay", '<div class="alert">Duplicate payment reference.</div>', "Pay")

        log_action(
            "MANUAL_PAYMENT",
            adm_no=adm,
            new={
                "payment_id": pid,
                "amount": amount,
                "method": method,
                "mpesa_code": code,
                "pay_code": account_no,
            }
        )
        return redirect(f"/payment/{pid}/receipt")

    account_no = (request.args.get("account_no") or "").strip().upper()
    # Backward compatibility for old /pay?adm_no= links.
    old_adm = (request.args.get("adm_no") or "").strip()
    conn = db()
    if not account_no and old_adm:
        old = conn.execute(
            "SELECT pay_code FROM students WHERE adm_no=? AND active=1",
            (old_adm,)
        ).fetchone()
        account_no = (old["pay_code"] or "").strip().upper() if old else ""
    s = conn.execute(
        "SELECT * FROM students WHERE UPPER(pay_code)=? AND active=1",
        (account_no,)
    ).fetchone() if account_no else None
    conn.close()

    phone_value = s["parent_phone"] if s else ""
    student_box = (
        f'<div class="alert success" id="studentInfo">'
        f'<b>{escape(s["name"])}</b> • ADM {escape(s["adm_no"])} • '
        f'Class {escape(s["class"])} • Account No: <b>{escape(s["pay_code"])}</b><br>'
        f'Parent phone: <b>{escape(s["parent_phone"] or "-")}</b> • '
        f'Current balance: <b>{money(s["balance"])}</b></div>'
        if s else
        '<div class="alert" id="studentInfo" style="display:none"></div>'
    )

    token = escape(csrf())
    initial_account = escape(account_no)
    initial_name = escape(s["name"]) if s else ""
    body = f"""
    <div class="top">
      <div><h1>Pay</h1><p class="muted">Search any student detail — ADM, name, phone or Account No — then SchoolPay automatically captures the Pay Code and payment details.</p></div>
      <a class="btn secondary" href="/reconciliation">M-Pesa Reconcile</a>
    </div>

    <div class="panel" style="max-width:900px">
      <div class="smart-pay-search">
        <label>Smart Student Search</label>
        <div class="search-wrap">
          <input id="payStudentSearch" autocomplete="off"
                 value="{initial_name or initial_account}"
                 placeholder="Search ADM, student name, phone or Pay Code..."
                 aria-label="Search student">
          <span class="search-icon">⌕</span>
        </div>
        <div id="paySearchResults" class="smart-results" style="display:none"></div>
        <div class="small muted" style="margin-top:7px">
          Start typing and select the correct student. The Account No / Pay Code is captured automatically.
        </div>
      </div>

      <div class="selected-student" id="selectedStudent" style="display:{'block' if s else 'none'}">
        <div class="selected-avatar" id="selectedAvatar">{escape((s["name"][0] if s and s["name"] else "S").upper())}</div>
        <div>
          <b id="selectedName">{escape(s["name"]) if s else ""}</b>
          <div class="small muted" id="selectedMeta">
            {f'ADM {escape(s["adm_no"])} • {escape(s["class"])} • Account No {escape(s["pay_code"])}' if s else ""}
          </div>
        </div>
        <button type="button" class="btn secondary" id="clearStudent" style="margin-left:auto">Change</button>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;margin:18px 0">
        <button type="button" class="paymode active" data-mode="manual">Manual / Cash</button>
        <button type="button" class="paymode" data-mode="stk">STK Push</button>
      </div>

      <form method="post" id="manualForm">{csrf_input()}
        <input type="hidden" id="accountNo" name="account_no" value="{initial_account}">
        <input type="hidden" id="admNo" name="adm_no" value="{escape(s["adm_no"]) if s else ""}">
        <div class="formgrid">
          <div><label>Account No / Student Code</label><input id="accountNoDisplay" value="{initial_account}" readonly placeholder="Select a student"></div>
          <div><label>Amount (KES)</label><input name="amount" type="number" min="0.01" step="0.01" required></div>
          <div><label>Method</label><select name="method"><option value="MANUAL">Cash / Manual</option><option value="MPESA">M-Pesa (already paid)</option><option value="BANK">Bank</option><option value="OTHER">Other</option></select></div>
          <div><label>M-Pesa receipt/reference (if applicable)</label><input name="mpesa_code" placeholder="e.g. QWE123ABC"></div>
          <div><label>Parent phone</label><input id="manualPhone" name="phone" value="{escape(phone_value or '')}" placeholder="0712345678"></div>
        </div>
        {student_box}
        <button id="savePayment" disabled="{'' if s else 'disabled'}">Save payment</button>
      </form>

      <form id="stkForm" style="display:none">
        <input type="hidden" name="_csrf" value="{token}">
        <input type="hidden" id="stkAccountNo" value="{initial_account}">
        <input type="hidden" id="stkAdm" value="{escape(s["adm_no"]) if s else ""}">
        <div class="formgrid">
          <div><label>Account No / Student Code</label><input id="stkAccountDisplay" value="{initial_account}" readonly placeholder="Select a student"></div>
          <div><label>Amount (KES)</label><input id="stkAmount" type="number" min="1" step="1" required placeholder="5000"></div>
          <div><label>Parent phone</label><input id="stkPhone" value="{escape(phone_value or '')}" required placeholder="0712345678"></div>
        </div>
        <div class="alert">The parent will receive an M-Pesa prompt. The M-Pesa AccountReference will automatically be the student's Pay Code.</div>
        <button type="submit" id="stkButton" disabled="{'' if s else 'disabled'}">Send STK Push</button>
        <div id="stkResult" class="alert" style="display:none;margin-top:14px"></div>
      </form>
    </div>

    <div class="panel" style="max-width:900px">
      <h3>How smart search works</h3>
      <p class="muted">Type an ADM number, part of the student's name, parent phone, or Pay Code. Choose a result once. SchoolPay then fills the Account No, ADM, class, parent phone and current balance for you.</p>
    </div>

    <style>
      .paymode.active{{background:var(--accent);color:#fff}}
      .paymode{{cursor:pointer}}
      .smart-pay-search{{position:relative}}
      .search-wrap{{position:relative}}
      #payStudentSearch{{font-size:16px;padding-right:42px}}
      .search-icon{{position:absolute;right:14px;top:50%;transform:translateY(-50%);font-size:22px;opacity:.55}}
      .smart-results{{position:absolute;z-index:50;left:0;right:0;background:var(--panel,#fff);border:1px solid var(--border,#ddd);border-radius:12px;box-shadow:0 12px 30px rgba(0,0,0,.15);overflow:hidden;margin-top:4px}}
      .smart-result{{display:flex;align-items:center;gap:12px;padding:12px 14px;cursor:pointer;border-bottom:1px solid var(--border,#eee)}}
      .smart-result:last-child{{border-bottom:0}}
      .smart-result:hover,.smart-result.active{{background:rgba(127,127,127,.10)}}
      .smart-avatar,.selected-avatar{{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:var(--accent);color:#fff;font-weight:700;flex:0 0 auto}}
      .smart-main{{min-width:0}}
      .smart-title{{font-weight:700}}
      .smart-sub{{font-size:12px;opacity:.72;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
      .selected-student{{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--border,#ddd);border-radius:12px;margin-top:12px}}
    </style>

    <script>
    const csrfToken = document.querySelector('#stkForm input[name="_csrf"]').value;
    const manualForm = document.getElementById('manualForm');
    const stkForm = document.getElementById('stkForm');
    const searchInput = document.getElementById('payStudentSearch');
    const resultsBox = document.getElementById('paySearchResults');
    const accountNo = document.getElementById('accountNo');
    const accountNoDisplay = document.getElementById('accountNoDisplay');
    const admNo = document.getElementById('admNo');
    const selectedStudent = document.getElementById('selectedStudent');
    const savePayment = document.getElementById('savePayment');
    const stkButton = document.getElementById('stkButton');
    let searchTimer = null;
    let selected = null;

    function setStudent(s) {{
      selected = s;
      accountNo.value = s.pay_code || '';
      accountNoDisplay.value = s.pay_code || '';
      admNo.value = s.adm_no || '';
      document.getElementById('stkAccountNo').value = s.pay_code || '';
      document.getElementById('stkAccountDisplay').value = s.pay_code || '';
      document.getElementById('stkAdm').value = s.adm_no || '';
      document.getElementById('manualPhone').value = s.parent_phone || '';
      document.getElementById('stkPhone').value = s.parent_phone || '';

      document.getElementById('selectedAvatar').textContent = (s.name || 'S').charAt(0).toUpperCase();
      document.getElementById('selectedName').textContent = s.name || '';
      document.getElementById('selectedMeta').textContent =
        'ADM ' + (s.adm_no || '-') + ' • ' + (s.class || '-') + ' • Account No ' + (s.pay_code || '-');
      selectedStudent.style.display = 'flex';
      resultsBox.style.display = 'none';
      savePayment.disabled = false;
      stkButton.disabled = false;
    }}

    function clearStudent() {{
      selected = null;
      accountNo.value = '';
      accountNoDisplay.value = '';
      admNo.value = '';
      document.getElementById('stkAccountNo').value = '';
      document.getElementById('stkAccountDisplay').value = '';
      document.getElementById('stkAdm').value = '';
      document.getElementById('manualPhone').value = '';
      document.getElementById('stkPhone').value = '';
      selectedStudent.style.display = 'none';
      savePayment.disabled = true;
      stkButton.disabled = true;
      searchInput.value = '';
      searchInput.focus();
    }}

    function renderResults(results) {{
      if (!results.length) {{
        resultsBox.innerHTML = '<div class="smart-result"><div class="smart-main"><div class="smart-title">No student found</div><div class="smart-sub">Try ADM, name, phone or Pay Code.</div></div></div>';
        resultsBox.style.display = 'block';
        return;
      }}
      resultsBox.innerHTML = results.map((s, i) => `
        <div class="smart-result" data-index="${{i}}">
          <div class="smart-avatar">${{(s.name || 'S').charAt(0).toUpperCase()}}</div>
          <div class="smart-main">
            <div class="smart-title">${{escapeHtml(s.name)}}</div>
            <div class="smart-sub">ADM ${{escapeHtml(s.adm_no)}} • ${{escapeHtml(s.class || '-')}} • Account No <b>${{escapeHtml(s.pay_code)}}</b> • ${{escapeHtml(s.parent_phone || 'No phone')}}</div>
          </div>
        </div>`).join('');
      resultsBox.style.display = 'block';
      resultsBox.querySelectorAll('.smart-result[data-index]').forEach(el => {{
        el.addEventListener('click', () => setStudent(results[Number(el.dataset.index)]));
      }});
    }}

    function escapeHtml(value) {{
      return String(value ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
    }}

    async function searchStudents(q) {{
      q = q.trim();
      if (!q) {{ resultsBox.style.display='none'; return; }}
      try {{
        const r = await fetch('/api/pay-student-search?q=' + encodeURIComponent(q), {{headers: {{'Accept':'application/json'}}}});
        const d = await r.json();
        if (!r.ok || !d.ok) throw new Error(d.error || 'Search failed');
        renderResults(d.results || []);
      }} catch(e) {{
        resultsBox.innerHTML = '<div class="smart-result"><div class="smart-main"><div class="smart-title">Search unavailable</div><div class="smart-sub">Please try again.</div></div></div>';
        resultsBox.style.display = 'block';
      }}
    }}

    searchInput.addEventListener('input', () => {{
      clearTimeout(searchTimer);
      const q = searchInput.value;
      if (!q.trim()) {{ resultsBox.style.display='none'; return; }}
      searchTimer = setTimeout(() => searchStudents(q), 180);
    }});
    searchInput.addEventListener('focus', () => {{
      if (searchInput.value.trim()) searchStudents(searchInput.value);
    }});
    document.addEventListener('click', e => {{
      if (!e.target.closest('.smart-pay-search')) resultsBox.style.display='none';
    }});
    document.getElementById('clearStudent').addEventListener('click', clearStudent);

    document.querySelectorAll('.paymode').forEach(btn => btn.addEventListener('click', () => {{
      document.querySelectorAll('.paymode').forEach(x => x.classList.remove('active'));
      btn.classList.add('active');
      const stk = btn.dataset.mode === 'stk';
      manualForm.style.display = stk ? 'none' : 'block';
      stkForm.style.display = stk ? 'block' : 'none';
    }}));

    stkForm.addEventListener('submit', async e => {{
      e.preventDefault();
      if (!selected || !selected.pay_code) {{
        alert('Please search and select a student first.');
        return;
      }}
      const result=document.getElementById('stkResult'), button=stkButton;
      button.disabled=true; button.textContent='Sending...'; result.style.display='block'; result.textContent='Sending STK Push...';
      try {{
        const r=await fetch('/stk_push', {{
          method:'POST',
          headers:{{'Content-Type':'application/json','X-CSRF-Token':csrfToken}},
          body:JSON.stringify({{
            account_no:selected.pay_code,
            amount:document.getElementById('stkAmount').value,
            phone:document.getElementById('stkPhone').value.trim()
          }})
        }});
        const d=await r.json();
        if(!r.ok||!d.ok) throw new Error(d.error||'STK Push failed');
        result.innerHTML='Success: '+d.message+(d.checkout_request_id?'<br><small>Checkout: '+d.checkout_request_id+'</small>':'');
        if(d.payment_id) pollPayment(d.payment_id,result,button);
        else {{button.disabled=false;button.textContent='Send STK Push';}}
      }} catch(err) {{result.textContent='Error: '+err.message;button.disabled=false;button.textContent='Send STK Push';}}
    }});

    async function pollPayment(id,result,button) {{
      let tries=0;
      const timer=setInterval(async()=>{{
        tries++;
        try {{
          const r=await fetch('/payment/'+id+'/status'); const d=await r.json();
          if(d.status==='SUCCESS') {{
            clearInterval(timer);
            result.innerHTML='Payment confirmed - M-Pesa: <b>'+(d.mpesa_code||'confirmed')+'</b><br>Student balance: <b>'+d.balance+'</b> <a class="btn secondary" href="/payment/'+id+'/receipt">Receipt</a>';
            button.disabled=false;button.textContent='Send STK Push';
          }} else if(['FAILED','CANCELLED','REVERSED'].includes(d.status)) {{
            clearInterval(timer);result.textContent='Payment status: '+d.status;button.disabled=false;button.textContent='Send STK Push';
          }} else if(tries>=24) {{
            clearInterval(timer);result.textContent='STK is still pending. Check M-Pesa Reconcile for the final status.';button.disabled=false;button.textContent='Send STK Push';
          }}
        }} catch(e) {{
          if(tries>=24){{clearInterval(timer);button.disabled=false;button.textContent='Send STK Push';}}
        }}
      }},5000);
    }}
    </script>
    """
    return page("Pay", body, "Pay")


@app.route("/api/pay-student-search")
@roles("admin", "bursar")
def pay_student_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify(ok=True, results=[])

    # Search the fields a bursar is most likely to know.
    like = f"%{q}%"
    starts = f"{q}%"
    conn = db()
    try:
        rows = conn.execute("""
            SELECT adm_no,name,class,parent_phone,pay_code,balance,total_paid,total_fees
            FROM students
            WHERE active=1
              AND (
                  adm_no LIKE ? COLLATE NOCASE
                  OR name LIKE ? COLLATE NOCASE
                  OR parent_phone LIKE ? COLLATE NOCASE
                  OR pay_code LIKE ? COLLATE NOCASE
                  OR class LIKE ? COLLATE NOCASE
              )
            ORDER BY
              CASE
                WHEN adm_no LIKE ? COLLATE NOCASE THEN 0
                WHEN pay_code LIKE ? COLLATE NOCASE THEN 1
                WHEN parent_phone LIKE ? COLLATE NOCASE THEN 2
                WHEN name LIKE ? COLLATE NOCASE THEN 3
                ELSE 4
              END,
              name COLLATE NOCASE
            LIMIT 10
        """, (like, like, like, like, like, starts, starts, starts, starts)).fetchall()
    finally:
        conn.close()

    return jsonify(ok=True, results=[
        {
            "adm_no": r["adm_no"],
            "name": r["name"],
            "class": r["class"],
            "parent_phone": r["parent_phone"] or "",
            "pay_code": r["pay_code"],
            "balance": float(r["balance"] or 0),
            "total_paid": float(r["total_paid"] or 0),
            "total_fees": float(r["total_fees"] or 0),
        }
        for r in rows
    ])


@app.route("/api/student/<adm_no>")
@roles("admin", "bursar")
def api_student(adm_no):
    conn=db(); s=conn.execute("SELECT adm_no,name,class,parent_phone,pay_code,balance,total_paid,total_fees FROM students WHERE adm_no=? AND active=1",(adm_no.strip(),)).fetchone(); conn.close()
    if not s: return jsonify(ok=False,error="Student not found"),404
    return jsonify(ok=True,student={"adm_no":s["adm_no"],"name":s["name"],"class":s["class"],"parent_phone":s["parent_phone"] or "","pay_code":s["pay_code"],"balance":money(s["balance"]),"total_paid":money(s["total_paid"]),"total_fees":money(s["total_fees"])})

@app.route("/payment/<int:payment_id>/status")
@roles("admin", "bursar")
def payment_status(payment_id):
    conn=db(); p=conn.execute("SELECT id,status,mpesa_code,amount,adm_no FROM payments WHERE id=?",(payment_id,)).fetchone(); balance=None
    if p:
        st=conn.execute("SELECT balance FROM students WHERE adm_no=?",(p["adm_no"],)).fetchone(); balance=money(st["balance"]) if st else "-"
    conn.close()
    if not p: return jsonify(ok=False,error="Payment not found"),404
    return jsonify(ok=True,id=p["id"],status=p["status"],mpesa_code=p["mpesa_code"],amount=money(p["amount"]),balance=balance)


@app.route("/payments")
@login_required
def payments():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip().upper()
    conn = db()
    sql = """
    SELECT p.*,s.name FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no
    WHERE 1=1
    """
    args = []
    if q:
        sql += " AND (p.adm_no LIKE ? OR p.mpesa_code LIKE ? OR p.pay_code LIKE ? OR s.name LIKE ?)"
        like = f"%{q}%"
        args += [like, like, like, like]
    if status:
        sql += " AND p.status=?"
        args.append(status)
    sql += " ORDER BY p.id DESC LIMIT 500"
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    trs = ""
    for p in rows:
        cls = "success" if p["status"] == "SUCCESS" else "warn" if p["status"] == "PENDING" else "danger"
        reverse = ""
        if session.get("role") == "admin" and p["status"] == "SUCCESS" and not p["reversed_at"]:
            reverse = f'<form method="post" action="/payment/{p["id"]}/reverse" style="display:inline">{csrf_input()}<button class="btn red" onclick="return confirm(\'Reverse this payment?\')">Reverse</button></form>'
        trs += f"""
        <tr><td>{p["id"]}</td><td>{escape(p["date"] or "")}</td><td>{escape(p["adm_no"] or "-")}</td>
        <td>{escape(p["name"] or "-")}</td><td>{money(p["amount"])}</td><td>{escape(p["method"] or "")}</td>
        <td>{escape(p["mpesa_code"] or "-")}</td><td><span class="badge {cls}">{escape(p["status"])}</span></td>
        <td><a class="btn secondary" href="/payment/{p["id"]}/receipt">Receipt</a>{reverse}</td></tr>"""
    body = f"""
    <div class="top"><div><h1>Payments</h1><p class="muted">{len(rows)} recent record(s)</p></div>
      <a class="btn" href="/pay">Record payment</a></div>
    <form class="search"><input name="q" value="{escape(q)}" placeholder="Search ADM, name, pay code or receipt">
      <select name="status"><option value="">All statuses</option>
      <option {"selected" if status=="SUCCESS" else ""}>SUCCESS</option><option {"selected" if status=="PENDING" else ""}>PENDING</option>
      <option {"selected" if status=="FAILED" else ""}>FAILED</option><option {"selected" if status=="REVERSED" else ""}>REVERSED</option></select>
      <button>Filter</button></form>
    <div class="panel"><table><thead><tr><th>ID</th><th>Date</th><th>ADM</th><th>Student</th><th>Amount</th><th>Method</th><th>Receipt</th><th>Status</th><th></th></tr></thead>
    <tbody>{trs or '<tr><td colspan="9">No payments found.</td></tr>'}</tbody></table></div>
    """
    return page("Payments", body, "Payments")


@app.route("/payment/<int:payment_id>/receipt")
@login_required
def receipt(payment_id):
    conn = db()
    p = conn.execute("""
        SELECT p.*,s.name,s.class,s.parent_phone,s.pay_code,s.total_fees,s.total_paid,s.balance
        FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no WHERE p.id=?
    """, (payment_id,)).fetchone()
    conn.close()
    if not p:
        abort(404)
    school = escape(setting("school_name", "SchoolPay"))
    body = f"""
    <div class="top noprint"><div><h1>Payment receipt</h1><p class="muted">Receipt #{p["id"]}</p></div>
      <div class="actions"><button onclick="window.print()">Print</button><a class="btn secondary" href="/payments">Back</a></div></div>
    <div class="panel" style="max-width:720px">
      <h2>{school}</h2><p class="muted">{escape(setting("school_address",""))} • {escape(setting("school_phone",""))}</p>
      <hr style="border-color:#26364f">
      <div class="formgrid">
        <div><b>Receipt ID</b><div>{p["id"]}</div></div><div><b>Date</b><div>{escape(p["date"] or "")}</div></div>
        <div><b>Student</b><div>{escape(p["name"] or "-")}</div></div><div><b>ADM</b><div>{escape(p["adm_no"] or "-")}</div></div>
        <div><b>Class</b><div>{escape(p["class"] or "-")}</div></div><div><b>Pay Code</b><div>{escape(p["pay_code"] or "-")}</div></div>
        <div><b>Method</b><div>{escape(p["method"] or "-")}</div></div><div><b>M-Pesa Reference</b><div>{escape(p["mpesa_code"] or "-")}</div></div>
        <div><b>Amount paid</b><div style="font-size:22px;font-weight:900">{money(p["amount"])}</div></div>
        <div><b>Balance after payment</b><div style="font-size:22px;font-weight:900">{money(p["balance"])}</div></div>
      </div>
      <p class="small muted">Generated by SchoolPay V10.</p>
    </div>"""
    return page("Receipt", body, "Payments")


@app.route("/payment/<int:payment_id>/reverse", methods=["POST"])
@roles("admin")
def reverse_payment(payment_id):
    check_csrf()
    reason = request.form.get("reason", "").strip() or "Admin reversal"
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        p = conn.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
        if not p:
            raise ValueError("Payment not found")
        if p["status"] != "SUCCESS" or p["reversed_at"]:
            raise ValueError("Payment is not eligible for reversal")
        s = conn.execute("SELECT * FROM students WHERE adm_no=?", (p["adm_no"],)).fetchone()
        if not s:
            raise ValueError("Student not found")
        new_paid = float(s["total_paid"] or 0) - float(p["amount"])
        new_balance = float(s["total_fees"] or 0) - new_paid
        conn.execute("""
            UPDATE students SET total_paid=?,balance=?,updated_at=CURRENT_TIMESTAMP WHERE adm_no=?
        """, (new_paid, new_balance, p["adm_no"]))
        conn.execute("""
            UPDATE payments SET status='REVERSED',reversed_at=?,reversed_by=?,reversal_reason=?
            WHERE id=?
        """, (now(), session["username"], reason, payment_id))
        add_ledger_entry(conn, p["adm_no"], "REVERSAL", f"Payment reversal: {reason}",
                         debit=float(p["amount"]), reference_type="reversal", reference_id=payment_id)
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return page("Payment reversal", f'<div class="alert">{escape(str(e))}</div>', "Payments")
    conn.close()
    log_action("REVERSE_PAYMENT", adm_no=p["adm_no"], old=dict(p), new={"reason":reason})
    return redirect("/payments?status=REVERSED")


# ================================================================
# M-PESA DARAJA
# ================================================================

def daraja_config():
    conn = db()
    row = conn.execute("SELECT * FROM daraja_config WHERE id=1").fetchone()
    conn.close()
    if row:
        cfg = dict(row)
        cfg["csecret"] = decrypt_secret(cfg.get("csecret"))
        cfg["passkey"] = decrypt_secret(cfg.get("passkey"))
        cfg["initiator_password"] = decrypt_secret(cfg.get("initiator_password"))
        return cfg
    return {
        "ckey": os.environ.get("MPESA_CONSUMER_KEY", ""),
        "csecret": os.environ.get("MPESA_CONSUMER_SECRET", ""),
        "shortcode": os.environ.get("MPESA_SHORTCODE", "174379"),
        "passkey": os.environ.get("MPESA_PASSKEY", ""),
        "callback_url": os.environ.get("MPESA_CALLBACK_URL", ""),
        "env": os.environ.get("MPESA_ENV", "sandbox"),
        "c2b_validation_url": os.environ.get("MPESA_C2B_VALIDATION_URL", ""),
        "c2b_confirmation_url": os.environ.get("MPESA_C2B_CONFIRMATION_URL", ""),
        "c2b_registered": 0,
        "initiator_name": os.environ.get("MPESA_INITIATOR_NAME", ""),
        "initiator_password": os.environ.get("MPESA_INITIATOR_PASSWORD", ""),
        "certificate_pem": os.environ.get("MPESA_CERTIFICATE_PEM", ""),
        "ts_result_url": os.environ.get("MPESA_TS_RESULT_URL", ""),
        "ts_timeout_url": os.environ.get("MPESA_TS_TIMEOUT_URL", ""),
    }


def daraja_base(cfg):
    return "https://api.safaricom.co.ke" if cfg.get("env") == "production" else "https://sandbox.safaricom.co.ke"


def daraja_token(cfg):
    if not cfg.get("ckey") or not cfg.get("csecret"):
        raise RuntimeError("Daraja consumer key/secret are not configured.")
    token_url = daraja_base(cfg) + "/oauth/v1/generate?grant_type=client_credentials"
    raw = f'{cfg["ckey"]}:{cfg["csecret"]}'.encode()
    auth = base64.b64encode(raw).decode()
    r = requests.get(token_url, headers={"Authorization": "Basic " + auth}, timeout=20)
    r.raise_for_status()
    data = r.json()
    return data["access_token"]


def compute_security_credential(cfg):
    """Encrypt the initiator password with Safaricom's public certificate,
    as required for the Transaction Status API (RSA/PKCS1v15, base64-encoded)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("The cryptography package is required for Transaction Status queries (pip install cryptography).")
    cert_pem = (cfg.get("certificate_pem") or "").strip()
    password = cfg.get("initiator_password") or ""
    if not cert_pem or not password:
        raise RuntimeError("Set the Initiator Name, Initiator Password and M-Pesa public certificate first.")
    from cryptography.hazmat.primitives.asymmetric import padding
    pub_key = None
    try:
        from cryptography import x509
        pub_key = x509.load_pem_x509_certificate(cert_pem.encode()).public_key()
    except Exception:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            pub_key = load_pem_public_key(cert_pem.encode())
        except Exception as e:
            raise RuntimeError(f"Could not read the M-Pesa public certificate: {e}")
    encrypted = pub_key.encrypt(password.encode(), padding.PKCS1v15())
    return base64.b64encode(encrypted).decode()


def transaction_status_query(cfg, transaction_id, result_url, timeout_url):
    """Ask Safaricom for the authoritative status of a transaction by its
    M-Pesa receipt number. Safaricom replies asynchronously to result_url —
    this call only returns an immediate accept/reject acknowledgement."""
    if not cfg.get("initiator_name"):
        raise RuntimeError("Set the Daraja Initiator Name first.")
    security_credential = compute_security_credential(cfg)
    token = daraja_token(cfg)
    payload = {
        "Initiator": cfg["initiator_name"],
        "SecurityCredential": security_credential,
        "CommandID": "TransactionStatusQuery",
        "TransactionID": transaction_id,
        "PartyA": cfg["shortcode"],
        "IdentifierType": "4",
        "ResultURL": result_url,
        "QueueTimeOutURL": timeout_url,
        "Remarks": "SchoolPay fee payment verification",
        "Occasion": "FeeVerification",
    }
    r = requests.post(
        daraja_base(cfg) + "/mpesa/transactionstatus/v1/query",
        json=payload,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        timeout=30,
    )
    result = r.json()
    return result, payload


def ts_result_param(items, name):
    for it in items or []:
        if it.get("Key") == name:
            return it.get("Value")
    return None


def ts_result_value(result, *names):
    """Read a Transaction Status result field across the several shapes Daraja
    is known to send: top-level keys, a nested ResultParameters list, or a
    nested "Result" object. Checks several accepted aliases for each field."""
    wanted = {str(n).strip().lower() for n in names}
    if not isinstance(result, dict):
        return None
    items = (result.get("ResultParameters") or {}).get("ResultParameter")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                k = str(item.get("Key") or item.get("Name") or "").strip().lower()
                if k in wanted:
                    return item.get("Value")
    for k, v in result.items():
        if str(k).strip().lower() in wanted:
            return v
    nested = result.get("Result")
    if isinstance(nested, dict):
        return ts_result_value(nested, *names)
    return None


@app.route("/daraja", methods=["GET", "POST"])
@roles("admin")
def daraja():
    if request.method == "POST":
        check_csrf()
        existing = daraja_config()  # decrypted current values, for masked-field fallback
        submitted_secret = request.form.get("csecret", "").strip()
        submitted_passkey = request.form.get("passkey", "").strip()
        submitted_initiator_pw = request.form.get("initiator_password", "").strip()
        MASK = "••••••••"
        # Blank or unchanged (still showing the mask) means "keep the current value" —
        # otherwise the mask itself would get saved as the literal secret.
        new_secret = existing.get("csecret", "") if submitted_secret in ("", MASK) else submitted_secret
        new_passkey = existing.get("passkey", "") if submitted_passkey in ("", MASK) else submitted_passkey
        new_initiator_pw = existing.get("initiator_password", "") if submitted_initiator_pw in ("", MASK) else submitted_initiator_pw
        cfg = {
            "ckey": request.form.get("ckey", "").strip(),
            "csecret": encrypt_secret(new_secret),
            "shortcode": request.form.get("shortcode", "").strip(),
            "passkey": encrypt_secret(new_passkey),
            "callback_url": request.form.get("callback_url", "").strip(),
            "env": request.form.get("env", "sandbox").strip(),
            "c2b_validation_url": request.form.get("c2b_validation_url", "").strip(),
            "c2b_confirmation_url": request.form.get("c2b_confirmation_url", "").strip(),
            "initiator_name": request.form.get("initiator_name", "").strip(),
            "initiator_password": encrypt_secret(new_initiator_pw),
            "certificate_pem": request.form.get("certificate_pem", "").strip(),
            "ts_result_url": request.form.get("ts_result_url", "").strip(),
            "ts_timeout_url": request.form.get("ts_timeout_url", "").strip(),
        }
        if cfg["env"] not in {"sandbox", "production"}:
            cfg["env"] = "sandbox"
        conn = db()
        conn.execute("""
            INSERT INTO daraja_config(id,ckey,csecret,shortcode,passkey,callback_url,env,c2b_validation_url,c2b_confirmation_url,c2b_registered,
                                       initiator_name,initiator_password,certificate_pem,ts_result_url,ts_timeout_url)
            VALUES(1,?,?,?,?,?,?,?,?,0,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              ckey=excluded.ckey,csecret=excluded.csecret,shortcode=excluded.shortcode,
              passkey=excluded.passkey,callback_url=excluded.callback_url,env=excluded.env,
              c2b_validation_url=excluded.c2b_validation_url,c2b_confirmation_url=excluded.c2b_confirmation_url,
              initiator_name=excluded.initiator_name,initiator_password=excluded.initiator_password,
              certificate_pem=excluded.certificate_pem,ts_result_url=excluded.ts_result_url,ts_timeout_url=excluded.ts_timeout_url
        """, (cfg["ckey"],cfg["csecret"],cfg["shortcode"],cfg["passkey"],cfg["callback_url"],cfg["env"],
              cfg["c2b_validation_url"],cfg["c2b_confirmation_url"],
              cfg["initiator_name"],cfg["initiator_password"],cfg["certificate_pem"],cfg["ts_result_url"],cfg["ts_timeout_url"]))
        conn.commit()
        conn.close()
        log_action("UPDATE_DARAJA_SETTINGS")
        return redirect("/daraja?msg=Settings saved")

    cfg = daraja_config()
    masked_secret = "••••••••" if cfg.get("csecret") else ""
    masked_passkey = "••••••••" if cfg.get("passkey") else ""
    masked_initiator_pw = "••••••••" if cfg.get("initiator_password") else ""
    msg = request.args.get("msg")
    alert = f'<div class="alert">{escape(msg)}</div>' if msg else ""
    body = f"""
    <div class="top"><div><h1>M-Pesa / Daraja</h1><p class="muted">Credentials are stored locally in SQLite{"" if CRYPTO_AVAILABLE else " in plaintext — install the cryptography package (pip install cryptography) to encrypt them at rest"}. Prefer environment variables in production.</p></div></div>
    {alert}
    <div class="panel" style="max-width:760px"><form method="post">{csrf_input()}
      <label>Consumer Key</label><input name="ckey" value="{escape(cfg.get("ckey",""))}">
      <label>Consumer Secret</label><input name="csecret" value="{masked_secret}" placeholder="Enter actual secret to replace it">
      <label>Shortcode</label><input name="shortcode" value="{escape(cfg.get("shortcode",""))}">
      <label>Passkey</label><input name="passkey" value="{masked_passkey}" placeholder="Enter actual passkey to replace it">
      <label>Callback URL</label><input name="callback_url" value="{escape(cfg.get("callback_url",""))}" placeholder="https://your-domain.example/mpesa/callback">
      <label>Environment</label><select name="env">
        <option value="sandbox" {"selected" if cfg.get("env")=="sandbox" else ""}>Sandbox</option>
        <option value="production" {"selected" if cfg.get("env")=="production" else ""}>Production</option>
      </select>
      <label>C2B Validation URL</label><input name="c2b_validation_url" value="{escape(cfg.get("c2b_validation_url", ""))}" placeholder="https://your-domain.example/mpesa/c2b/validation">
      <label>C2B Confirmation URL</label><input name="c2b_confirmation_url" value="{escape(cfg.get("c2b_confirmation_url", ""))}" placeholder="https://your-domain.example/mpesa/c2b/confirmation">
      <button>Save Daraja settings</button>
    </form></div>
    <div class="panel" style="max-width:760px"><h3>Transaction verification (manual M-Pesa entries)</h3>
      <p class="muted">Used by the <a href="/pay">Pay</a> page to check every manually-entered M-Pesa receipt against Safaricom before it updates any balance.</p>
      <form method="post">{csrf_input()}
      <input type="hidden" name="ckey" value="{escape(cfg.get("ckey",""))}"><input type="hidden" name="csecret" value="{masked_secret}">
      <input type="hidden" name="shortcode" value="{escape(cfg.get("shortcode",""))}"><input type="hidden" name="passkey" value="{masked_passkey}">
      <input type="hidden" name="callback_url" value="{escape(cfg.get("callback_url",""))}"><input type="hidden" name="env" value="{escape(cfg.get("env","sandbox"))}">
      <input type="hidden" name="c2b_validation_url" value="{escape(cfg.get("c2b_validation_url",""))}"><input type="hidden" name="c2b_confirmation_url" value="{escape(cfg.get("c2b_confirmation_url",""))}">
      <label>Initiator Name</label><input name="initiator_name" value="{escape(cfg.get("initiator_name",""))}" placeholder="API operator username set up in the Daraja org portal">
      <label>Initiator Password</label><input name="initiator_password" value="{masked_initiator_pw}" placeholder="Enter actual password to replace it">
      <label>M-Pesa Public Certificate (PEM)</label><textarea name="certificate_pem" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----">{escape(cfg.get("certificate_pem",""))}</textarea>
      <label>Transaction Status Result URL</label><input name="ts_result_url" value="{escape(cfg.get("ts_result_url",""))}" placeholder="https://your-domain.example/mpesa/transactionstatus/result">
      <label>Transaction Status Timeout URL</label><input name="ts_timeout_url" value="{escape(cfg.get("ts_timeout_url",""))}" placeholder="https://your-domain.example/mpesa/transactionstatus/timeout">
      <p class="small muted">Get the Initiator Name/Password from your Daraja org's API operator setup, and the public certificate (sandbox or production) from Safaricom's Daraja documentation.</p>
      <button>Save verification settings</button>
    </form></div>
    <div class="panel"><h3>PayBill / C2B</h3>
      <p class="muted">Parents can pay directly to the school PayBill from home using the student's Pay Code as the M-Pesa Account Number — no call to the bursar needed. SchoolPay matches the payment automatically: first by the account reference typed in (hyphens/spaces/case don't matter), and if that's blank or mistyped, by the phone number already on file as the student's parent phone.</p>
      <p><b>Validation:</b> <code>/mpesa/c2b/validation</code><br><b>Confirmation:</b> <code>/mpesa/c2b/confirmation</code></p>
      <p><span class="badge {'success' if cfg.get('c2b_registered') else 'warn'}">{'REGISTERED' if cfg.get('c2b_registered') else 'NOT REGISTERED'}</span></p>
      <form method="post" action="/daraja/c2b/register">{csrf_input()}<button class="btn green">Register PayBill C2B URLs</button></form>
      <p class="small muted">The URLs must be public HTTPS endpoints. Save the settings first, then register them with Daraja. A payment only lands in <a href="/unmatched">Unmatched</a> if neither the reference nor the phone number identifies exactly one student.</p>
    </div>

    <div class="panel"><b>STK callback endpoint:</b> <code>/mpesa/callback</code><br>
    <b>Transaction Status endpoints:</b> <code>/mpesa/transactionstatus/result</code> and <code>/mpesa/transactionstatus/timeout</code><br>
    <span class="small muted">These must be reachable by Safaricom. Never use a placeholder URL in production.</span><br>
    <span class="small muted">All callback/validation/confirmation/result/timeout endpoints require the <code>MPESA_CALLBACK_TOKEN</code> environment variable to be set — requests without a matching token are rejected. {"" if os.environ.get("MPESA_CALLBACK_TOKEN","").strip() else '<b style="color:#ff7a45">Not set — callbacks are currently disabled.</b>'}</span></div>
    """
    return page("M-Pesa", body, "M-Pesa")


@app.route("/daraja/c2b/register", methods=["POST"])
@roles("admin")
def register_c2b_urls():
    check_csrf()
    cfg = daraja_config()
    validation = (cfg.get("c2b_validation_url") or "").strip()
    confirmation = (cfg.get("c2b_confirmation_url") or "").strip()
    if not validation or not confirmation:
        return redirect("/daraja?msg=Set both C2B Validation and Confirmation URLs first")
    for url in (validation, confirmation):
        if not url.lower().startswith("https://") or "example.com" in url.lower() or "YOUR_" in url.upper():
            return redirect("/daraja?msg=C2B URLs must be real public HTTPS URLs")
    if not os.environ.get("MPESA_CALLBACK_TOKEN", "").strip():
        return redirect("/daraja?msg=Set the MPESA_CALLBACK_TOKEN environment variable before registering, so these endpoints stay protected")
    try:
        token = daraja_token(cfg)
        payload = {
            "ShortCode": cfg["shortcode"],
            "ResponseType": "Completed",
            "ConfirmationURL": with_callback_token(confirmation),
            "ValidationURL": with_callback_token(validation),
        }
        r = requests.post(daraja_base(cfg) + "/mpesa/c2b/v1/registerurl", json=payload,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, timeout=30)
        data = r.json()
        ok = str(data.get("ResponseCode", "")) == "0" or str(data.get("ResultCode", "")) == "0"
        conn = db()
        conn.execute("UPDATE daraja_config SET c2b_registered=? WHERE id=1", (1 if ok else 0,))
        conn.commit(); conn.close()
        log_action("C2B_REGISTER_URLS", new=data)
        return redirect("/daraja?msg=" + ("C2B PayBill URLs registered successfully" if ok else "C2B registration response: " + str(data.get("ResponseDescription") or data.get("errorMessage") or data)))
    except Exception as e:
        return redirect("/daraja?msg=C2B registration failed: " + str(e))


# ================================================================
# WHATSAPP SETTINGS
# ================================================================

@app.route("/whatsapp", methods=["GET", "POST"])
@roles("admin")
def whatsapp_settings():
    if request.method == "POST":
        check_csrf()
        existing = whatsapp_config()
        submitted_token = request.form.get("access_token", "").strip()
        MASK = "••••••••"
        new_token = existing.get("access_token", "") if submitted_token in ("", MASK) else submitted_token

        def _int(name, default=0):
            try:
                return int(request.form.get(name, default))
            except (TypeError, ValueError):
                return default

        def _float(name, default=0.0):
            try:
                return float(request.form.get(name, default))
            except (TypeError, ValueError):
                return default

        cfg = {
            "access_token": encrypt_secret(new_token),
            "phone_number_id": request.form.get("phone_number_id", "").strip(),
            "api_version": request.form.get("api_version", "v20.0").strip() or "v20.0",
            "enabled": 1 if request.form.get("enabled") == "on" else 0,
            "use_template_for_receipt": 1 if request.form.get("use_template_for_receipt") == "on" else 0,
            "receipt_template": request.form.get("receipt_template", "").strip(),
            "receipt_template_lang": request.form.get("receipt_template_lang", "en_US").strip() or "en_US",
            "use_template_for_reminder": 1 if request.form.get("use_template_for_reminder") == "on" else 0,
            "reminder_template": request.form.get("reminder_template", "").strip(),
            "reminder_template_lang": request.form.get("reminder_template_lang", "en_US").strip() or "en_US",
            "auto_reminder_enabled": 1 if request.form.get("auto_reminder_enabled") == "on" else 0,
            "auto_reminder_interval_days": max(1, _int("auto_reminder_interval_days", 7)),
            "auto_reminder_min_balance": max(0.0, _float("auto_reminder_min_balance", 0)),
        }
        conn = db()
        conn.execute("""
            INSERT INTO whatsapp_config(id,access_token,phone_number_id,api_version,enabled,
                use_template_for_receipt,receipt_template,receipt_template_lang,
                use_template_for_reminder,reminder_template,reminder_template_lang,
                auto_reminder_enabled,auto_reminder_interval_days,auto_reminder_min_balance)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              access_token=excluded.access_token,phone_number_id=excluded.phone_number_id,api_version=excluded.api_version,
              enabled=excluded.enabled,use_template_for_receipt=excluded.use_template_for_receipt,
              receipt_template=excluded.receipt_template,receipt_template_lang=excluded.receipt_template_lang,
              use_template_for_reminder=excluded.use_template_for_reminder,reminder_template=excluded.reminder_template,
              reminder_template_lang=excluded.reminder_template_lang,auto_reminder_enabled=excluded.auto_reminder_enabled,
              auto_reminder_interval_days=excluded.auto_reminder_interval_days,auto_reminder_min_balance=excluded.auto_reminder_min_balance
        """, (cfg["access_token"], cfg["phone_number_id"], cfg["api_version"], cfg["enabled"],
              cfg["use_template_for_receipt"], cfg["receipt_template"], cfg["receipt_template_lang"],
              cfg["use_template_for_reminder"], cfg["reminder_template"], cfg["reminder_template_lang"],
              cfg["auto_reminder_enabled"], cfg["auto_reminder_interval_days"], cfg["auto_reminder_min_balance"]))
        conn.commit()
        conn.close()
        log_action("UPDATE_WHATSAPP_SETTINGS")
        return redirect("/whatsapp?msg=Settings saved")

    cfg = whatsapp_config()
    masked_token = "••••••••" if cfg.get("access_token") else ""
    msg = request.args.get("msg")
    alert = f'<div class="alert">{escape(msg)}</div>' if msg else ""

    conn = db()
    recent = conn.execute("""
        SELECT w.*, s.name AS student_name FROM whatsapp_log w
        LEFT JOIN students s ON s.adm_no=w.adm_no ORDER BY w.id DESC LIMIT 20
    """).fetchall()
    conn.close()
    recent_trs = "".join(
        f"""<tr><td>{escape(r["created_at"] or "")}</td><td>{escape(r["kind"])}</td>
        <td>{escape(r["student_name"] or r["adm_no"] or "-")}</td><td>{escape(r["phone"] or "-")}</td>
        <td><span class="badge {'success' if r['status']=='SENT' else 'danger'}">{escape(r['status'])}</span></td></tr>"""
        for r in recent
    )

    body = f"""
    <div class="top"><div><h1>WhatsApp</h1><p class="muted">Automatic payment receipts and arrears reminders via the WhatsApp Business Cloud API — no more calling parents for their M-Pesa message.</p></div></div>
    {alert}
    <div class="panel" style="max-width:760px"><form method="post">{csrf_input()}
      <label><input type="checkbox" name="enabled" {"checked" if cfg.get("enabled") else ""}> Enabled</label>
      <label>Access Token</label><input name="access_token" value="{masked_token}" placeholder="Enter actual token to replace it">
      <label>Phone Number ID</label><input name="phone_number_id" value="{escape(cfg.get("phone_number_id",""))}" placeholder="From Meta's WhatsApp Business settings">
      <label>Graph API Version</label><input name="api_version" value="{escape(cfg.get("api_version","v20.0"))}">
      <hr>
      <h4>Payment receipts</h4>
      <label><input type="checkbox" name="use_template_for_receipt" {"checked" if cfg.get("use_template_for_receipt") else ""}> Send receipts using an approved template (recommended for reliability)</label>
      <label>Receipt Template Name</label><input name="receipt_template" value="{escape(cfg.get("receipt_template") or "")}">
      <label>Receipt Template Language</label><input name="receipt_template_lang" value="{escape(cfg.get("receipt_template_lang","en_US"))}">
      <hr>
      <h4>Arrears reminders</h4>
      <label><input type="checkbox" name="use_template_for_reminder" {"checked" if cfg.get("use_template_for_reminder") else ""}> Send reminders using an approved template (required outside the 24h chat window)</label>
      <label>Reminder Template Name</label><input name="reminder_template" value="{escape(cfg.get("reminder_template") or "")}">
      <label>Reminder Template Language</label><input name="reminder_template_lang" value="{escape(cfg.get("reminder_template_lang","en_US"))}">
      <label><input type="checkbox" name="auto_reminder_enabled" {"checked" if cfg.get("auto_reminder_enabled") else ""}> Send reminders automatically (no staff action needed)</label>
      <label>Remind every (days)</label><input type="number" min="1" name="auto_reminder_interval_days" value="{int(cfg.get("auto_reminder_interval_days") or 7)}">
      <label>Only remind if balance is at least (KES)</label><input type="number" min="0" step="0.01" name="auto_reminder_min_balance" value="{cfg.get("auto_reminder_min_balance") or 0}">
      <p class="small muted">WhatsApp requires a pre-approved message template for any business-initiated message sent outside a 24-hour customer chat window — reminders almost always need one. Create templates in Meta Business Manager first.</p>
      <button>Save WhatsApp settings</button>
    </form></div>
    <div class="panel"><h3>Recent messages</h3><table><thead><tr><th>Time</th><th>Kind</th><th>Student</th><th>Phone</th><th>Status</th></tr></thead>
    <tbody>{recent_trs or '<tr><td colspan="5">No WhatsApp messages sent yet.</td></tr>'}</tbody></table></div>
    """
    return page("WhatsApp", body, "WhatsApp")


@app.route("/stk_push", methods=["POST"])
@roles("admin", "bursar")
def stk_push():
    check_csrf()
    data = request.get_json(silent=True) or request.form
    account_no = (data.get("account_no") or "").strip().upper()
    phone = normalize_phone(data.get("phone") or "")
    try:
        amount = float(data.get("amount") or 0)
    except (TypeError, ValueError):
        amount = 0

    if not account_no or amount <= 0 or not valid_msisdn(phone):
        return jsonify(
            ok=False,
            error="Valid Student Code / Account No, positive amount and Kenyan phone are required."
        ), 400

    conn = db()
    s = conn.execute(
        "SELECT * FROM students WHERE UPPER(pay_code)=? AND active=1 LIMIT 1",
        (account_no,)
    ).fetchone()
    conn.close()

    if not s:
        return jsonify(ok=False, error="Active student not found for that Account No."), 404

    adm = s["adm_no"]

    cfg = daraja_config()
    required = ["ckey","csecret","shortcode","passkey","callback_url"]
    if any(not cfg.get(k) for k in required):
        return jsonify(ok=False, error="Daraja is not fully configured. Add credentials and callback URL first."), 400

    if "YOUR_" in cfg.get("callback_url", "").upper() or "example.com" in cfg.get("callback_url", "").lower():
        return jsonify(ok=False, error="Replace the placeholder callback URL with a real public HTTPS callback URL."), 400

    if not os.environ.get("MPESA_CALLBACK_TOKEN", "").strip():
        return jsonify(ok=False, error="Set the MPESA_CALLBACK_TOKEN environment variable first, so the callback endpoint stays protected."), 400

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(
        f'{cfg["shortcode"]}{cfg["passkey"]}{timestamp}'.encode()
    ).decode()

    conn = db()
    cur = conn.execute("""
        INSERT INTO payments(adm_no,pay_code,amount,method,phone,status,date,created_by)
        VALUES(?,?,?,?,?,?,?,?)
    """, (adm, s["pay_code"], amount, "MPESA_STK", phone, "PENDING", now(), session["username"]))
    pid = cur.lastrowid
    conn.commit()
    conn.close()

    try:
        token = daraja_token(cfg)
        url = daraja_base(cfg) + "/mpesa/stkpush/v1/processrequest"
        payload = {
            "BusinessShortCode": cfg["shortcode"],
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(round(amount)),
            "PartyA": phone,
            "PartyB": cfg["shortcode"],
            "PhoneNumber": phone,
            "CallBackURL": with_callback_token(cfg["callback_url"]),
            "AccountReference": str(s["pay_code"])[:12],
            "TransactionDesc": "School fees"[:13],
        }
        r = requests.post(url, json=payload, headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
        }, timeout=30)
        result = r.json()
        checkout = result.get("CheckoutRequestID")
        merchant = result.get("MerchantRequestID")
        response_code = str(result.get("ResponseCode", ""))
        conn = db()
        conn.execute("""
            UPDATE payments SET checkout_request_id=?,merchant_request_id=?,raw_data=?
            WHERE id=?
        """, (checkout, merchant, safe_json(result), pid))
        if response_code != "0" or not checkout:
            conn.execute("UPDATE payments SET status='FAILED' WHERE id=?", (pid,))
        conn.commit()
        conn.close()

        if response_code != "0" or not checkout:
            return jsonify(ok=False, error=result.get("errorMessage") or result.get("ResponseDescription") or "STK request failed.", data=result), 400

        log_action("STK_PUSH_SENT", adm_no=adm, new={"payment_id":pid,"checkout_request_id":checkout,"amount":amount})
        return jsonify(ok=True, payment_id=pid, checkout_request_id=checkout,
                       message="STK Push sent. Complete payment on the phone.")
    except Exception as e:
        conn = db()
        conn.execute("UPDATE payments SET status='FAILED',raw_data=? WHERE id=?",
                     (safe_json({"error":str(e)}), pid))
        conn.commit()
        conn.close()
        return jsonify(ok=False, error=str(e)), 502


def query_stk_status(cfg, checkout_id):
    timestamp=datetime.now().strftime("%Y%m%d%H%M%S")
    password=base64.b64encode(f'{cfg["shortcode"]}{cfg["passkey"]}{timestamp}'.encode()).decode()
    token=daraja_token(cfg)
    r=requests.post(daraja_base(cfg)+"/mpesa/stkpushquery/v1/query",json={"BusinessShortCode":cfg["shortcode"],"Password":password,"Timestamp":timestamp,"CheckoutRequestID":checkout_id},headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},timeout=20)
    r.raise_for_status(); return r.json()

def auto_reconcile_pending_mpesa():
    if os.environ.get("SCHOOLPAY_DISABLE_AUTO_POLL", "0") == "1":
        return
    interval = max(10, int(os.environ.get("MPESA_AUTO_POLL_SECONDS", "15")))
    while True:
        try:
            cfg = daraja_config()
            if cfg.get("ckey") and cfg.get("csecret") and cfg.get("shortcode") and cfg.get("passkey"):
                conn = db()
                pending = conn.execute("""
                    SELECT id,adm_no,checkout_request_id,amount,pay_code,phone
                    FROM payments
                    WHERE method='MPESA_STK' AND status='PENDING'
                      AND checkout_request_id IS NOT NULL
                      AND date(date)>=date('now','-2 days')
                    ORDER BY id LIMIT 20
                """).fetchall()
                conn.close()
                for p in pending:
                    try:
                        result = query_stk_status(cfg, p["checkout_request_id"])
                        rc = str(result.get("ResultCode", ""))
                        if rc == "0":
                            meta = (result.get("CallbackMetadata") or {}).get("Item") or []
                            amount = callback_item(meta, "Amount") or p["amount"]
                            receipt = callback_item(meta, "MpesaReceiptNumber")
                            phone = normalize_phone(str(callback_item(meta, "PhoneNumber") or p["phone"] or ""))
                            pid, created = record_success_payment(
                                p["adm_no"], float(amount), "MPESA_STK",
                                str(receipt or "").strip() or None, phone,
                                p["checkout_request_id"], result.get("MerchantRequestID"),
                                safe_json(result), created_by="AUTO_RECONCILE"
                            )
                            if created:
                                log_action("AUTO_MPESA_SUCCESS", adm_no=p["adm_no"],
                                           new={"payment_id": pid, "receipt": receipt, "checkout_request_id": p["checkout_request_id"]},
                                           username="SYSTEM", role="SYSTEM")
                            else:
                                conn = db(); conn.execute("UPDATE payments SET raw_data=? WHERE id=?", (safe_json(result), p["id"])); conn.commit(); conn.close()
                        elif rc in {"1032", "1037", "1", "2001"}:
                            conn = db()
                            conn.execute("UPDATE payments SET status='FAILED',raw_data=? WHERE id=? AND status='PENDING'", (safe_json(result), p["id"]))
                            conn.commit(); conn.close()
                            log_action("AUTO_MPESA_FAILED", adm_no=p["adm_no"],
                                       new={"payment_id": p["id"], "result_code": rc}, username="SYSTEM", role="SYSTEM")
                    except Exception:
                        continue

            # Safety net: if Safaricom's ResultURL callback for a manual-entry
            # verification never arrives (network hiccup, etc.), re-query status
            # for anything still PENDING after a couple of minutes.
            ts_ready = CRYPTO_AVAILABLE and all(cfg.get(k) for k in (
                "ckey", "csecret", "shortcode", "initiator_name",
                "initiator_password", "certificate_pem", "ts_result_url", "ts_timeout_url"
            ))
            if ts_ready:
                conn = db()
                stuck = conn.execute("""
                    SELECT * FROM mpesa_verifications
                    WHERE status='PENDING' AND created_at<=datetime('now','-2 minutes')
                      AND attempts<5
                    ORDER BY id LIMIT 10
                """).fetchall()
                conn.close()
                for v in stuck:
                    try:
                        result, req_payload = transaction_status_query(
                            cfg, v["mpesa_code"],
                            with_callback_token(cfg["ts_result_url"]),
                            with_callback_token(cfg["ts_timeout_url"]),
                        )
                        conn = db()
                        conn.execute("""
                            UPDATE mpesa_verifications
                            SET attempts=attempts+1, originator_conversation_id=?, conversation_id=?, raw_request=?
                            WHERE id=?
                        """, (
                            result.get("OriginatorConversationID") or v["originator_conversation_id"],
                            result.get("ConversationID") or v["conversation_id"],
                            safe_json({"request": req_payload, "ack": result}),
                            v["id"]
                        ))
                        conn.commit()
                        conn.close()
                    except Exception:
                        conn = db()
                        conn.execute("UPDATE mpesa_verifications SET attempts=attempts+1 WHERE id=?", (v["id"],))
                        conn.commit()
                        conn.close()

            # Automatic arrears reminders — once per day, at most.
            wa_cfg = whatsapp_config()
            if whatsapp_ready(wa_cfg) and wa_cfg.get("auto_reminder_enabled"):
                today = datetime.now().strftime("%Y-%m-%d")
                if setting("whatsapp_last_auto_reminder_date", "") != today:
                    interval_days = int(wa_cfg.get("auto_reminder_interval_days") or 7)
                    min_balance = float(wa_cfg.get("auto_reminder_min_balance") or 0)
                    conn = db()
                    due = conn.execute("""
                        SELECT s.* FROM students s WHERE s.active=1 AND s.balance>?
                          AND NOT EXISTS (
                            SELECT 1 FROM whatsapp_log w
                            WHERE w.adm_no=s.adm_no AND w.kind='REMINDER' AND w.status='SENT'
                              AND w.created_at>=datetime('now', ?)
                          )
                        ORDER BY s.balance DESC LIMIT 300
                    """, (min_balance, f"-{interval_days} days")).fetchall()
                    conn.close()
                    for s in due:
                        ok, detail = send_whatsapp_reminder(wa_cfg, s)
                        log_whatsapp(s["adm_no"], s["parent_phone"], "REMINDER", "SENT" if ok else "FAILED", detail)
                    set_setting("whatsapp_last_auto_reminder_date", today)
                    if due:
                        log_action("AUTO_ARREARS_REMINDERS_SENT", new={"count": len(due)}, username="SYSTEM", role="SYSTEM")
        except Exception:
            pass
        time.sleep(interval)

def callback_token_valid():
    expected = os.environ.get("MPESA_CALLBACK_TOKEN", "").strip()
    if not expected:
        # Fail closed: an unconfigured token must not leave the callback open.
        # Set MPESA_CALLBACK_TOKEN and include ?token=... in the callback/validation/
        # confirmation URLs registered with Daraja.
        return False
    supplied = request.args.get("token") or request.headers.get("X-Callback-Token")
    return bool(supplied) and secrets.compare_digest(supplied, expected)


# ================================================================
# WHATSAPP (WhatsApp Cloud API) — automatic payment receipts and
# arrears reminders, so parents don't need to be chased by phone.
# ================================================================

def whatsapp_config():
    conn = db()
    row = conn.execute("SELECT * FROM whatsapp_config WHERE id=1").fetchone()
    conn.close()
    if row:
        cfg = dict(row)
        cfg["access_token"] = decrypt_secret(cfg.get("access_token"))
        return cfg
    return {
        "access_token": os.environ.get("WHATSAPP_ACCESS_TOKEN", ""),
        "phone_number_id": os.environ.get("WHATSAPP_PHONE_NUMBER_ID", ""),
        "api_version": os.environ.get("WHATSAPP_API_VERSION", "v20.0"),
        "enabled": 1 if os.environ.get("WHATSAPP_ACCESS_TOKEN") else 0,
        "use_template_for_receipt": 0,
        "receipt_template": os.environ.get("WHATSAPP_RECEIPT_TEMPLATE", ""),
        "receipt_template_lang": "en_US",
        "use_template_for_reminder": 1,
        "reminder_template": os.environ.get("WHATSAPP_REMINDER_TEMPLATE", ""),
        "reminder_template_lang": "en_US",
        "auto_reminder_enabled": 0,
        "auto_reminder_interval_days": 7,
        "auto_reminder_min_balance": 0,
    }


def whatsapp_ready(cfg):
    return bool(cfg.get("enabled") and cfg.get("access_token") and cfg.get("phone_number_id"))


def log_whatsapp(adm_no, phone, kind, status, detail, payment_id=None):
    conn = db()
    conn.execute("""
        INSERT INTO whatsapp_log(adm_no,phone,kind,status,detail,payment_id) VALUES(?,?,?,?,?,?)
    """, (adm_no, phone, kind, status, (detail or "")[:2000], payment_id))
    conn.commit()
    conn.close()


def send_whatsapp_text(cfg, phone, message):
    msisdn = normalize_phone(phone)
    if not valid_msisdn(msisdn):
        raise ValueError(f"Invalid WhatsApp number: {phone}")
    url = f'https://graph.facebook.com/{cfg.get("api_version") or "v20.0"}/{cfg["phone_number_id"]}/messages'
    payload = {"messaging_product": "whatsapp", "to": msisdn, "type": "text", "text": {"body": message}}
    r = requests.post(url, json=payload, headers={"Authorization": "Bearer " + cfg["access_token"]}, timeout=20)
    r.raise_for_status()
    return r.json()


def send_whatsapp_template(cfg, phone, template_name, lang, body_params):
    msisdn = normalize_phone(phone)
    if not valid_msisdn(msisdn):
        raise ValueError(f"Invalid WhatsApp number: {phone}")
    url = f'https://graph.facebook.com/{cfg.get("api_version") or "v20.0"}/{cfg["phone_number_id"]}/messages'
    payload = {
        "messaging_product": "whatsapp", "to": msisdn, "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": lang or "en_US"},
            "components": [{"type": "body", "parameters": [{"type": "text", "text": str(p)} for p in body_params]}] if body_params else [],
        },
    }
    r = requests.post(url, json=payload, headers={"Authorization": "Bearer " + cfg["access_token"]}, timeout=20)
    r.raise_for_status()
    return r.json()


def dispatch_whatsapp_receipt(adm_no, name, parent_phone, amount, method, mpesa_code, new_balance, payment_id):
    """Fire-and-forget: never let a WhatsApp hiccup slow down or fail a
    payment, or delay the ACK a webhook (e.g. Safaricom) is waiting on."""
    def _worker():
        cfg = whatsapp_config()
        if not whatsapp_ready(cfg) or not parent_phone:
            return
        school = setting("school_name", "SchoolPay")
        balance_line = (f"Balance owing: {money(new_balance)}." if new_balance > 0
                         else "Your account is fully paid up." if new_balance == 0
                         else f"You have a credit of {money(abs(new_balance))}.")
        message = (
            f"Dear Parent, we've received {money(amount)} for {name} ({adm_no}) via {method}"
            + (f" (Ref: {mpesa_code})" if mpesa_code else "") + f". {balance_line} Thank you — {school}."
        )
        try:
            if cfg.get("use_template_for_receipt") and cfg.get("receipt_template"):
                resp = send_whatsapp_template(
                    cfg, parent_phone, cfg["receipt_template"], cfg.get("receipt_template_lang"),
                    [name, money(amount), money(new_balance)]
                )
            else:
                resp = send_whatsapp_text(cfg, parent_phone, message)
            log_whatsapp(adm_no, parent_phone, "RECEIPT", "SENT", safe_json(resp), payment_id)
        except Exception as e:
            log_whatsapp(adm_no, parent_phone, "RECEIPT", "FAILED", str(e), payment_id)
    threading.Thread(target=_worker, daemon=True).start()


def send_whatsapp_reminder(cfg, student):
    """Send one arrears reminder. Returns (ok, detail) — caller logs it."""
    if not whatsapp_ready(cfg):
        return False, "WhatsApp is not configured/enabled"
    if not student["parent_phone"]:
        return False, "No parent phone on file"
    school = setting("school_name", "SchoolPay")
    message = (
        f"Dear Parent, this is a reminder that {student['name']} ({student['adm_no']}) "
        f"has an outstanding balance of {money(student['balance'])} at {school}. "
        f"Kindly clear this at your earliest convenience. Thank you."
    )
    try:
        if cfg.get("use_template_for_reminder") and cfg.get("reminder_template"):
            resp = send_whatsapp_template(
                cfg, student["parent_phone"], cfg["reminder_template"], cfg.get("reminder_template_lang"),
                [student["name"], money(student["balance"])]
            )
        else:
            resp = send_whatsapp_text(cfg, student["parent_phone"], message)
        return True, safe_json(resp)
    except Exception as e:
        return False, str(e)


def with_callback_token(url):
    """Append the configured MPESA_CALLBACK_TOKEN as a query param so Daraja's
    request round-trips it back to us for verification in callback_token_valid()."""
    token = os.environ.get("MPESA_CALLBACK_TOKEN", "").strip()
    if not url or not token:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}token={token}"


def callback_item(items, name):
    for item in items or []:
        if item.get("Name") == name:
            return item.get("Value")
    return None


def _normalized_ref(value):
    """Uppercase, alphanumeric-only form of a code, so 'sch s001 f25e' or
    'sch-s001-f25e' still matches 'SCH-S001-F25E'."""
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


def c2b_student_from_reference(conn, ref):
    ref = str(ref or "").strip()
    if not ref:
        return None
    rows = conn.execute("SELECT * FROM students WHERE active=1 AND (pay_code=? OR adm_no=?) LIMIT 2", (ref, ref)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if rows:
        return None  # 2+ exact matches: genuinely ambiguous, don't guess

    # Parents at home often mistype the PayBill account number — drop the
    # hyphens/spaces/case and compare again before giving up.
    norm_ref = _normalized_ref(ref)
    if not norm_ref:
        return None
    candidates = conn.execute("SELECT * FROM students WHERE active=1").fetchall()
    matches = [s for s in candidates
               if _normalized_ref(s["pay_code"]) == norm_ref or _normalized_ref(s["adm_no"]) == norm_ref]
    return matches[0] if len(matches) == 1 else None


def c2b_student_from_phone(conn, phone):
    """Last-resort match: the sending phone number is the one registered for
    a single active student's parent. Only used once the reference itself
    couldn't be matched, and only when it identifies exactly one student."""
    if not phone:
        return None
    rows = conn.execute("SELECT * FROM students WHERE active=1 AND parent_phone=? LIMIT 2", (phone,)).fetchall()
    return rows[0] if len(rows) == 1 else None


@app.route("/mpesa/c2b/validation", methods=["POST"])
def c2b_validation():
    if not callback_token_valid():
        return jsonify(ResultCode=1, ResultDesc="Rejected"), 403
    payload = request.get_json(silent=True) or request.form.to_dict()
    # Do not reject unknown references here. Accepting them allows SchoolPay to place
    # the transaction in the unmatched queue instead of losing a parent's payment.
    return jsonify(ResultCode=0, ResultDesc="Accepted")


@app.route("/mpesa/c2b/confirmation", methods=["POST"])
def c2b_confirmation():
    if not callback_token_valid():
        return jsonify(ResultCode=1, ResultDesc="Rejected"), 403
    payload = request.get_json(silent=True) or request.form.to_dict()
    raw = safe_json(payload)
    receipt = str(payload.get("TransID") or payload.get("MpesaReceiptNumber") or payload.get("TransId") or "").strip() or None
    amount = payload.get("TransAmount") or payload.get("Amount")
    phone = normalize_phone(str(payload.get("MSISDN") or payload.get("PhoneNumber") or ""))
    ref = str(payload.get("BillRefNumber") or payload.get("AccountReference") or "").strip()
    try:
        amount_num = float(amount)
    except (TypeError, ValueError):
        amount_num = 0
    if amount_num <= 0:
        return jsonify(ResultCode=0, ResultDesc="Accepted")

    conn = db()
    student = c2b_student_from_reference(conn, ref)
    match_method = "reference" if student else None
    if not student:
        student = c2b_student_from_phone(conn, phone)
        if student:
            match_method = "phone"
    conn.close()
    if student:
        try:
            pid, created = record_success_payment(
                student["adm_no"], amount_num, "MPESA_C2B", receipt, phone,
                raw_data=raw, created_by="DARAJA_C2B"
            )
            if created:
                log_action("C2B_PAYMENT_SUCCESS", adm_no=student["adm_no"],
                           new={"payment_id": pid, "receipt": receipt, "amount": amount_num,
                                "pay_code": student["pay_code"], "matched_by": match_method},
                           username="DARAJA", role="SYSTEM")
        except sqlite3.IntegrityError:
            pass
    else:
        conn = db()
        conn.execute("""
            INSERT INTO unmatched_payments(mpesa_code,amount,phone,pay_code,raw_data,reason)
            VALUES(?,?,?,?,?,?)
        """, (receipt, amount_num, phone, ref, raw,
              "C2B PayBill payment could not be safely matched to one student by reference or parent phone"))
        conn.commit(); conn.close()
        log_action("C2B_PAYMENT_UNMATCHED", new={"receipt": receipt, "amount": amount_num, "pay_code": ref, "phone": phone}, username="DARAJA", role="SYSTEM")
    return jsonify(ResultCode=0, ResultDesc="Accepted")


@app.route("/mpesa/callback", methods=["POST"])
def mpesa_callback():
    if not callback_token_valid():
        return jsonify(ResultCode=1, ResultDesc="Rejected"), 403

    payload = request.get_json(silent=True) or {}
    raw = safe_json(payload)

    # STK callback shape.
    stk = ((payload.get("Body") or {}).get("stkCallback") or {})
    checkout_id = stk.get("CheckoutRequestID")
    merchant_id = stk.get("MerchantRequestID")
    result_code = stk.get("ResultCode")

    if stk:
        if str(result_code) != "0":
            if checkout_id:
                conn = db()
                conn.execute("""
                    UPDATE payments SET status='FAILED',merchant_request_id=?,raw_data=?
                    WHERE checkout_request_id=? AND status='PENDING'
                """, (merchant_id, raw, checkout_id))
                conn.commit()
                conn.close()
            return jsonify(ResultCode=0, ResultDesc="Accepted")

        meta = (stk.get("CallbackMetadata") or {}).get("Item") or []
        amount = callback_item(meta, "Amount")
        receipt = callback_item(meta, "MpesaReceiptNumber")
        phone = callback_item(meta, "PhoneNumber")

        conn = db()
        pending = conn.execute("""
            SELECT * FROM payments WHERE checkout_request_id=? LIMIT 1
        """, (checkout_id,)).fetchone() if checkout_id else None
        conn.close()

        if pending:
            if amount is None or abs(float(amount) - float(pending["amount"])) > 0.001:
                conn = db()
                conn.execute("""
                    UPDATE payments SET status='AMOUNT_MISMATCH',merchant_request_id=?,phone=?,raw_data=?
                    WHERE id=?
                """, (merchant_id, normalize_phone(str(phone or "")), raw, pending["id"]))
                conn.execute("""
                    INSERT INTO unmatched_payments(mpesa_code,amount,phone,pay_code,adm_no,raw_data,reason)
                    VALUES(?,?,?,?,?,?,?)
                """, (receipt, amount, normalize_phone(str(phone or "")),
                      pending["pay_code"], pending["adm_no"], raw, "STK amount mismatch"))
                conn.commit()
                conn.close()
                return jsonify(ResultCode=0, ResultDesc="Accepted")

            conn = db()
            conn.execute("UPDATE payments SET merchant_request_id=?,phone=?,raw_data=? WHERE id=?",
                         (merchant_id, normalize_phone(str(phone or "")), raw, pending["id"]))
            conn.commit()
            conn.close()
            try:
                pid, created = record_success_payment(
                    pending["adm_no"], float(amount), "MPESA_STK",
                    str(receipt or "").strip() or None, normalize_phone(str(phone or "")),
                    checkout_id, merchant_id, raw, created_by="DARAJA"
                )
                if created:
                    log_action("MPESA_CALLBACK_SUCCESS", adm_no=pending["adm_no"],
                               new={"payment_id":pid,"receipt":receipt,"checkout_request_id":checkout_id},
                               username="DARAJA", role="SYSTEM")
            except sqlite3.IntegrityError:
                # Duplicate receipt: do not deduct twice.
                pass
            return jsonify(ResultCode=0, ResultDesc="Accepted")

        # If no pending STK record, try a precise reference match.
        ref = None
        for key in ("AccountReference", "BillRefNumber", "accountReference"):
            if payload.get(key):
                ref = str(payload[key]).strip()
                break
        conn = db()
        s = c2b_student_from_reference(conn, ref) if ref else None
        if not s:
            s = c2b_student_from_phone(conn, normalize_phone(str(phone or "")))
        conn.close()
        if s and amount:
            try:
                pid, created = record_success_payment(
                    s["adm_no"], float(amount), "MPESA_CALLBACK",
                    str(receipt or "").strip() or None, normalize_phone(str(phone or "")),
                    checkout_id, merchant_id, raw, created_by="DARAJA"
                )
                return jsonify(ResultCode=0, ResultDesc="Accepted")
            except Exception:
                pass

        # Never guess when identity is ambiguous.
        conn = db()
        conn.execute("""
            INSERT INTO unmatched_payments(mpesa_code,amount,phone,raw_data,reason)
            VALUES(?,?,?,?,?)
        """, (receipt, amount, normalize_phone(str(phone or "")), raw, "No safe student match"))
        conn.commit()
        conn.close()
        return jsonify(ResultCode=0, ResultDesc="Accepted")

    # Generic/C2B-like callback: try common fields.
    result = payload.get("Result") or payload.get("Transaction") or payload
    receipt = result.get("TransID") or result.get("MpesaReceiptNumber") or result.get("TransId")
    amount = result.get("TransAmount") or result.get("Amount")
    phone = normalize_phone(str(result.get("MSISDN") or result.get("PhoneNumber") or ""))
    ref = str(result.get("BillRefNumber") or result.get("AccountReference") or "").strip()

    conn = db()
    student = c2b_student_from_reference(conn, ref) if ref else None
    if not student:
        student = c2b_student_from_phone(conn, phone)
    conn.close()

    if student and amount is not None:
        try:
            pid, created = record_success_payment(
                student["adm_no"], float(amount), "MPESA_CALLBACK",
                str(receipt or "").strip() or None, phone,
                raw_data=raw, created_by="DARAJA"
            )
            if created:
                log_action("MPESA_GENERIC_CALLBACK", adm_no=student["adm_no"],
                           new={"payment_id":pid,"receipt":receipt}, username="DARAJA", role="SYSTEM")
        except Exception:
            pass
    else:
        conn = db()
        conn.execute("""
            INSERT INTO unmatched_payments(mpesa_code,amount,phone,pay_code,raw_data,reason)
            VALUES(?,?,?,?,?,?)
        """, (receipt, amount, phone, ref, raw,
              "No match or multiple students share the phone number"))
        conn.commit()
        conn.close()

    return jsonify(ResultCode=0, ResultDesc="Accepted")


# ================================================================
# TRANSACTION STATUS VERIFICATION (manual M-Pesa entries on /pay)
# ================================================================

def apply_verification_result(verif, result_code, tx_status, amount, receipt, raw, reference=None, result_desc=None):
    """Shared outcome handling for a Transaction Status result, whether it
    arrived via the live callback or a safety-net requery."""
    conn = db()
    try:
        if str(result_code) == "0" and str(tx_status or "").strip().lower().startswith("complet"):
            # Some Daraja accounts echo the account/bill reference in the
            # Transaction Status result. When present, cross-check it against
            # the student the bursar actually selected — never switch students
            # based on the callback alone.
            ref = str(reference or "").strip().upper()
            if ref and ref not in (str(verif["adm_no"] or "").upper(),):
                conn2 = db()
                s = conn2.execute("SELECT pay_code FROM students WHERE adm_no=?", (verif["adm_no"],)).fetchone()
                conn2.close()
                expected_ref = str(s["pay_code"] or "").upper() if s else ""
                if expected_ref and ref != expected_ref and _normalized_ref(ref) != _normalized_ref(expected_ref):
                    reason = "Safaricom's reference on this transaction doesn't match the student selected at /pay"
                    conn.execute("""
                        UPDATE mpesa_verifications SET status='MISMATCH', raw_result=?, reason=?, resolved_at=? WHERE id=?
                    """, (raw, reason, now(), verif["id"]))
                    conn.commit()
                    log_action("MPESA_VERIFY_REF_MISMATCH", adm_no=verif["adm_no"],
                               new={"verification_id": verif["id"], "safaricom_ref": ref, "expected_ref": expected_ref},
                               username="SYSTEM", role="SYSTEM")
                    return

            try:
                amt = float(amount) if amount is not None else None
            except (TypeError, ValueError):
                amt = None
            if amt is None or abs(amt - float(verif["expected_amount"])) > 0.001:
                reason = f"Safaricom-confirmed amount ({amt}) does not match the amount entered at /pay ({verif['expected_amount']})"
                conn.execute("""
                    UPDATE mpesa_verifications SET status='MISMATCH', raw_result=?, reason=?, resolved_at=? WHERE id=?
                """, (raw, reason, now(), verif["id"]))
                conn.execute("""
                    INSERT INTO unmatched_payments(mpesa_code,amount,pay_code,adm_no,raw_data,reason)
                    VALUES(?,?,?,?,?,?)
                """, (receipt or verif["mpesa_code"], amt, None, verif["adm_no"], raw, reason))
                conn.commit()
                log_action("MPESA_VERIFY_MISMATCH", adm_no=verif["adm_no"],
                           new={"verification_id": verif["id"], "expected": verif["expected_amount"], "confirmed": amt},
                           username="SYSTEM", role="SYSTEM")
                return
            conn.commit()
            conn.close()
            try:
                pid, created = record_success_payment(
                    verif["adm_no"], amt, "MPESA_MANUAL_VERIFIED",
                    str(receipt or verif["mpesa_code"]).strip() or None, None,
                    raw_data=raw, created_by=verif["initiated_by"] or "SYSTEM"
                )
            except sqlite3.IntegrityError:
                pid, created = None, False
            conn = db()
            conn.execute("""
                UPDATE mpesa_verifications SET status='VERIFIED', raw_result=?, payment_id=?, reason=?, resolved_at=? WHERE id=?
            """, (raw, pid, "Ledger credited from Safaricom-verified transaction", now(), verif["id"]))
            conn.commit()
            if created:
                log_action("MPESA_VERIFY_SUCCESS", adm_no=verif["adm_no"],
                           new={"verification_id": verif["id"], "payment_id": pid, "receipt": receipt},
                           username="SYSTEM", role="SYSTEM")
        else:
            reason = str(result_desc) if result_desc else "Safaricom did not confirm this transaction as completed"
            conn.execute("""
                UPDATE mpesa_verifications SET status='FAILED', raw_result=?, reason=?, resolved_at=? WHERE id=?
            """, (raw, reason, now(), verif["id"]))
            conn.commit()
            log_action("MPESA_VERIFY_FAILED", adm_no=verif["adm_no"],
                       new={"verification_id": verif["id"], "result_code": result_code, "tx_status": tx_status},
                       username="SYSTEM", role="SYSTEM")
    finally:
        conn.close()


@app.route("/mpesa/verification/<int:verification_id>")
@roles("admin", "bursar")
def mpesa_verification_status(verification_id):
    conn = db()
    v = conn.execute("""
        SELECT v.*, s.name AS student_name FROM mpesa_verifications v
        LEFT JOIN students s ON s.adm_no=v.adm_no WHERE v.id=?
    """, (verification_id,)).fetchone()
    conn.close()
    if not v:
        return page("M-Pesa Verification", '<div class="alert">Verification request not found.</div>', "Pay"), 404
    badge = {"VERIFIED": "success", "PENDING": "warn"}.get(v["status"], "danger")
    meta = "" if v["status"] != "PENDING" else '<meta http-equiv="refresh" content="10">'
    body = f"""{meta}
    <div class="top"><div><h1>M-Pesa Receipt Verification</h1><p class="muted">SchoolPay is checking this receipt against Safaricom directly.</p></div></div>
    <div class="panel" style="max-width:760px">
      <p><b>Receipt entered:</b> {escape(v['mpesa_code'] or '-')}</p>
      <p><b>Student:</b> {escape(v['student_name'] or '-')} ({escape(v['adm_no'] or '-')})</p>
      <p><b>Amount entered:</b> {money(v['expected_amount'] or 0)}</p>
      <p><b>Status:</b> <span class="badge {badge}">{escape(v['status'])}</span></p>
      <p><b>Detail:</b> {escape(v['reason'] or 'Waiting for Safaricom to respond...')}</p>
      <p class="small muted">{'This page refreshes automatically every 10 seconds while pending.' if v['status']=='PENDING' else 'Requested by ' + escape(v['initiated_by'] or '-') + ' on ' + escape(v['created_at'] or '-') + '.'}</p>
      <a class="btn secondary" href="/pay">Back to Pay</a>
      <a class="btn secondary" href="/reconciliation">All verifications</a>
    </div>"""
    return page("M-Pesa Verification", body, "Pay")


@app.route("/mpesa/transactionstatus/result", methods=["POST"])
def mpesa_transaction_status_result():
    if not callback_token_valid():
        return jsonify(ResultCode=1, ResultDesc="Rejected"), 403
    payload = request.get_json(silent=True) or {}
    raw = safe_json(payload)
    result = payload.get("Result") or {}
    oconv = result.get("OriginatorConversationID") or payload.get("OriginatorConversationID")
    conv = result.get("ConversationID") or payload.get("ConversationID")
    tx_id = str(ts_result_value(result, "TransactionID") or result.get("TransactionID") or "").strip()

    conn = db()
    verif = conn.execute("""
        SELECT * FROM mpesa_verifications WHERE originator_conversation_id=? AND status='PENDING' LIMIT 1
    """, (oconv,)).fetchone()
    if not verif and conv:
        # Some Daraja accounts only echo ConversationID, not OriginatorConversationID.
        verif = conn.execute("""
            SELECT * FROM mpesa_verifications WHERE conversation_id=? AND status='PENDING' LIMIT 1
        """, (conv,)).fetchone()
    if not verif and tx_id:
        verif = conn.execute("""
            SELECT * FROM mpesa_verifications WHERE mpesa_code=? AND status='PENDING' LIMIT 1
        """, (tx_id,)).fetchone()
    conn.close()
    if not verif:
        # Unknown or already-resolved conversation — nothing to do, but still ack.
        return jsonify(ResultCode=0, ResultDesc="Accepted")

    tx_status = ts_result_value(result, "TransactionStatus")
    amount = ts_result_value(result, "Amount", "TransactionAmount", "TransAmount")
    receipt = ts_result_value(result, "ReceiptNo", "MpesaReceiptNumber", "TransactionReceipt") or tx_id
    reference = ts_result_value(result, "BillReferenceNumber", "BillRefNumber", "AccountReference")
    result_desc = result.get("ResultDesc") or payload.get("ResultDesc")
    apply_verification_result(verif, result.get("ResultCode"), tx_status, amount, receipt, raw,
                               reference=reference, result_desc=result_desc)
    return jsonify(ResultCode=0, ResultDesc="Accepted")


@app.route("/mpesa/transactionstatus/timeout", methods=["POST"])
def mpesa_transaction_status_timeout():
    if not callback_token_valid():
        return jsonify(ResultCode=1, ResultDesc="Rejected"), 403
    payload = request.get_json(silent=True) or {}
    raw = safe_json(payload)
    result = payload.get("Result") or payload
    oconv = result.get("OriginatorConversationID")
    conn = db()
    conn.execute("""
        UPDATE mpesa_verifications SET status='TIMEOUT', raw_result=?
        WHERE originator_conversation_id=? AND status='PENDING'
    """, (raw, oconv))
    conn.commit()
    conn.close()
    log_action("MPESA_VERIFY_TIMEOUT", new={"originator_conversation_id": oconv}, username="SYSTEM", role="SYSTEM")
    return jsonify(ResultCode=0, ResultDesc="Accepted")


# ================================================================
# M-PESA RECONCILIATION CENTER
# ================================================================

@app.route("/reconciliation")
@roles("admin", "bursar")
def reconciliation():
    conn = db()
    counts = conn.execute("""
        SELECT
          SUM(CASE WHEN status='SUCCESS' THEN 1 ELSE 0 END) matched,
          SUM(CASE WHEN status='PENDING' THEN 1 ELSE 0 END) pending,
          SUM(CASE WHEN status IN ('FAILED','CANCELLED') THEN 1 ELSE 0 END) failed,
          SUM(CASE WHEN status='REVERSED' THEN 1 ELSE 0 END) reversed
        FROM payments WHERE UPPER(method) LIKE 'MPESA%'
    """).fetchone()
    unmatched_count = conn.execute("SELECT COUNT(*) n FROM unmatched_payments WHERE status='UNRESOLVED'").fetchone()["n"]
    rows = conn.execute("""
        SELECT p.*, s.name AS student_name
        FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no
        WHERE UPPER(p.method) LIKE 'MPESA%'
        ORDER BY p.id DESC LIMIT 100
    """).fetchall()
    verifications = conn.execute("""
        SELECT v.*, s.name AS student_name
        FROM mpesa_verifications v LEFT JOIN students s ON s.adm_no=v.adm_no
        ORDER BY v.id DESC LIMIT 50
    """).fetchall()
    conn.close()
    trs = ''.join(
        f"""<tr><td>{r["id"]}</td><td>{escape(r["date"] or "")}</td><td>{escape(r["mpesa_code"] or "-")}</td>
        <td>{escape(r["adm_no"] or "-")}</td><td>{escape(r["student_name"] or "-")}</td><td>{money(r["amount"])}</td>
        <td><span class="badge {'success' if r['status']=='SUCCESS' else 'warn' if r['status']=='PENDING' else 'danger'}">{escape(r['status'])}</span></td></tr>"""
        for r in rows
    )
    verif_badge = {
        "PENDING": "warn", "VERIFIED": "success", "MISMATCH": "danger",
        "FAILED": "danger", "TIMEOUT": "danger",
    }
    verif_trs = ''.join(
        f"""<tr><td>{v["id"]}</td><td>{escape(v["created_at"] or "")}</td><td>{escape(v["mpesa_code"] or "-")}</td>
        <td>{escape(v["adm_no"] or "-")}</td><td>{escape(v["student_name"] or "-")}</td><td>{money(v["expected_amount"])}</td>
        <td>{escape(v["initiated_by"] or "-")}</td>
        <td><span class="badge {verif_badge.get(v['status'],'info')}">{escape(v['status'])}</span></td></tr>"""
        for v in verifications
    )
    body = f"""<div class="top"><div><h1>M-Pesa Reconciliation</h1><p class="muted">Monitor automatic matching and payments that need attention.</p></div><a class="btn secondary" href="/unmatched">Review unmatched ({unmatched_count})</a></div>
    <div class="grid"><div class="card stat"><div class="label">Matched</div><div class="value">{int(counts["matched"] or 0)}</div></div>
    <div class="card stat"><div class="label">Pending</div><div class="value">{int(counts["pending"] or 0)}</div></div>
    <div class="card stat"><div class="label">Failed</div><div class="value">{int(counts["failed"] or 0)}</div></div>
    <div class="card stat"><div class="label">Unmatched</div><div class="value">{unmatched_count}</div></div></div>
    <div class="panel"><h3>Recent M-Pesa transactions</h3><table><thead><tr><th>ID</th><th>Date</th><th>Receipt</th><th>ADM</th><th>Student</th><th>Amount</th><th>Status</th></tr></thead><tbody>{trs or '<tr><td colspan="7">No M-Pesa transactions.</td></tr>'}</tbody></table></div>
    <div class="panel"><h3>Manual M-Pesa verifications</h3><p class="muted">Receipts typed in on the <a href="/pay">Pay</a> page are checked against Safaricom before they touch any balance.</p>
    <table><thead><tr><th>ID</th><th>Requested</th><th>Receipt</th><th>ADM</th><th>Student</th><th>Amount</th><th>By</th><th>Status</th></tr></thead>
    <tbody>{verif_trs or '<tr><td colspan="8">No manual M-Pesa verifications yet.</td></tr>'}</tbody></table></div>"""
    return page("M-Pesa Reconciliation", body, "Reconcile")


# ================================================================
# UNMATCHED PAYMENTS
# ================================================================

@app.route("/unmatched")
@login_required
def unmatched():
    conn = db()
    rows = conn.execute("""
        SELECT * FROM unmatched_payments WHERE status='UNRESOLVED'
        ORDER BY id DESC LIMIT 300
    """).fetchall()
    conn.close()
    trs = "".join(
        f"""<tr><td>{x["id"]}</td><td>{escape(x["created_at"])}</td><td>{escape(x["mpesa_code"] or "-")}</td>
        <td>{money(x["amount"])}</td><td>{escape(x["phone"] or "-")}</td><td>{escape(x["pay_code"] or "-")}</td>
        <td>{escape(x["reason"] or "-")}</td><td><a class="btn secondary" href="/unmatched/{x["id"]}">Resolve</a></td></tr>"""
        for x in rows
    )
    body = f"""
    <div class="top"><div><h1>Unmatched payments</h1><p class="muted">Payments that were not safely linked to one student.</p></div></div>
    <div class="panel"><table><thead><tr><th>ID</th><th>Date</th><th>Receipt</th><th>Amount</th><th>Phone</th><th>Reference</th><th>Reason</th><th></th></tr></thead>
    <tbody>{trs or '<tr><td colspan="8">No unresolved payments.</td></tr>'}</tbody></table></div>"""
    return page("Unmatched", body, "Unmatched")


@app.route("/unmatched/<int:uid>", methods=["GET", "POST"])
@roles("admin", "bursar")
def resolve_unmatched(uid):
    conn = db()
    u = conn.execute("SELECT * FROM unmatched_payments WHERE id=?", (uid,)).fetchone()
    students = conn.execute("SELECT adm_no,name,class,pay_code FROM students WHERE active=1 ORDER BY name").fetchall()
    conn.close()
    if not u:
        abort(404)
    if request.method == "POST":
        check_csrf()
        adm = request.form.get("adm_no", "").strip()
        conn = db()
        s = conn.execute("SELECT * FROM students WHERE adm_no=?", (adm,)).fetchone()
        conn.close()
        if not s:
            return page("Resolve payment", '<div class="alert">Student not found.</div>', "Unmatched")
        if u["amount"] is None or float(u["amount"]) <= 0:
            return page("Resolve payment", '<div class="alert">Invalid payment amount.</div>', "Unmatched")
        try:
            pid, created = record_success_payment(
                adm, float(u["amount"]), "MPESA_RECONCILED",
                u["mpesa_code"], u["phone"], raw_data=u["raw_data"],
                created_by=session["username"]
            )
            conn = db()
            conn.execute("""
                UPDATE unmatched_payments SET status='RESOLVED',adm_no=?,resolved_by=?,resolved_at=?
                WHERE id=?
            """, (adm, session["username"], now(), uid))
            conn.commit()
            conn.close()
            log_action("RESOLVE_UNMATCHED", adm_no=adm, new={"unmatched_id":uid,"payment_id":pid})
            return redirect("/unmatched")
        except sqlite3.IntegrityError:
            return page("Resolve payment", '<div class="alert">This M-Pesa reference already exists.</div>', "Unmatched")

    options = "".join(
        f'<option value="{escape(s["adm_no"])}">{escape(s["adm_no"])} — {escape(s["name"])} ({escape(s["class"])}) — {escape(s["pay_code"])}</option>'
        for s in students
    )
    body = f"""
    <div class="top"><div><h1>Resolve unmatched payment</h1><p class="muted">Confirm the correct student before crediting the account.</p></div></div>
    <div class="panel" style="max-width:760px">
      <div class="formgrid"><div><b>Receipt</b><div>{escape(u["mpesa_code"] or "-")}</div></div>
      <div><b>Amount</b><div>{money(u["amount"])}</div></div><div><b>Phone</b><div>{escape(u["phone"] or "-")}</div></div>
      <div><b>Reference</b><div>{escape(u["pay_code"] or "-")}</div></div></div>
      <form method="post">{csrf_input()}<label>Apply to student</label><select name="adm_no" required><option value="">Select...</option>{options}</select>
      <button>Resolve and credit account</button></form>
    </div>"""
    return page("Resolve payment", body, "Unmatched")


# ================================================================
# REPORTS
# ================================================================

@app.route("/reports")
@login_required
def reports():
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    grade = request.args.get("class", "").strip()

    conn = db()
    sql = """
      SELECT COALESCE(SUM(p.amount),0) paid, COUNT(p.id) count
      FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no
      WHERE p.status='SUCCESS' AND p.reversed_at IS NULL
    """
    args = []
    if start:
        sql += " AND date(p.date)>=date(?)"
        args.append(start)
    if end:
        sql += " AND date(p.date)<=date(?)"
        args.append(end)
    if grade:
        sql += " AND s.class=?"
        args.append(grade)
    totals = conn.execute(sql, args).fetchone()

    by_method = conn.execute("""
      SELECT method,COALESCE(SUM(amount),0) amount,COUNT(*) count
      FROM payments
      WHERE status='SUCCESS' AND reversed_at IS NULL
      GROUP BY method ORDER BY amount DESC
    """).fetchall()

    by_class = conn.execute("""
      SELECT class,COUNT(*) students,COALESCE(SUM(total_fees),0) fees,
             COALESCE(SUM(total_paid),0) paid,
             COALESCE(SUM(CASE WHEN balance>0 THEN balance ELSE 0 END),0) owed
      FROM students WHERE active=1 GROUP BY class ORDER BY class
    """).fetchall()
    conn.close()

    methods = "".join(f'<tr><td>{escape(x["method"])}</td><td>{x["count"]}</td><td>{money(x["amount"])}</td></tr>' for x in by_method)
    classes = "".join(f'<tr><td>{escape(x["class"])}</td><td>{x["students"]}</td><td>{money(x["fees"])}</td><td>{money(x["paid"])}</td><td>{money(x["owed"])}</td></tr>' for x in by_class)

    body = f"""
    <div class="top"><div><h1>Reports</h1><p class="muted">Collection and outstanding-balance overview.</p></div>
      <a class="btn secondary" href="/export/payments">Export Excel</a></div>
    <div class="panel"><form class="formgrid">
      <div><label>Start date</label><input type="date" name="start" value="{escape(start)}"></div>
      <div><label>End date</label><input type="date" name="end" value="{escape(end)}"></div>
      <div><label>Class</label><input name="class" value="{escape(grade)}"></div>
      <div><label>&nbsp;</label><button>Run report</button></div>
    </form></div>
    <div class="grid">
      <div class="card stat"><div class="label">Payments</div><div class="value">{totals["count"]}</div></div>
      <div class="card stat"><div class="label">Collected</div><div class="value">{money(totals["paid"])}</div></div>
    </div>
    <div class="panel"><h3>By payment method</h3><table><thead><tr><th>Method</th><th>Count</th><th>Amount</th></tr></thead><tbody>{methods or '<tr><td colspan="3">No data.</td></tr>'}</tbody></table></div>
    <div class="panel"><h3>By class</h3><table><thead><tr><th>Class</th><th>Students</th><th>Fees</th><th>Paid</th><th>Outstanding</th></tr></thead><tbody>{classes}</tbody></table></div>
    """
    return page("Reports", body, "Reports")


@app.route("/reports/arrears")
@login_required
def arrears_report():
    grade = request.args.get("class", "").strip()
    min_balance = request.args.get("min_balance", "").strip()
    try:
        min_balance_val = float(min_balance) if min_balance else 0.01
    except ValueError:
        min_balance_val = 0.01

    conn = db()
    sql = """
        SELECT s.*, 
          (SELECT MAX(p.date) FROM payments p WHERE p.adm_no=s.adm_no AND p.status='SUCCESS') AS last_payment_date,
          (SELECT MAX(w.created_at) FROM whatsapp_log w WHERE w.adm_no=s.adm_no AND w.kind='REMINDER' AND w.status='SENT') AS last_reminder_at
        FROM students s WHERE s.active=1 AND s.balance>=?
    """
    args = [min_balance_val]
    if grade:
        sql += " AND s.class=?"
        args.append(grade)
    sql += " ORDER BY s.balance DESC"
    rows = conn.execute(sql, args).fetchall()
    total_owed = sum(r["balance"] for r in rows)
    conn.close()

    wa_cfg = whatsapp_config()
    can_remind = whatsapp_ready(wa_cfg)
    msg = request.args.get("msg")
    msg_html = f'<div class="alert">{escape(msg)}</div>' if msg else ""

    trs = "".join(
        f"""<tr>
        <td><input type="checkbox" name="adm_no" value="{escape(r['adm_no'])}"></td>
        <td>{escape(r['adm_no'])}</td><td>{escape(r['name'])}</td><td>{escape(r['class'])}</td>
        <td>{escape(r['parent_phone'] or '-')}</td><td>{money(r['balance'])}</td>
        <td>{escape(r['last_payment_date'] or 'Never')}</td>
        <td>{escape(r['last_reminder_at'] or 'Never')}</td>
        </tr>"""
        for r in rows
    )
    body = f"""
    <div class="top"><div><h1>Arrears</h1><p class="muted">Students with an outstanding balance, with one-tap WhatsApp reminders.</p></div>
      <a class="btn secondary" href="/export/arrears?class={escape(grade)}&min_balance={escape(min_balance)}">Export Excel</a></div>
    {msg_html}
    <div class="panel"><form class="formgrid" method="get">
      <div><label>Class</label><input name="class" value="{escape(grade)}"></div>
      <div><label>Min balance (KES)</label><input name="min_balance" value="{escape(min_balance)}" placeholder="0.01"></div>
      <div><label>&nbsp;</label><button>Filter</button></div>
    </form></div>
    <div class="grid">
      <div class="card stat"><div class="label">Students in arrears</div><div class="value">{len(rows)}</div></div>
      <div class="card stat"><div class="label">Total owed</div><div class="value">{money(total_owed)}</div></div>
    </div>
    {'<div class="alert">Configure and enable WhatsApp on the <a href="/whatsapp">WhatsApp settings</a> page to send reminders.</div>' if not can_remind else ''}
    <div class="panel">
    <form method="post" action="/reports/arrears/remind">{csrf_input()}
      <input type="hidden" name="class" value="{escape(grade)}"><input type="hidden" name="min_balance" value="{escape(min_balance)}">
      <table><thead><tr><th><input type="checkbox" onclick="this.closest('table').querySelectorAll('input[name=adm_no]').forEach(c=>c.checked=this.checked)"></th>
      <th>ADM</th><th>Name</th><th>Class</th><th>Parent Phone</th><th>Balance</th><th>Last Payment</th><th>Last Reminder</th></tr></thead>
      <tbody>{trs or '<tr><td colspan="8">No students in arrears for this filter.</td></tr>'}</tbody></table>
      {'<button class="btn green" style="margin-top:12px">Send WhatsApp reminder to selected</button>' if can_remind and rows else ''}
    </form>
    </div>
    """
    return page("Arrears", body, "Arrears")


@app.route("/reports/arrears/remind", methods=["POST"])
@roles("admin", "bursar")
def arrears_remind():
    check_csrf()
    adm_nos = request.form.getlist("adm_no")
    grade = request.form.get("class", "")
    min_balance = request.form.get("min_balance", "")
    cfg = whatsapp_config()
    if not whatsapp_ready(cfg):
        return redirect(f"/reports/arrears?class={grade}&min_balance={min_balance}&msg=WhatsApp is not configured")
    if not adm_nos:
        return redirect(f"/reports/arrears?class={grade}&min_balance={min_balance}")

    conn = db()
    sent, failed = 0, 0
    for adm_no in adm_nos[:200]:  # sane cap per click
        s = conn.execute("SELECT * FROM students WHERE adm_no=? AND active=1 AND balance>0", (adm_no,)).fetchone()
        if not s:
            continue
        ok, detail = send_whatsapp_reminder(cfg, s)
        log_whatsapp(adm_no, s["parent_phone"], "REMINDER", "SENT" if ok else "FAILED", detail)
        sent += 1 if ok else 0
        failed += 0 if ok else 1
    conn.close()
    log_action("ARREARS_REMINDERS_SENT", new={"sent": sent, "failed": failed})
    return redirect(f"/reports/arrears?class={grade}&min_balance={min_balance}")


# ================================================================
# USERS / SETTINGS
# ================================================================

@app.route("/users", methods=["GET", "POST"])
@roles("admin")
def users():
    if request.method == "POST":
        check_csrf()
        action = request.form.get("action")
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "bursar")
        password = request.form.get("password", "")
        if action == "add":
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
                return page("Users", '<div class="alert">Invalid username.</div>', "Users")
            if len(password) < 10:
                return page("Users", '<div class="alert">Password must be at least 10 characters.</div>', "Users")
            if role not in {"admin","bursar"}:
                return page("Users", '<div class="alert">Invalid role.</div>', "Users")
            conn = db()
            try:
                conn.execute("""
                    INSERT INTO users(username,password_hash,role,must_change_password)
                    VALUES(?,?,?,0)
                """, (username, generate_password_hash(password), role))
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return page("Users", '<div class="alert">Username already exists.</div>', "Users")
            conn.close()
            log_action("ADD_USER", new={"username":username,"role":role})
        elif action == "reset":
            if len(password) < 10:
                return page("Users", '<div class="alert">Password must be at least 10 characters.</div>', "Users")
            conn = db()
            conn.execute("""
                UPDATE users SET password_hash=?,must_change_password=1 WHERE username=?
            """, (generate_password_hash(password), username))
            conn.commit()
            conn.close()
            log_action("RESET_USER_PASSWORD", new={"username":username})
        elif action == "delete":
            if username == session["username"]:
                return page("Users", '<div class="alert">You cannot delete your own account.</div>', "Users")
            conn = db()
            conn.execute("DELETE FROM users WHERE username=?", (username,))
            conn.commit()
            conn.close()
            log_action("DELETE_USER", new={"username":username})

    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    conn.close()
    trs = "".join(
        f'<tr><td>{escape(u["username"])}</td><td>{escape(u["role"])}</td><td>{escape(u["created_at"] or "-")}</td>'
        f'<td>{"Yes" if u["must_change_password"] else "No"}</td>'
        f'<td><form method="post" style="display:flex;gap:5px">{csrf_input()}<input type="hidden" name="action" value="delete"><input type="hidden" name="username" value="{escape(u["username"])}"><button class="btn red">Delete</button></form></td></tr>'
        for u in rows
    )
    body = f"""
    <div class="top"><div><h1>Users</h1><p class="muted">Admin-only account management.</p></div></div>
    <div class="panel" style="max-width:760px"><h3>Add user</h3><form method="post">{csrf_input()}<input type="hidden" name="action" value="add">
      <div class="formgrid"><div><label>Username</label><input name="username" required></div>
      <div><label>Role</label><select name="role"><option value="bursar">Bursar</option><option value="admin">Admin</option></select></div>
      <div><label>Password</label><input type="password" name="password" minlength="10" required></div></div>
      <button>Add user</button></form></div>
    <div class="panel"><h3>Existing users</h3><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Must change</th><th></th></tr></thead><tbody>{trs}</tbody></table></div>
    <div class="panel"><h3>Reset a password</h3><form method="post">{csrf_input()}<input type="hidden" name="action" value="reset">
      <div class="formgrid"><div><label>Username</label><input name="username" required></div><div><label>Temporary password</label><input type="password" name="password" minlength="10" required></div></div>
      <button>Reset password</button></form></div>
    """
    return page("Users", body, "Users")


@app.route("/settings", methods=["GET", "POST"])
@roles("admin")
def settings():
    if request.method == "POST":
        check_csrf()
        for key in ("school_name","school_address","school_phone"):
            set_setting(key, request.form.get(key, "").strip())
        log_action("UPDATE_SCHOOL_SETTINGS")
        return redirect("/settings?msg=Settings saved")
    msg = request.args.get("msg")
    alert = f'<div class="alert">{escape(msg)}</div>' if msg else ""
    body = f"""
    <div class="top"><div><h1>School settings</h1><p class="muted">Information shown on receipts and reports.</p></div></div>
    {alert}<div class="panel" style="max-width:760px"><form method="post">{csrf_input()}
      <label>School name</label><input name="school_name" value="{escape(setting("school_name"))}" required>
      <label>Address</label><input name="school_address" value="{escape(setting("school_address"))}">
      <label>Phone</label><input name="school_phone" value="{escape(setting("school_phone"))}">
      <button>Save settings</button>
    </form></div>"""
    return page("Settings", body, "Settings")


# ================================================================
# EXPORTS / BACKUP / LOGS
# ================================================================

def excel_safe_cell(value):
    """Neutralize CSV/Excel formula injection: a cell starting with
    = + - @ (or tab/CR) is interpreted as a formula by Excel/Sheets when the
    workbook is opened. Prefix with a leading apostrophe so it's read as text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def excel_download(filename, sheet, headers, rows):
    wb = Workbook()
    ws = wb.active
    ws.title = sheet
    ws.append(headers)
    for row in rows:
        ws.append([excel_safe_cell(v) for v in row])
    for cell in ws[1]:
        cell.font = cell.font.copy(bold=True)
    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)
    return send_file(stream, as_attachment=True, download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/export/students")
@login_required
def export_students():
    conn = db()
    rows = conn.execute("""
        SELECT adm_no,name,class,parent_phone,pay_code,total_fees,total_paid,balance,active
        FROM students ORDER BY name
    """).fetchall()
    conn.close()
    return excel_download(
        "students.xlsx","Students",
        ["ADM","Name","Class","Parent Phone","Pay Code","Total Fees","Total Paid","Balance","Active"],
        rows
    )


@app.route("/export/payments")
@login_required
def export_payments():
    conn = db()
    rows = conn.execute("""
        SELECT p.id,p.date,p.adm_no,s.name,p.amount,p.method,p.mpesa_code,p.status,p.created_by
        FROM payments p LEFT JOIN students s ON s.adm_no=p.adm_no ORDER BY p.id DESC
    """).fetchall()
    conn.close()
    return excel_download(
        "payments.xlsx","Payments",
        ["ID","Date","ADM","Student","Amount","Method","M-Pesa Code","Status","Created By"],
        rows
    )


@app.route("/export/balances")
@login_required
def export_balances():
    conn = db()
    rows = conn.execute("""
        SELECT adm_no,name,class,total_fees,total_paid,balance FROM students ORDER BY class,name
    """).fetchall()
    conn.close()
    return excel_download(
        "balances.xlsx","Balances",
        ["ADM","Name","Class","Total Fees","Total Paid","Balance"],
        rows
    )


@app.route("/export/arrears")
@login_required
def export_arrears():
    grade = request.args.get("class", "").strip()
    min_balance = request.args.get("min_balance", "").strip()
    try:
        min_balance_val = float(min_balance) if min_balance else 0.01
    except ValueError:
        min_balance_val = 0.01
    conn = db()
    sql = "SELECT adm_no,name,class,parent_phone,total_fees,total_paid,balance FROM students WHERE active=1 AND balance>=?"
    args = [min_balance_val]
    if grade:
        sql += " AND class=?"
        args.append(grade)
    sql += " ORDER BY balance DESC"
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return excel_download(
        "arrears.xlsx", "Arrears",
        ["ADM", "Name", "Class", "Parent Phone", "Total Fees", "Total Paid", "Balance"],
        rows
    )


@app.route("/backup")
@roles("admin")
def backup():
    # SQLite backup API gives a consistent copy while the app is running.
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = BACKUP_DIR / f"schoolpay_{stamp}.db"
    src = db()
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    log_action("DATABASE_BACKUP", new={"file": str(target.name)})
    return send_file(target, as_attachment=True, download_name=target.name,
                     mimetype="application/octet-stream")


@app.route("/logs")
@roles("admin")
def logs():
    conn = db()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()
    trs = "".join(
        f'<tr><td>{x["id"]}</td><td>{escape(x["date"] or "")}</td><td>{escape(x["username"] or "")}</td>'
        f'<td>{escape(x["role"] or "")}</td><td>{escape(x["action"])}</td><td>{escape(x["adm_no"] or "-")}</td></tr>'
        for x in rows
    )
    body = f"""
    <div class="top"><div><h1>Audit logs</h1><p class="muted">Recent security and accounting events.</p></div></div>
    <div class="panel"><table><thead><tr><th>ID</th><th>Date</th><th>User</th><th>Role</th><th>Action</th><th>ADM</th></tr></thead>
    <tbody>{trs}</tbody></table></div>"""
    return page("Logs", body, "Logs")


# ================================================================
# HEALTH
# ================================================================

@app.route("/health")
def health():
    conn = db()
    try:
        conn.execute("SELECT 1").fetchone()
        return jsonify(ok=True, database="ok", time=now())
    finally:
        conn.close()


@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/stk_push") or request.path.startswith("/mpesa"):
        return jsonify(ok=False, error=str(e.description)), 400
    return page("Bad request", f'<div class="alert">{escape(str(e.description))}</div>')


@app.errorhandler(403)
def forbidden(e):
    return page("Access denied", '<div class="alert">You do not have permission to perform this action.</div>')


@app.errorhandler(404)
def not_found(e):
    return page("Not found", '<div class="alert">The requested page or record was not found.</div>')


# ================================================================
# START
# ================================================================

_auto_mpesa_thread = threading.Thread(target=auto_reconcile_pending_mpesa, name="schoolpay-mpesa-poller", daemon=True)
_auto_mpesa_thread.start()



def proxy_daraja_token():
    try:
        cfg = daraja_config()
        import base64, requests, os
        key = cfg.get('ckey') or cfg.get('consumer_key') or os.environ.get('MPESA_CKEY','')
        secret = cfg.get('csecret') or cfg.get('consumer_secret') or os.environ.get('MPESA_CSECRET','')
        env = (cfg.get('env') or 'sandbox').lower()
        if env == 'production':
            url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        else:
            url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
        r = requests.get(url, headers={"Authorization": f"Basic {auth}"}, timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return (f'{{"error":"{e}"}}', 500, {"Content-Type": "application/json"})
@app.route("/proxy/daraja-token")
def proxy_daraja_token():
    try:
        cfg = daraja_config()
        import base64, requests, os
        key = cfg.get('ckey') or cfg.get('consumer_key') or os.environ.get('MPESA_CKEY','')
        secret = cfg.get('csecret') or cfg.get('consumer_secret') or os.environ.get('MPESA_CSECRET','')
        env = (cfg.get('env') or 'sandbox').lower()
        if env == 'production':
            url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        else:
            url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
        r = requests.get(url, headers={"Authorization": f"Basic {auth}"}, timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return (f'{{"error":"{e}"}}', 500, {"Content-Type": "application/json"})
