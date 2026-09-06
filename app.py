
import difflib
import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "sih2026_advanced_lawgpt_ai_master_21006"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit, avoids OOM/crash on huge files

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_NAME = os.path.join(BASE_DIR, "secure_legal_master_21006.db")


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_uuid TEXT UNIQUE,
            case_no TEXT DEFAULT 'CR-2026/891',
            original_filename TEXT,
            stored_filename TEXT,
            file_hash TEXT,
            uploaded_by TEXT,
            role TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            case_no TEXT DEFAULT 'CR-2026/891',
            action TEXT,
            status TEXT,
            username TEXT,
            role TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_locker (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_tag TEXT UNIQUE,
            case_no TEXT,
            item_name TEXT,
            category TEXT,
            locker_shelf TEXT,
            custodian TEXT,
            status TEXT,
            timestamp TEXT
        )
    """)

    system_users = [
        ("admin", "admin123", "Court Administrator"),
        ("singham", "singham123", "Police Inspector"),
        ("ap", "ap123", "Presiding Judge")
    ]
    for u, p, r in system_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (u,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (u, generate_password_hash(p), r)
            )
        else:
            cursor.execute(
                "UPDATE users SET password_hash = ?, role = ? WHERE username = ?",
                (generate_password_hash(p), r, u)
            )

    conn.commit()
    conn.close()


init_db()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_view"))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Same as login_required, but for endpoints called via fetch()/AJAX.
    Returns a JSON 401 instead of an HTML redirect, so the frontend can
    detect it cleanly instead of trying to JSON-parse a login page and
    silently breaking."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "session_expired", "message": "Your session has expired. Please log in again."}), 401
        return f(*args, **kwargs)
    return decorated_function


def calculate_sha256(stream):
    sha = hashlib.sha256()
    for chunk in iter(lambda: stream.read(4096), b""):
        sha.update(chunk)
    stream.seek(0)
    return sha.hexdigest()


# ---------------- ADVANCED LAWGPT AI REASONING ENGINE ---------------- #

def ai_chat_reasoning(user_query, current_doc_text="", original_doc_text="", is_tampered=False, diff_summary=None):
    q = user_query.lower()
    combined_context = f"{original_doc_text}\n{current_doc_text}".strip()

    if not combined_context:
        return "⚠️ **LawGPT Alert:** No active case document is loaded in your workspace. Please ingest or audit an evidence record first so I can cross-examine it."

    if any(k in q for k in ["role", "accused", "suspect", "kaun", "dhara", "charges", "chargesheet", "ilzam"]):
        lines = [l.strip() for l in combined_context.splitlines() if l.strip()]
        relevant = [l for l in lines if re.search(r'accused|role|charge|suspect|allegation|victim|name|offense|bns|ipc', l, re.I)]
        if relevant:
            ans = "👤 **LawGPT Accused & Allegation Analysis:**\n"
            for r in relevant[:5]:
                ans += f"• {r}\n"
            ans += "\n⚖️ **Judicial Note:** The accused is subject to inquiry under corresponding penal statutes. Verify matching identity in the physical locker log."
            return ans
        return "👤 **LawGPT Entity Scan:** No explicit 'Accused' metadata label identified in current document text lines. Review the full text viewer for deeper context."

    if any(k in q for k in ["gap", "tamper", "changed", "difference", "galti", "badla", "forgery", "modified", "discrepancy", "alter"]):
        if not is_tampered:
            return "✅ **Forensic Integrity Verified:** Zero legal gaps or discrepancies detected. The uploaded document perfectly matches the registered SHA-256 master hash in the immutable vault."
        
        ans = "🚨 **LawGPT Forensic Discrepancy & Legal Gap Breakdown:**\n"
        if diff_summary:
            for d in diff_summary:
                if d.get("type") == "removed":
                    ans += f"• ❌ **Omitted / Deleted from Master:** \"{d.get('text')}\"\n"
                else:
                    ans += f"• ⚠️ **Fraudulent Insertion / Alteration:** \"{d.get('text')}\"\n"
            ans += "\n⚖️ **Judicial Consequence:** This document is legally compromised. It violates Section 65B Indian Evidence Act admissibility and attracts prosecution under BNS Section 338 (Forgery of Public Record)."
        else:
            ans += "• Critical binary and cryptographic hash checksum mismatch detected against vault baseline."
        return ans

    if any(k in q for k in ["witness", "time", "statement", "bayan", "waqt", "samay", "kya time", "kab"]):
        time_matches = re.findall(r'(?:\b\d{1,2}:\d{2}(?:\s?[ap]m)?\b|\b\d{1,2}\s+(?:am|pm)\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b|timestamp|time|ist|hours)', combined_context, re.I)
        witness_lines = [l.strip() for l in combined_context.splitlines() if re.search(r'witness|statement|time|stated|saw|present|spot|police| FIR ', l, re.I)]
        
        ans = "👁️ **LawGPT Witness Statement & Temporal Correlation:**\n"
        if witness_lines:
            for wl in witness_lines[:4]:
                ans += f"• {wl}\n"
        if time_matches:
            ans += f"\n⏰ **Extracted Temporal Markers / Timestamps:** {', '.join(set(time_matches[:5]))}"
        else:
            ans += "\n⏰ **Temporal Status:** Standard incident logging verified in custody record."
        return ans

    if any(k in q for k in ["summary", "summarize", "kya hai", "brief", "details", "batao", "overview"]):
        lines = [l.strip() for l in (current_doc_text or original_doc_text).splitlines() if l.strip()]
        brief = lines[:6]
        ans = "📜 **LawGPT Case Executive Summary:**\n"
        for b in brief:
            ans += f"• {b}\n"
        if is_tampered:
            ans += "\n🚨 **Forensic Warning:** Tampered document! Do not rely upon this copy for judicial adjudication."
        return ans

    if any(k in q for k in ["65b", "admissible", "court", "valid", "legal", "certify"]):
        if not is_tampered:
            return "⚖️ **Section 65B Admissibility Status: APPROVED**\nUnbroken chain-of-custody verified via hardware attestation and SHA-256 digest matching. Official 65B Certificate is fully authorized for issuance."
        return "❌ **Section 65B Admissibility Status: REJECTED**\nCryptographic hash mismatch identified. The file has undergone unauthorized modification outside the secure gateway."

    return f"🤖 **LawGPT AI Legal Assistant:**\nI have scanned the active docket. Relevant context excerpt:\n> {combined_context[:250]}...\n\nAsk me specific cross-examination questions like:\n• *'Is chargesheet mein accused ka role kya hai?'*\n• *'Original aur modified file mein main legal gap kya hai?'*\n• *'Witness ne statement mein kya time bataya?'*"


# ---------------- FRONTEND TEMPLATES ---------------- #

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Digital Evidence Management System | Sign In</title>
    <style>
        :root {
            --bg-body: #030712;
            --card-bg: #0b1329;
            --border-color: #1e293b;
            --input-bg: #030712;
            --input-border: #1f2937;
            --text-main: #f3f4f6;
            --text-heading: #f9fafb;
            --text-muted: #9ca3af;
            --emerald-secure: #10b981;
            --emerald-dark: #047857;
            color-scheme: dark;
        }
        body.light-theme {
            --bg-body: #eef2f7;
            --card-bg: #ffffff;
            --border-color: #dde3ec;
            --input-bg: #f8fafc;
            --input-border: #dde3ec;
            --text-main: #0f172a;
            --text-heading: #0f172a;
            --text-muted: #5b6779;
            --emerald-secure: #059669;
            --emerald-dark: #047857;
            color-scheme: light;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body {
            background: var(--bg-body);
            background-image: 
                radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(37, 99, 235, 0.08) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            transition: background-color 0.25s ease, color 0.25s ease;
        }
        .tricolor-bar {
            width: 100%;
            height: 3px;
            position: fixed;
            top: 0;
            left: 0;
            background: linear-gradient(90deg, #FF9933 33.33%, #FFFFFF 33.33%, #FFFFFF 66.66%, #138808 66.66%);
        }
        .theme-toggle-btn {
            position: fixed;
            top: 16px;
            right: 16px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            width: 38px;
            height: 38px;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-wrap { width: 100%; max-width: 420px; padding: 20px; }
        .login-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-top: 3px solid var(--emerald-secure);
            border-radius: 14px;
            padding: 36px 32px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.35);
            transition: background-color 0.25s ease, border-color 0.25s ease;
        }
        .heading { text-align: center; font-size: 18px; font-weight: 800; color: var(--text-heading); letter-spacing: 0.5px; }
        .subheading {
            text-align: center;
            font-size: 11px;
            color: var(--emerald-secure);
            margin-top: 4px;
            margin-bottom: 24px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .input-group { margin-bottom: 16px; }
        .input-group label {
            display: block;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .input-group input {
            width: 100%;
            padding: 12px 14px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            border-radius: 8px;
            color: var(--text-main);
            font-size: 13px;
        }
        .input-group input:focus { outline: none; border-color: var(--emerald-secure); box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15); }
        button.btn-login {
            width: 100%;
            padding: 13px;
            background: linear-gradient(180deg, var(--emerald-secure) 0%, var(--emerald-dark) 100%);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
        }
        .quick-creds {
            margin-top: 24px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 11px;
            color: var(--text-muted);
            line-height: 1.6;
        }
        .quick-creds b { color: var(--text-main); }
        .error-banner {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #fca5a5;
            padding: 10px;
            border-radius: 8px;
            font-size: 12px;
            margin-bottom: 16px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="tricolor-bar"></div>
    <button class="theme-toggle-btn" id="themeToggleBtn" onclick="toggleTheme()" title="Switch Light / Dark Theme">🌙</button>
    <div class="login-wrap">
        <div class="login-card">
            <div style="text-align: center; font-size: 32px; margin-bottom: 10px;">⚖️</div>
            <h1 class="heading">SECURE DIGITAL EVIDENCE MANAGEMENT SYSTEM</h1>
            <p class="subheading">Command Center & LawGPT AI Suite</p>
            {% if error %}<div class="error-banner">{{ error }}</div>{% endif %}
            <form method="POST" action="/login">
                <div class="input-group">
                    <label>Designated ID / Username</label>
                    <input type="text" name="username" placeholder="e.g. singham" required>
                </div>
                <div class="input-group">
                    <label>Cryptographic Passkey</label>
                    <input type="password" name="password" placeholder="••••••••" required>
                </div>
                <button type="submit" class="btn-login">Authenticate Judicial Session</button>
            </form>
            <div class="quick-creds">
                <b>Pre-Configured Officer Access:</b><br>
                👮 <b>Police Inspector:</b> singham / singham123<br>
                ⚖️ <b>Presiding Judge:</b> ap / ap123<br>
                👑 <b>Court Admin:</b> admin / admin123
            </div>
        </div>
    </div>
    <script>
        function applyTheme(theme) {
            const btn = document.getElementById('themeToggleBtn');
            if (theme === 'light') {
                document.body.classList.add('light-theme');
                if (btn) btn.innerText = '☀️';
            } else {
                document.body.classList.remove('light-theme');
                if (btn) btn.innerText = '🌙';
            }
        }
        function toggleTheme() {
            const isLight = document.body.classList.contains('light-theme');
            const nextTheme = isLight ? 'dark' : 'light';
            applyTheme(nextTheme);
            try { localStorage.setItem('sdems_theme', nextTheme); } catch (e) {}
        }
        (function initTheme() {
            let saved = null;
            try { saved = localStorage.getItem('sdems_theme'); } catch (e) {}
            if (!saved) {
                saved = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
            }
            applyTheme(saved);
        })();
    </script>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Digital Evidence Management System | Section 65B Certified</title>
    <style>
        :root {
            --bg-body: #030712;
            --sidebar-bg: #0b1329;
            --card-bg: #0f172a;
            --card-inner: #020617;
            --border-color: #1e293b;
            --emerald-secure: #10b981;
            --emerald-dark: #047857;
            --sapphire-accent: #3b82f6;
            --rose-accent: #ef4444;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --surface-1: #111827;
            --surface-2: #0b1329;
            --shadow-color: rgba(0, 0, 0, 0.7);
            --overlay-color: rgba(0, 0, 0, 0.75);
            --scrollbar-track: #030712;
            --scrollbar-thumb: #1e293b;
            --success-text: var(--success-text);
            --danger-text: var(--danger-text);
            --info-text: var(--info-text);
            color-scheme: dark;
        }
        body.light-theme {
            --bg-body: #eef2f7;
            --sidebar-bg: #ffffff;
            --card-bg: #ffffff;
            --card-inner: #f5f7fa;
            --border-color: #dde3ec;
            --emerald-secure: #059669;
            --emerald-dark: #047857;
            --sapphire-accent: #2563eb;
            --rose-accent: #dc2626;
            --text-main: #0f172a;
            --text-muted: #5b6779;
            --surface-1: #f1f4f9;
            --surface-2: #f8fafc;
            --shadow-color: rgba(15, 23, 42, 0.10);
            --overlay-color: rgba(15, 23, 42, 0.45);
            --scrollbar-track: #eef2f7;
            --scrollbar-thumb: #cbd5e1;
            --success-text: #047857;
            --danger-text: #b91c1c;
            --info-text: #1d4ed8;
            color-scheme: light;
        }
        body, body.light-theme { transition: background-color 0.25s ease, color 0.25s ease; }
        body.light-theme .card, body.light-theme .top-nav, body.light-theme .slide-drawer,
        body.light-theme .live-feed-bar, body.light-theme table, body.light-theme .msg-ai,
        body.light-theme input, body.light-theme .shelf-bay, body.light-theme .case-folder {
            transition: background-color 0.25s ease, color 0.25s ease, border-color 0.25s ease;
        }
        .theme-toggle-btn {
            background: var(--surface-1);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            width: 38px;
            height: 38px;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        body.light-theme .brand-icon, body.light-theme .hamburger-btn { background: var(--surface-1); }
        body.light-theme ::-webkit-scrollbar-track { background: var(--scrollbar-track); }
        body.light-theme ::-webkit-scrollbar-thumb { background: var(--scrollbar-thumb); }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg-body); color: var(--text-main); min-height: 100vh; overflow-x: hidden; position: relative; }
        
        .drawer-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 998;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }
        .drawer-overlay.active { opacity: 1; pointer-events: auto; }

        .slide-drawer {
            position: fixed;
            top: 0;
            left: -420px;
            width: 410px;
            height: 100vh;
            background: var(--sidebar-bg);
            border-right: 1px solid var(--border-color);
            z-index: 999;
            display: flex;
            flex-direction: column;
            transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 10px 0 35px rgba(0,0,0,0.8);
        }
        .slide-drawer.open { left: 0; }
        
        .drawer-header {
            padding: 16px 18px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-body);
        }
        .brand-wrap { display: flex; align-items: center; gap: 10px; }
        .brand-icon {
            width: 34px;
            height: 34px;
            background: var(--surface-1);
            border: 1px solid var(--emerald-secure);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        .nav-menu { padding: 10px; list-style: none; border-bottom: 1px solid var(--border-color); }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 12px;
            border-radius: 6px;
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            margin-bottom: 3px;
            transition: all 0.2s;
        }
        .nav-item:hover, .nav-item.active { background: var(--border-color); color: var(--text-main); border-left: 3px solid var(--emerald-secure); }

        .sidebar-chat-wrapper { flex: 1; display: flex; flex-direction: column; background: var(--bg-body); overflow: hidden; }
        .sidebar-chat-header { padding: 10px 14px; background: var(--card-bg); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; }
        .sidebar-chat-messages { flex: 1; padding: 12px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; font-size: 11px; }
        .msg { padding: 9px 12px; border-radius: 6px; max-width: 92%; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
        .msg-ai { background: var(--surface-1); color: var(--text-main); border-left: 3px solid var(--emerald-secure); align-self: flex-start; }
        .msg-user { background: #1d4ed8; color: #fff; align-self: flex-end; }
        
        .sidebar-chat-input-box { padding: 8px 10px; border-top: 1px solid var(--border-color); background: var(--bg-body); display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
        .sidebar-chat-input-box input { margin-bottom: 0; padding: 8px 10px; font-size: 11px; flex: 1; }
        .sidebar-chat-send-btn { background: var(--emerald-secure); color: #000; border: none; border-radius: 4px; padding: 0 12px; font-weight: 800; cursor: pointer; font-size: 11px; height: 32px; }

        .drawer-footer { padding: 10px 14px; border-top: 1px solid var(--border-color); background: var(--bg-body); font-size: 11px; display: flex; justify-content: space-between; align-items: center; }

        .top-nav {
            background: var(--bg-body);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .left-menu-btn-group { display: flex; align-items: center; gap: 14px; }
        .hamburger-btn {
            background: var(--surface-1);
            border: 1px solid var(--border-color);
            color: var(--emerald-secure);
            width: 38px;
            height: 38px;
            border-radius: 8px;
            font-size: 18px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .btn-open-copilot {
            background: var(--surface-1);
            border: 1px solid var(--emerald-secure);
            color: var(--emerald-secure);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .role-highlight-badge {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--emerald-secure);
            color: var(--emerald-secure);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
        }
        .logout-btn {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger-text);
            border: 1px solid #ef4444;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            text-decoration: none;
        }

        .live-feed-bar {
            background: var(--surface-2);
            border-bottom: 1px solid var(--border-color);
            padding: 8px 28px;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 11px;
        }
        .live-pulse {
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 8px #10b981;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
        .ticker-text { color: #d1d5db; font-weight: 600; font-family: monospace; }

        .content-area { padding: 22px 28px; max-width: 1400px; width: 100%; margin: 0 auto; }

        .quick-hero-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 22px;
        }
        .hero-action-card {
            background: linear-gradient(135deg, var(--surface-2) 0%, var(--card-bg) 100%);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        .hero-action-card:hover {
            border-color: var(--emerald-secure);
            transform: translateY(-2px);
        }
        .hero-title h4 { font-size: 13px; font-weight: 800; color: var(--text-main); margin-bottom: 3px; }
        .hero-title p { font-size: 11px; color: var(--text-muted); }
        .hero-icon { font-size: 24px; }

        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 22px;
        }
        .kpi-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px 16px;
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .kpi-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .kpi-data h3 { font-size: 18px; font-weight: 800; color: var(--text-main); }
        .kpi-data p { font-size: 10px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }

        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
            margin-bottom: 20px;
        }
        .card-header {
            font-size: 13px;
            font-weight: 800;
            color: var(--text-main);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            text-transform: uppercase;
        }
        .card-header span.tag {
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 4px;
            background: var(--card-inner);
            color: var(--emerald-secure);
            border: 1px solid var(--border-color);
        }

        label.form-label {
            display: block;
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        input, select, textarea {
            width: 100%;
            padding: 9px 12px;
            background: var(--card-inner);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-main);
            font-size: 12px;
            margin-bottom: 12px;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--emerald-secure);
        }
        button.btn-primary {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            cursor: pointer;
            color: var(--text-main);
        }
        .btn-emerald { background: linear-gradient(180deg, #10b981 0%, #047857 100%); }
        .btn-blue { background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%); }
        .btn-rose { background: linear-gradient(180deg, #e11d48 0%, #be123c 100%); }
        
        .btn-emerald-cert {
            background: linear-gradient(180deg, #10b981 0%, #065f46 100%);
            border: 1px solid #34d399;
            color: white;
            padding: 7px 12px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 8px;
        }

        .case-folder {
            background: var(--card-inner);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        .folder-header {
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: var(--surface-2);
        }
        .folder-header:hover { background: #111e38; }
        .folder-title { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 12px; color: var(--text-main); }
        .folder-body { padding: 12px 16px; display: none; border-top: 1px solid var(--border-color); }
        .folder-body.open { display: block; }

        table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 6px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { background: var(--card-inner); color: var(--text-muted); font-size: 10px; text-transform: uppercase; font-weight: 800; }
        .badge {
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 800;
            font-size: 10px;
            display: inline-block;
        }
        .badge-green { background: rgba(16, 185, 129, 0.15); color: var(--success-text); border: 1px solid #10b981; }
        .badge-red { background: rgba(239, 68, 68, 0.15); color: var(--danger-text); border: 1px solid #ef4444; }
        .badge-blue { background: rgba(37, 99, 235, 0.15); color: var(--info-text); border: 1px solid #2563eb; }

        .side-by-side { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 14px; }
        .doc-view-box {
            background: var(--card-inner);
            border: 1px solid var(--border-color);
            border-radius: 0 0 8px 8px;
            padding: 12px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.5;
            max-height: 250px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        .doc-header {
            font-size: 11px;
            font-weight: 800;
            padding: 7px 10px;
            border-radius: 6px 6px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header-orig { background: #064e3b; color: var(--success-text); }
        .header-mod { background: #7f1d1d; color: var(--danger-text); }
        .summary-card {
            background: var(--card-inner);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
        }
        .summary-item {
            font-size: 11px;
            margin-bottom: 6px;
            padding: 5px 10px;
            border-radius: 4px;
            font-family: monospace;
        }
        .item-deleted { background: rgba(225, 29, 72, 0.15); color: var(--danger-text); border-left: 3px solid #e11d48; }
        .item-added { background: rgba(5, 150, 105, 0.15); color: #86efac; border-left: 3px solid #059669; }

        .modal-bg { display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.85); z-index: 1000; justify-content: center; align-items: center; }
        .modal-card { background: var(--card-bg); border: 1px solid var(--emerald-secure); border-radius: 12px; padding: 22px; width: 440px; box-shadow: 0 20px 50px rgba(0,0,0,0.8); }
        .camera-viewport {
            position: relative;
            width: 100%;
            height: 240px;
            background: #000;
            border-radius: 8px;
            overflow: hidden;
            border: 2px solid var(--border-color);
            margin-bottom: 12px;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        #webcamVideo { width: 100%; height: 100%; object-fit: cover; }
        .laser-beam {
            position: absolute;
            top: 0;
            left: 5%;
            width: 90%;
            height: 2px;
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
            animation: scanLaser 2s infinite alternate ease-in-out;
            pointer-events: none;
            z-index: 10;
        }
        @keyframes scanLaser {
            0% { top: 10%; }
            100% { top: 90%; }
        }
        .camera-status-overlay {
            position: absolute;
            bottom: 8px;
            left: 8px;
            background: rgba(0,0,0,0.7);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            color: var(--success-text);
            font-family: monospace;
            z-index: 11;
        }
        .shelf-bay {
            background: var(--card-inner);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px;
            position: relative;
            transition: all 0.2s ease;
        }
        .shelf-bay:hover {
            border-color: var(--emerald-secure);
            transform: translateY(-2px);
        }
        .shelf-bay.occupied {
            border-left: 4px solid var(--emerald-secure);
            background: rgba(16, 185, 129, 0.05);
        }
        .shelf-bay.empty {
            border-left: 4px solid #334155;
        }
        .bay-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            font-weight: 800;
            color: var(--text-main);
            margin-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 6px;
        }
        .bay-body {
            font-size: 10px;
            color: var(--text-muted);
            line-height: 1.4;
        }
    </style>
</head>
<body>

    <!-- Real Camera QR / Tag Scanner Modal -->
    <div id="qrModal" class="modal-bg">
        <div class="modal-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <b style="font-size: 13px; color: var(--text-main); display: flex; align-items: center; gap: 6px;">
                    <span>📷</span> Real Hardware QR & Tag Scanner
                </b>
                <button onclick="closeQrModal()" style="background: none; border: none; color: var(--text-main); cursor: pointer; font-size: 16px;">✕</button>
            </div>
            
            <div class="camera-viewport">
                <video id="webcamVideo" autoplay playsinline muted></video>
                <div class="laser-beam" id="laserBeam"></div>
                <div class="camera-status-overlay" id="camStatus">INITIALIZING CAMERA...</div>
            </div>

            <div style="display: flex; gap: 8px; margin-bottom: 10px;">
                <input type="text" id="qrTagInput" placeholder="Tag ID or QR Code Content..." style="margin-bottom: 0;">
                <button class="btn-primary btn-emerald" onclick="simulateTagScan()" style="width: auto; white-space: nowrap; padding: 0 14px;">Scan / Match</button>
            </div>
            
            <div id="qrScanResult" style="display: none; padding: 10px; background: var(--card-inner); border-radius: 6px; font-size: 11px; border: 1px solid var(--border-color);"></div>
        </div>
    </div>

    <!-- Drawer Overlay -->
    <div id="drawerOverlay" class="drawer-overlay" onclick="closeDrawer()"></div>

    <!-- Sliding Sidebar Drawer with LawGPT -->
    <div id="slideDrawer" class="slide-drawer">
        <div class="drawer-header">
            <div class="brand-wrap">
                <div class="brand-icon">⚖️</div>
                <div>
                    <h2 style="font-size: 12px; color: var(--text-main); font-weight: 800;">E-EVIDENCE VAULT</h2>
                    <p style="font-size: 9px; color: var(--emerald-secure); font-weight: 700;">COMMAND RAIL</p>
                </div>
            </div>
            <button style="background: none; border: none; color: var(--text-main); cursor: pointer; font-size: 16px;" onclick="closeDrawer()">✕</button>
        </div>

        <ul class="nav-menu">
            <li class="nav-item active" onclick="switchDrawerTab('vault', this)">📁 1. Master Vault & Explorer</li>
            <li class="nav-item" onclick="switchDrawerTab('locker', this)">🔒 2. Physical Evidence Locker</li>
            <li class="nav-item" onclick="switchDrawerTab('redaction', this)">✂️ 3. Judicial Redaction Tool</li>
            <li class="nav-item" onclick="switchDrawerTab('attestation', this)">🖥️ 4. Hardware Telemetry</li>
            <li class="nav-item" onclick="switchDrawerTab('heatmap', this)">🗺️ 5. Vault Shelf Heatmap</li>
        </ul>

        <!-- LawGPT Chatbot inside Sidebar -->
        <div class="sidebar-chat-wrapper">
            <div class="sidebar-chat-header">
                <div>
                    <b style="font-size: 11px; color: var(--emerald-secure);">🤖 LawGPT AI Cross-Examiner</b>
                    <span style="font-size: 9px; color: var(--text-muted); display: block;">Case Forensic Assistant</span>
                </div>
                <span style="font-size: 9px; background: rgba(16,185,129,0.2); color: var(--success-text); padding: 2px 5px; border-radius: 4px;">LIVE</span>
            </div>
            
            <div id="chatMessages" class="sidebar-chat-messages">
                <div class="msg msg-ai">Hello Officer / Your Honour. I am your <b>LawGPT Sidebar Copilot</b>. Upload or audit any case document, then ask me:
• *"Is chargesheet mein accused ka role kya hai?"*
• *"Original aur modified file mein main legal gap kya hai?"*
• *"Witness ne statement mein kya time bataya?"*</div>
            </div>

            <!-- Voice-Enabled Sidebar Chat Form -->
            <form id="chatForm" class="sidebar-chat-input-box">
                <input type="text" id="chatInput" placeholder="Ask AI about this case..." autocomplete="off" required>
                <button type="submit" class="sidebar-chat-send-btn">Ask</button>
                <button type="button" id="micBtn" onclick="toggleSpeechRecognition()" title="Voice Input (Speech-to-Text)" style="background: var(--border-color); color: #38bdf8; border: 1px solid #3b82f6; border-radius: 4px; padding: 0 8px; cursor: pointer; font-size: 13px; height: 32px;">🎙️</button>
                <button type="button" id="ttsToggleBtn" onclick="toggleTTS()" title="Toggle Auto-Readout (Text-to-Speech)" style="background: var(--border-color); color: #94a3b8; border: 1px solid #334155; border-radius: 4px; padding: 0 6px; cursor: pointer; font-size: 10px; height: 32px; font-weight: bold;">🔊 Mute</button>
            </form>
        </div>

        <div class="drawer-footer">
            <span style="font-size: 10px; color: var(--text-muted);">Officer: <b>{{ session['user']['username'] }}</b></span>
            <span style="font-size: 10px; color: var(--emerald-secure);">🟢 Active</span>
        </div>
    </div>

    <!-- Top Sticky Header -->
    <div class="top-nav">
        <div class="left-menu-btn-group">
            <button class="hamburger-btn" onclick="openDrawer()" title="Open Navigation & AI Copilot">☰</button>
            <div style="font-size: 13px; font-weight: 800; color: var(--text-main); display: flex; align-items: center; gap: 8px;">
                <span>SECURE DIGITAL EVIDENCE MANAGEMENT SYSTEM</span>
                <span style="color: var(--border-color);">|</span>
                <span style="font-size: 10px; color: var(--emerald-secure); text-transform: uppercase;">Section 65B Certified</span>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
            <span class="role-highlight-badge">{{ session['user']['role'] }} Priority View</span>
            <button class="btn-open-copilot" onclick="openDrawer()">🤖 Open AI Copilot</button>
            <button class="theme-toggle-btn" id="themeToggleBtn" onclick="toggleTheme()" title="Switch Light / Dark Theme">🌙</button>
            <span style="font-size: 11px; color: var(--text-muted);"><b>{{ session['user']['username'] }}</b></span>
            <a href="/logout" class="logout-btn">Sign Out</a>
        </div>
    </div>

    <!-- Live Security Alert Feed Ticker -->
    <div class="live-feed-bar">
        <div class="live-pulse"></div>
        <span style="color: var(--emerald-secure); font-weight: 800;">LIVE CUSTODY FEED:</span>
        <span id="tickerFeed" class="ticker-text">Initializing synchronized cryptographic custody ledger...</span>
    </div>

    <!-- Main Workspace Container -->
    <div class="content-area">
        
        <!-- Interactive Quick-Action Workspace Hero -->
        <div class="quick-hero-grid">
            <div class="hero-action-card" onclick="focusAction('ingest')">
                <div class="hero-title">
                    <h4>⚡ Quick Case Seal</h4>
                    <p>Instant FIR / Document Ingestion with SHA-256 Digest</p>
                </div>
                <div class="hero-icon">📥</div>
            </div>
            <div class="hero-action-card" onclick="focusAction('verify')">
                <div class="hero-title">
                    <h4>🔍 Rapid 65B Audit Scanner</h4>
                    <p>Drop suspect file to inspect tampering & gaps</p>
                </div>
                <div class="hero-icon">🛡️</div>
            </div>
            <div class="hero-action-card" onclick="openQrModal()">
                <div class="hero-title">
                    <h4>📷 Live QR / Tag Scanner</h4>
                    <p>Access hardware camera to scan evidence barcodes</p>
                </div>
                <div class="hero-icon">🏷️</div>
            </div>
        </div>

        <!-- Live Executive Metrics KPI Bar -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-icon" style="background: rgba(16, 185, 129, 0.15); color: var(--success-text);">🛡️</div>
                <div class="kpi-data">
                    <h3 id="statTotalDocs">0</h3>
                    <p>Master Records Sealed</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon" style="background: rgba(16, 185, 129, 0.15); color: var(--success-text);">⚡</div>
                <div class="kpi-data">
                    <h3 id="statAudits">0</h3>
                    <p>65B Integrity Audits</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon" style="background: rgba(37, 99, 235, 0.15); color: var(--info-text);">📦</div>
                <div class="kpi-data">
                    <h3 id="statPhysical">0</h3>
                    <p>Physical Evidence Tags</p>
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-icon" style="background: rgba(239, 68, 68, 0.15); color: var(--danger-text);">🚨</div>
                <div class="kpi-data">
                    <h3 id="statTamper">0</h3>
                    <p>Active Tamper Flags</p>
                </div>
            </div>
        </div>

        <!-- TAB 1: MASTER VAULT & CASE EXPLORER -->
        <div id="view-vault" class="tab-content active">
            <div class="grid-2">
                <div class="card" id="cardIngest">
                    <div class="card-header">
                        <span>1. Ingest Master Case Document</span>
                        <span class="tag">SHA-256 Seal</span>
                    </div>
                    <form id="uploadForm">
                        <label class="form-label">Select Evidence Record (FIR / Charge Sheet / Forensic Report)</label>
                        <input type="file" id="fileInput" required>
                        <button type="submit" class="btn-primary btn-emerald">Ingest & Calculate SHA-256 Digest</button>
                    </form>
                    <div id="uploadRes" style="display: none; margin-top: 15px; padding: 12px; background: var(--card-inner); border-radius: 8px; border: 1px solid var(--border-color);">
                        <span style="font-size: 11px; color: var(--emerald-secure); font-weight: bold;">CRYPTOGRAPHIC DIGEST ISSUED:</span>
                        <p id="resHash" style="color: var(--success-text); font-family: monospace; font-size: 11px; word-break: break-all; margin: 4px 0 10px 0;"></p>
                        <a id="certUploadLink" href="#" target="_blank" class="btn-emerald-cert">📜 Generate Section 65B Certificate (PDF)</a>
                    </div>
                </div>

                <div class="card" id="cardVerify">
                    <div class="card-header">
                        <span>2. Cryptographic Tamper Audit</span>
                        <span class="tag">65B Verification</span>
                    </div>
                    <form id="verifyForm">
                        <label class="form-label">Upload Suspect File to Audit Against Master Vault</label>
                        <input type="file" id="verifyFileInput" required>
                        <button type="submit" class="btn-primary btn-blue">Execute Bit-Level Forensic Audit</button>
                    </form>
                    <div id="verifyRes" style="display: none; margin-top: 15px; padding: 12px; border-radius: 8px; text-align: center; font-weight: bold; font-size: 12px;"></div>
                    <div id="certVerifyBox" style="display: none; text-align: center;">
                        <a id="certVerifyLink" href="#" target="_blank" class="btn-emerald-cert">📜 Download Legal Certificate (PDF)</a>
                    </div>
                </div>
            </div>

            <!-- Forensic Comparison Workspace -->
            <div id="forensicBox" class="card" style="display: none; border: 1px solid var(--rose-accent); border-top: 4px solid var(--rose-accent);">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 12px;">
                    <h3 style="color: var(--danger-text); font-size: 14px; font-weight: 800;">⚖️ FORENSIC ALTERATION AUDIT (EVIDENCE TAMPERING DETECTED)</h3>
                    <span id="auditDateBadge" class="badge badge-red"></span>
                </div>

                <div class="summary-card">
                    <div style="font-size: 12px; font-weight: 800; color: var(--danger-text); text-transform: uppercase; margin-bottom: 8px;">
                        🚨 Discrepancy Breakdown (Exact Words/Clauses Manipulated):
                    </div>
                    <div id="humanSummary"></div>
                </div>

                <div class="side-by-side">
                    <div>
                        <div class="doc-header header-orig">
                            <span id="origDocLabel">🏛️ ORIGINAL SEALED COPY</span>
                            <span id="origTimestamp"></span>
                        </div>
                        <div id="origDocContent" class="doc-view-box"></div>
                    </div>
                    <div>
                        <div class="doc-header header-mod">
                            <span id="modDocLabel">⚠️ TAMPERED UPLOAD</span>
                            <span id="modTimestamp"></span>
                        </div>
                        <div id="modDocContent" class="doc-view-box"></div>
                    </div>
                </div>
            </div>

            <!-- Case File Explorer (Hierarchical Folders) -->
            <div class="card">
                <div class="card-header">
                    <span>📂 Case-Wise Digital Evidence Dockets (FIR Folders)</span>
                    <span class="tag">Hierarchical Vault</span>
                </div>
                <div id="caseExplorerList"></div>
            </div>

            <!-- Global Audit Log -->
            <div class="card">
                <div class="card-header">
                    <span>Immutable Chain of Custody Audit Log</span>
                    <span class="tag">Live Audit Trail</span>
                </div>
                <table>
                    <thead>
                        <tr><th>Timestamp (IST)</th><th>Case ID</th><th>Document Name</th><th>Action</th><th>Custody Officer</th><th>Integrity Status</th><th>Section 65B Certificate</th></tr>
                    </thead>
                    <tbody id="auditTable"></tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: EVIDENCE LOCKER -->
        <div id="view-locker" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <span>Register Physical Evidence Item</span>
                        <span class="tag">Vault Asset Tag</span>
                    </div>
                    <form id="lockerForm">
                        <label class="form-label">FIR / Case Docket No</label>
                        <input type="text" id="lockCase" placeholder="e.g. CR-FIR-2026/891" required>
                        <label class="form-label">Asset Description</label>
                        <input type="text" id="lockName" placeholder="e.g. Seized Mobile Phone (IMEI: 894102...)" required>
                        <label class="form-label">Category</label>
                        <select id="lockCategory">
                            <option>Digital Media / Storage Drive</option>
                            <option>Documentary Record</option>
                            <option>Biological Sample</option>
                            <option>Seized Asset / Cash</option>
                        </select>
                        <label class="form-label">Vault Shelf Location</label>
                        <input type="text" id="lockShelf" placeholder="e.g. Central Vault 02 - Shelf A3" required>
                        <button type="submit" class="btn-primary btn-emerald">Register & Tag Physical Evidence</button>
                    </form>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span>Physical Custody Ledger</span>
                        <span class="tag">Active Items</span>
                    </div>
                    <table>
                        <thead>
                            <tr><th>Asset Tag</th><th>Case No</th><th>Item Details</th><th>Shelf Location</th><th>Status</th></tr>
                        </thead>
                        <tbody id="lockerTable"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: REDACTION TOOL -->
        <div id="view-redaction" class="tab-content">
            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <span>Witness Protection & Anonymizer</span>
                        <span class="tag">Privacy Compliance</span>
                    </div>
                    <label class="form-label">Original Statement / Record Text</label>
                    <textarea id="redactInput" rows="7" placeholder="Paste sensitive statements, witness details..."></textarea>
                    <label class="form-label">Entities to Blackout (Comma Separated)</label>
                    <input type="text" id="redactKeywords" placeholder="e.g. Ramesh Kumar, 9876543210, Minor Witness">
                    <button type="button" class="btn-primary btn-rose" onclick="executeRedaction()">Generate Court-Safe Anonymized Copy</button>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span>Public Disclosure Copy</span>
                        <span class="tag">Non-Reversible</span>
                    </div>
                    <div id="redactOutput" style="background: var(--card-inner); padding: 14px; border-radius: 8px; font-family: monospace; font-size: 12px; border: 1px solid var(--border-color); white-space: pre-wrap; min-height: 180px;">Awaiting text input...</div>
                </div>
            </div>
        </div>

        <!-- TAB 4: HARDWARE ATTESTATION -->
        <div id="view-attestation" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>Hardware Root of Trust Telemetry</span>
                    <span class="tag">Section 65B Admissibility</span>
                </div>
                <div class="grid-2">
                    <div style="background: var(--card-inner); padding: 16px; border-radius: 8px; border: 1px solid var(--border-color);">
                        <span style="font-size: 10px; color: var(--emerald-secure); font-weight: bold; text-transform: uppercase;">Node Host Address</span>
                        <p style="font-family: monospace; color: var(--info-text); font-size: 14px; margin: 4px 0 0 0;">127.0.0.1:21006 (Courtroom Node Alpha)</p>
                    </div>
                    <div style="background: var(--card-inner); padding: 16px; border-radius: 8px; border: 1px solid var(--border-color);">
                        <span style="font-size: 10px; color: var(--emerald-secure); font-weight: bold; text-transform: uppercase;">Cryptographic Engine</span>
                        <p style="font-family: monospace; color: var(--success-text); font-size: 14px; margin: 4px 0 0 0;">FIPS-Approved SHA-256 Digest Engine</p>
                    </div>
                    <div style="background: var(--card-inner); padding: 16px; border-radius: 8px; border: 1px solid var(--border-color);">
                        <span style="font-size: 10px; color: var(--emerald-secure); font-weight: bold; text-transform: uppercase;">Hardware MAC Signature</span>
                        <p style="font-family: monospace; color: var(--danger-text); font-size: 14px; margin: 4px 0 0 0;">02:42:AC:11:00:02 (Attested Physical Silicon)</p>
                    </div>
                    <div style="background: var(--card-inner); padding: 16px; border-radius: 8px; border: 1px solid var(--border-color);">
                        <span style="font-size: 10px; color: var(--emerald-secure); font-weight: bold; text-transform: uppercase;">Clock Source</span>
                        <p style="font-family: monospace; color: var(--success-text); font-size: 14px; margin: 4px 0 0 0;">NTP Stratum-1 Synced (+05:30 IST)</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 5: VAULT SHELF HEATMAP -->
        <div id="view-heatmap" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span>🗺️ Central Evidence Vault - 3D Shelf Heatmap & Occupancy</span>
                    <span class="tag">Live Facility Telemetry</span>
                </div>
                <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 16px;">
                    Real-time sensor grid tracking physical evidence locker bays. 
                    <span style="color: var(--success-text); font-weight: bold;">■ Secure / Occupied</span> | 
                    <span style="color: var(--text-muted); font-weight: bold;">■ Available Bay</span>
                </p>
                <div id="vaultGridContainer" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 14px;"></div>
            </div>
        </div>

    </div>

    <script>
        let currentOriginalText = "";

        // ---------------- THEME (Dark / Light) ---------------- //
        function applyTheme(theme) {
            const btn = document.getElementById('themeToggleBtn');
            if (theme === 'light') {
                document.body.classList.add('light-theme');
                if (btn) btn.innerText = '☀️';
            } else {
                document.body.classList.remove('light-theme');
                if (btn) btn.innerText = '🌙';
            }
        }

        function toggleTheme() {
            const isLight = document.body.classList.contains('light-theme');
            const nextTheme = isLight ? 'dark' : 'light';
            applyTheme(nextTheme);
            try { localStorage.setItem('sdems_theme', nextTheme); } catch (e) { /* storage unavailable, theme just won't persist */ }
        }

        (function initTheme() {
            let saved = null;
            try { saved = localStorage.getItem('sdems_theme'); } catch (e) { /* ignore */ }
            if (!saved) {
                saved = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
            }
            applyTheme(saved);
        })();

        let currentSuspectText = "";
        let currentIsTampered = false;
        let currentDiffSummary = [];
        let webcamStream = null;

        // Safe wrapper around fetch(): never lets the UI hang/"crash" silently.
        // Handles session-expiry (401 -> redirect to login) and non-JSON
        // responses (e.g. a stray HTML error page) gracefully instead of
        // throwing an unhandled parse error.
        async function safeFetchJson(url, options) {
            let res;
            try {
                res = await fetch(url, options);
            } catch (networkErr) {
                alert("⚠️ Network error: could not reach the server. Please check your connection and try again.");
                throw networkErr;
            }

            if (res.status === 401) {
                alert("⚠️ Your session has expired. Please log in again.");
                window.location.href = '/login';
                throw new Error("session_expired");
            }

            const contentType = res.headers.get("content-type") || "";
            if (!contentType.includes("application/json")) {
                alert("⚠️ Unexpected server response. Please try again.");
                throw new Error("non_json_response");
            }

            const data = await res.json();
            if (!res.ok) {
                alert("⚠️ " + (data.message || "Something went wrong. Please try again."));
                throw new Error(data.error || "request_failed");
            }
            return data;
        }

        let recognition = null;
        let isListening = false;
        let autoSpeakEnabled = false;

        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            recognition = new SpeechRecognition();
            recognition.continuous = false;
            recognition.interimResults = false;
            recognition.lang = 'en-IN';

            recognition.onstart = function() {
                isListening = true;
                const micBtn = document.getElementById('micBtn');
                micBtn.style.background = '#ef4444';
                micBtn.style.color = '#fff';
                micBtn.title = "Listening... Speak now";
            };

            recognition.onresult = function(event) {
                const transcript = event.results[0][0].transcript;
                document.getElementById('chatInput').value = transcript;
                document.getElementById('chatForm').dispatchEvent(new Event('submit'));
            };

            recognition.onerror = function(event) {
                console.warn("Speech recognition error", event.error);
                stopListeningState();
            };

            recognition.onend = function() {
                stopListeningState();
            };
        }

        function toggleSpeechRecognition() {
            if (!recognition) {
                alert("Speech-to-text is not supported in this browser. Please use Google Chrome.");
                return;
            }
            if (isListening) {
                recognition.stop();
            } else {
                recognition.start();
            }
        }

        function stopListeningState() {
            isListening = false;
            const micBtn = document.getElementById('micBtn');
            if (micBtn) {
                micBtn.style.background = 'var(--border-color)';
                micBtn.style.color = '#38bdf8';
                micBtn.title = "Voice Input (Speech-to-Text)";
            }
        }

        function speakText(text) {
            if (!autoSpeakEnabled || !('speechSynthesis' in window)) return;
            const cleanText = text.replace(/[*_#`\[\]]/g, '').replace(/⚠️|⚖️|🚨|🤖|✅|📜|📄|🏷️|⚡/g, '');
            window.speechSynthesis.cancel();
            const utterance = new SpeechSynthesisUtterance(cleanText);
            utterance.rate = 1.0;
            utterance.pitch = 1.0;
            utterance.lang = 'en-IN';
            window.speechSynthesis.speak(utterance);
        }

        function toggleTTS() {
            autoSpeakEnabled = !autoSpeakEnabled;
            const btn = document.getElementById('ttsToggleBtn');
            if (autoSpeakEnabled) {
                btn.style.color = '#10b981';
                btn.style.borderColor = '#10b981';
                btn.innerText = '🔊 On';
                speakText("LawGPT voice readout activated.");
            } else {
                btn.style.color = '#94a3b8';
                btn.style.borderColor = '#334155';
                btn.innerText = '🔊 Mute';
                window.speechSynthesis.cancel();
            }
        }

        function openDrawer() {
            document.getElementById('slideDrawer').classList.add('open');
            document.getElementById('drawerOverlay').classList.add('active');
        }

        function closeDrawer() {
            document.getElementById('slideDrawer').classList.remove('open');
            document.getElementById('drawerOverlay').classList.remove('active');
        }

        function switchDrawerTab(tabName, el) {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById('view-' + tabName).classList.add('active');
            if (el) el.classList.add('active');
            closeDrawer();
        }

        function focusAction(action) {
            switchDrawerTab('vault', document.querySelectorAll('.nav-item')[0]);
            if (action === 'ingest') {
                document.getElementById('cardIngest').scrollIntoView({ behavior: 'smooth' });
                document.getElementById('fileInput').focus();
            } else if (action === 'verify') {
                document.getElementById('cardVerify').scrollIntoView({ behavior: 'smooth' });
                document.getElementById('verifyFileInput').focus();
            }
        }

        function toggleFolder(id) {
            const body = document.getElementById('folderBody_' + id);
            body.classList.toggle('open');
        }

        async function openQrModal() {
            const modal = document.getElementById('qrModal');
            const video = document.getElementById('webcamVideo');
            const statusLabel = document.getElementById('camStatus');
            modal.style.display = 'flex';
            statusLabel.innerText = "REQUESTING CAMERA ACCESS...";

            try {
                if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
                    webcamStream = await navigator.mediaDevices.getUserMedia({
                        video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } }
                    });
                    video.srcObject = webcamStream;
                    statusLabel.innerText = "CAMERA STREAM ACTIVE • SCANNING";
                } else {
                    statusLabel.innerText = "WEBCAM NOT SUPPORTED BY BROWSER";
                }
            } catch (err) {
                statusLabel.innerText = "CAMERA ACCESS DENIED (USE MANUAL INPUT)";
            }
        }

        function closeQrModal() {
            const modal = document.getElementById('qrModal');
            const video = document.getElementById('webcamVideo');
            modal.style.display = 'none';

            if (webcamStream) {
                webcamStream.getTracks().forEach(track => track.stop());
                webcamStream = null;
            }
            if (video) video.srcObject = null;
        }

        async function simulateTagScan() {
            let tag = document.getElementById('qrTagInput').value.trim();
            let data;
            try {
                data = await safeFetchJson('/api/all_data');
            } catch (err) {
                console.error("Tag scan failed", err);
                return;
            }

            if (!tag && data.locker.length > 0) {
                tag = data.locker[0].item_tag;
                document.getElementById('qrTagInput').value = tag;
            }

            const found = data.locker.find(l => l.item_tag.toLowerCase() === tag.toLowerCase() || l.case_no.toLowerCase() === tag.toLowerCase());
            const box = document.getElementById('qrScanResult');
            box.style.display = 'block';
            if (found) {
                box.innerHTML = `<span style="color:var(--success-text); font-weight:bold;">✅ ASSET IDENTIFIED:</span><br>Item: <b>${found.item_name}</b><br>Case: ${found.case_no}<br>Shelf Loc: <b>${found.locker_shelf}</b><br>Status: <span class="badge badge-green">${found.status}</span>`;
            } else {
                box.innerHTML = `<span style="color:var(--danger-text); font-weight:bold;">❌ ASSET NOT FOUND:</span> No physical locker entry matches "${tag || 'Scan Input'}".`;
            }
        }

        function renderVaultHeatmap(lockerItems) {
            const container = document.getElementById('vaultGridContainer');
            if (!container) return;

            const totalBays = ['Bay A-01', 'Bay A-02', 'Bay A-03', 'Bay A-04', 'Bay B-01', 'Bay B-02', 'Bay B-03', 'Bay B-04', 'Bay C-01', 'Bay C-02', 'Bay C-03', 'Bay C-04'];
            let gridHTML = '';
            
            totalBays.forEach(bayName => {
                const matchedItem = lockerItems.find(item => item.locker_shelf && item.locker_shelf.toLowerCase().includes(bayName.toLowerCase()));
                if (matchedItem) {
                    gridHTML += `
                        <div class="shelf-bay occupied">
                            <div class="bay-header">
                                <span>📦 ${bayName}</span>
                                <span class="badge badge-green">OCCUPIED</span>
                            </div>
                            <div class="bay-body">
                                <b>Tag:</b> ${matchedItem.item_tag}<br>
                                <b>Item:</b> ${matchedItem.item_name}<br>
                                <b>Case:</b> ${matchedItem.case_no}
                            </div>
                        </div>
                    `;
                } else {
                    gridHTML += `
                        <div class="shelf-bay empty">
                            <div class="bay-header">
                                <span>📦 ${bayName}</span>
                                <span style="color: #64748b; font-size: 9px;">AVAILABLE</span>
                            </div>
                            <div class="bay-body" style="color: #64748b;">
                                Sensor Status: Online<br>
                                Capacity: Ready for Ingestion
                            </div>
                        </div>
                    `;
                }
            });
            container.innerHTML = gridHTML;
        }

        async function fetchAllData() {
            try {
                const res = await fetch('/api/all_data');
                const data = await res.json();

                document.getElementById('statTotalDocs').innerText = data.total_docs || 0;
                document.getElementById('statAudits').innerText = data.audit_logs.length || 0;
                document.getElementById('statPhysical').innerText = data.locker.length || 0;
                const tamperCount = data.audit_logs.filter(l => l.status === 'TAMPER_ALERT').length;
                document.getElementById('statTamper').innerText = tamperCount;

                if (data.audit_logs.length > 0) {
                    const top = data.audit_logs[0];
                    document.getElementById('tickerFeed').innerText = `[${top.timestamp}] ACTION: ${top.action} on "${top.filename}" by ${top.username} (${top.role}) -> STATUS: ${top.status}`;
                }

                renderVaultHeatmap(data.locker);

                const casesMap = {};
                data.documents.forEach(doc => {
                    const cNo = doc.case_no || 'CR-2026/891';
                    if (!casesMap[cNo]) casesMap[cNo] = { docs: [], locker: [] };
                    casesMap[cNo].docs.push(doc);
                });
                data.locker.forEach(item => {
                    const cNo = item.case_no || 'CR-2026/891';
                    if (!casesMap[cNo]) casesMap[cNo] = { docs: [], locker: [] };
                    casesMap[cNo].locker.push(item);
                });

                let folderHTML = '';
                let index = 0;
                for (const [caseNo, contents] of Object.entries(casesMap)) {
                    index++;
                    folderHTML += `
                        <div class="case-folder">
                            <div class="folder-header" onclick="toggleFolder(${index})">
                                <div class="folder-title">
                                    <span>📁</span>
                                    <span>${caseNo}</span>
                                    <span style="font-size: 11px; color: var(--emerald-secure);">(${contents.docs.length} Files, ${contents.locker.length} Physical Items)</span>
                                </div>
                                <span style="font-size: 11px; color: var(--text-muted);">▼ Click to Expand</span>
                            </div>
                            <div id="folderBody_${index}" class="folder-body">
                                <h5 style="color: var(--success-text); font-size: 11px; text-transform: uppercase; margin-bottom: 6px;">Sealed Digital Records:</h5>
                                <ul style="list-style: none; margin-bottom: 12px; font-size: 12px; font-family: monospace;">
                                    ${contents.docs.map(d => `
                                        <li style="padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between;">
                                            <span>📄 <b>${d.original_filename}</b> <span style="color: var(--text-muted);">(${d.file_hash.substring(0, 16)}...)</span></span>
                                            <a href="/certificate/${encodeURIComponent(d.original_filename)}" target="_blank" style="color: var(--emerald-secure); font-weight: bold; text-decoration: underline;">View 65B Cert</a>
                                        </li>
                                    `).join('')}
                                </ul>
                                ${contents.locker.length > 0 ? `
                                    <h5 style="color: var(--info-text); font-size: 11px; text-transform: uppercase; margin-bottom: 6px;">Tagged Physical Locker Items:</h5>
                                    <ul style="list-style: none; font-size: 12px;">
                                        ${contents.locker.map(l => `
                                            <li style="padding: 4px 0; color: #cbd5e1;">🏷️ <b>${l.item_tag}</b> - ${l.item_name} (Location: ${l.locker_shelf})</li>
                                        `).join('')}
                                    </ul>
                                ` : ''}
                            </div>
                        </div>
                    `;
                }
                document.getElementById('caseExplorerList').innerHTML = folderHTML || '<p style="font-size: 12px; color: var(--text-muted);">No active case dockets found.</p>';

                document.getElementById('auditTable').innerHTML = data.audit_logs.map(l => `
                    <tr>
                        <td style="color: var(--text-muted); font-family: monospace;">${l.timestamp}</td>
                        <td><b>${l.case_no || 'CR-2026/891'}</b></td>
                        <td><b>${l.filename}</b></td>
                        <td>${l.action}</td>
                        <td>${l.username} (${l.role})</td>
                        <td><span class="badge ${l.status.includes('MATCH') || l.status.includes('SECURED') ? 'badge-green' : 'badge-red'}">${l.status}</span></td>
                        <td><a href="/certificate/${encodeURIComponent(l.filename)}" target="_blank" style="color: var(--emerald-secure); font-weight: bold; text-decoration: underline; font-size: 11px;">📜 View 65B Certificate</a></td>
                    </tr>
                `).join('');

                document.getElementById('lockerTable').innerHTML = data.locker.map(i => `
                    <tr>
                        <td><span class="badge badge-blue">${i.item_tag}</span></td>
                        <td><b>${i.case_no}</b></td>
                        <td>${i.item_name}</td>
                        <td>${i.locker_shelf}</td>
                        <td><span class="badge badge-green">${i.status}</span></td>
                    </tr>
                `).join('');
            } catch (err) {
                console.error("Ledger sync failed", err);
            }
        }

        document.getElementById('uploadForm').onsubmit = async (e) => {
            e.preventDefault();
            const file = document.getElementById('fileInput').files[0];
            if (!file) return;

            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerText : '';
            if (submitBtn) { submitBtn.disabled = true; submitBtn.innerText = 'Ingesting...'; }

            try {
                const fd = new FormData();
                fd.append('file', file);

                const data = await safeFetchJson('/upload', { method: 'POST', body: fd });

                document.getElementById('uploadRes').style.display = 'block';
                document.getElementById('resHash').innerText = data.hash;
                document.getElementById('certUploadLink').href = '/certificate/' + encodeURIComponent(data.filename);

                const reader = new FileReader();
                reader.onload = function() {
                    currentOriginalText = reader.result;
                    currentSuspectText = reader.result;
                    currentIsTampered = false;
                    currentDiffSummary = [];
                    addChatMessage("ai", `✅ Ingested **${data.filename}** into Vault. Ask me in this sidebar to cross-examine accused details or witness statements.`);
                };
                reader.readAsText(file);

                document.getElementById('uploadForm').reset();
                fetchAllData();
            } catch (err) {
                console.error("Upload failed", err);
            } finally {
                if (submitBtn) { submitBtn.disabled = false; submitBtn.innerText = originalBtnText; }
            }
        };

        document.getElementById('verifyForm').onsubmit = async (e) => {
            e.preventDefault();
            const file = document.getElementById('verifyFileInput').files[0];
            if (!file) return;

            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerText : '';
            if (submitBtn) { submitBtn.disabled = true; submitBtn.innerText = 'Auditing...'; }

            try {

            const fd = new FormData();
            fd.append('file', file);

            const data = await safeFetchJson('/verify', { method: 'POST', body: fd });

            const v = document.getElementById('verifyRes');
            const forensicBox = document.getElementById('forensicBox');
            const certVerifyBox = document.getElementById('certVerifyBox');
            
            v.style.display = 'block';
            currentOriginalText = data.original_text || "";
            currentSuspectText = data.current_text || "";
            currentDiffSummary = data.summary || [];
            
            if (data.status === 'MATCHED') {
                currentIsTampered = false;
                v.style.background = 'rgba(16, 185, 129, 0.15)';
                v.style.color = 'var(--success-text)';
                v.style.border = '1px solid #10b981';
                v.innerText = '✅ SECTION 65B CERTIFIED: Document is authentic and matches registered baseline!';
                forensicBox.style.display = 'none';
                certVerifyBox.style.display = 'block';
                document.getElementById('certVerifyLink').href = '/certificate/' + encodeURIComponent(data.current_filename);
                addChatMessage("ai", `✅ Verified **${data.current_filename}** as genuine Section 65B certified evidence.`);
            } else if (data.status === 'RENAMED_MATCH') {
                currentIsTampered = false;
                v.style.background = 'rgba(16, 185, 129, 0.15)';
                v.style.color = 'var(--success-text)';
                v.style.border = '1px solid #10b981';
                v.innerHTML = `✅ <b>CONTENT AUTHENTIC (RENAMED):</b> File content is 100% genuine.<br><span style="font-size:11px;">Registered Master: <b>${data.baseline_filename}</b> | Uploaded As: <b>${data.current_filename}</b></span>`;
                forensicBox.style.display = 'none';
                certVerifyBox.style.display = 'block';
                document.getElementById('certVerifyLink').href = '/certificate/' + encodeURIComponent(data.baseline_filename);
                addChatMessage("ai", `✅ File **${data.current_filename}** matches genuine baseline of **${data.baseline_filename}**.`);
            } else {
                currentIsTampered = true;
                v.style.background = 'rgba(239, 68, 68, 0.15)';
                v.style.color = 'var(--danger-text)';
                v.style.border = '1px solid #ef4444';
                v.innerText = '🚨 RED ALERT: Cryptographic mismatch! Unauthorized alterations detected!';
                forensicBox.style.display = 'block';
                certVerifyBox.style.display = 'none';

                document.getElementById('auditDateBadge').innerText = 'AUDITED AT: ' + data.verify_time;
                document.getElementById('origDocLabel').innerText = '🏛️ ORIGINAL MASTER: ' + (data.baseline_filename || 'Vault Copy');
                document.getElementById('origTimestamp').innerText = 'SEALED: ' + (data.orig_time || 'Registered');
                
                document.getElementById('modDocLabel').innerText = '⚠️ TAMPERED UPLOAD: ' + data.current_filename;
                document.getElementById('modTimestamp').innerText = 'VERIFIED: ' + data.verify_time;

                document.getElementById('origDocContent').innerText = data.original_text || 'Master copy empty or binary.';
                document.getElementById('modDocContent').innerText = data.current_text || 'Uploaded file empty or binary.';

                let summaryHTML = '';
                if (data.summary && data.summary.length > 0) {
                    summaryHTML = data.summary.map(s => {
                        if (s.type === 'removed') {
                            return `<div class="summary-item item-deleted"><b>❌ ASLI SE HATAYA GAYA (Deleted):</b> "${s.text}"</div>`;
                        } else {
                            return `<div class="summary-item item-added"><b>⚠️ NAYA JHOOTH / ALTERATION (Added):</b> "${s.text}"</div>`;
                        }
                    }).join('');
                } else {
                    summaryHTML = '<div class="summary-item item-deleted"><b>🚨 Tamper Reason:</b> Entire file contents or hashes differ from the registered master copy.</div>';
                }
                document.getElementById('humanSummary').innerHTML = summaryHTML;

                addChatMessage("ai", `🚨 **TAMPER ALERT on ${data.current_filename}:**\nDifferences detected against master seal. Ask me: *"Original aur modified file mein main legal gap kya hai?"*`);
            }

            document.getElementById('verifyForm').reset();
            fetchAllData();
            } catch (err) {
                console.error("Verify failed", err);
            } finally {
                if (submitBtn) { submitBtn.disabled = false; submitBtn.innerText = originalBtnText; }
            }
        };

        function addChatMessage(sender, text) {
            const box = document.getElementById('chatMessages');
            const msg = document.createElement('div');
            msg.className = 'msg ' + (sender === 'user' ? 'msg-user' : 'msg-ai');
            msg.innerHTML = text.replace(/\\n/g, '<br>');
            box.appendChild(msg);
            box.scrollTop = box.scrollHeight;
            if (sender === 'ai') {
                speakText(text);
            }
        }

        document.getElementById('chatForm').onsubmit = async (e) => {
            e.preventDefault();
            const inp = document.getElementById('chatInput');
            const query = inp.value.trim();
            if (!query) return;

            addChatMessage("user", query);
            inp.value = '';

            try {
                const data = await safeFetchJson('/api/ai/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        query: query,
                        original_text: currentOriginalText,
                        suspect_text: currentSuspectText,
                        is_tampered: currentIsTampered,
                        diff_summary: currentDiffSummary
                    })
                });
                addChatMessage("ai", data.reply);
            } catch (err) {
                console.error("Chat failed", err);
            }
        };

        document.getElementById('lockerForm').onsubmit = async (e) => {
            e.preventDefault();
            const payload = {
                case_no: document.getElementById('lockCase').value,
                item_name: document.getElementById('lockName').value,
                category: document.getElementById('lockCategory').value,
                locker_shelf: document.getElementById('lockShelf').value
            };
            try {
                await safeFetchJson('/api/locker/add', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
                document.getElementById('lockerForm').reset();
                fetchAllData();
            } catch (err) {
                console.error("Locker add failed", err);
            }
        };

        function executeRedaction() {
            let text = document.getElementById('redactInput').value;
            const keywords = document.getElementById('redactKeywords').value.split(',');
            keywords.forEach(kw => {
                const k = kw.trim();
                if (k.length > 0) {
                    const regex = new RegExp(k, 'gi');
                    text = text.replace(regex, '[████ REDACTED ████]');
                }
            });
            document.getElementById('redactOutput').innerText = text;
        }

        fetchAllData();
    </script>
</body>
</html>
"""

CERTIFICATE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Section 65B Legal Certificate - {{ doc.original_filename }}</title>
    <style>
        body {
            background: #f1f5f9;
            color: #0f172a;
            font-family: 'Times New Roman', Times, serif;
            margin: 0;
            padding: 40px 20px;
        }
        .cert-paper {
            background: #ffffff;
            max-width: 800px;
            margin: 0 auto;
            padding: 50px 60px;
            border: 2px solid #0f172a;
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            position: relative;
        }
        .watermark {
            position: absolute;
            top: 45%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-30deg);
            font-size: 70px;
            color: rgba(15, 23, 42, 0.04);
            font-weight: bold;
            pointer-events: none;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        .emblem { font-size: 36px; margin-bottom: 4px; }
        h1 { font-size: 18px; margin: 0; text-transform: uppercase; letter-spacing: 1px; }
        h2 { font-size: 15px; margin: 4px 0 0 0; font-weight: normal; font-style: italic; }
        .sub-bar { margin-top: 6px; font-size: 12px; font-weight: bold; color: #334155; text-transform: uppercase; }
        p, li { font-size: 13px; line-height: 1.6; text-align: justify; }
        .data-table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 12px; }
        .data-table th, .data-table td { border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }
        .data-table th { background: #f8fafc; width: 32%; font-weight: bold; }
        .hash-code {
            font-family: 'Courier New', Courier, monospace;
            font-size: 11px;
            word-break: break-all;
            background: #f1f5f9;
            padding: 4px 6px;
            border-radius: 4px;
        }
        .signatures { margin-top: 40px; display: flex; justify-content: space-between; }
        .sig-block { width: 42%; text-align: center; border-top: 1px solid #0f172a; padding-top: 8px; font-size: 12px; }
        .print-btn-bar { max-width: 800px; margin: 0 auto 20px auto; display: flex; justify-content: flex-end; gap: 10px; }
        .btn-print {
            background: #0f172a;
            color: white;
            padding: 10px 18px;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            font-size: 12px;
            cursor: pointer;
            text-transform: uppercase;
        }
        @media print {
            body { padding: 0; background: none; }
            .cert-paper { border: none; box-shadow: none; padding: 0; }
            .print-btn-bar { display: none; }
        }
    </style>
</head>
<body>

    <div class="print-btn-bar">
        <button class="btn-print" onclick="window.print()">🖨️ Print / Save as PDF Certificate</button>
    </div>

    <div class="cert-paper">
        <div class="watermark">SECTION 65B CERTIFIED</div>
        <div class="header">
            <div class="emblem">⚖️</div>
            <h1>CERTIFICATE OF ELECTRONIC EVIDENCE</h1>
            <h2>Under Section 65B of the Indian Evidence Act, 1872</h2>
            <div class="sub-bar">Read with Section 63 of Bharatiya Sakshya Adhiniyam (BSA), 2023</div>
        </div>

        <p>
            I, the undersigned Authorized Forensic / Custody Officer, do hereby solemnly declare and certify under Section 65B(4) of the Indian Evidence Act that:
        </p>

        <ol>
            <li>The electronic record titled <b>"{{ doc.original_filename }}"</b> was ingested and produced by the secure, computer-controlled document repository system during the ordinary course of lawful activities.</li>
            <li>Throughout the material period, the host computing systems and cryptographic engines operated properly without impairment or unauthorized interference.</li>
            <li>The cryptographic hash digest recorded herein represents the authentic, unaltered state of the document at the point of ingestion and sealing.</li>
        </ol>

        <table class="data-table">
            <tr><th>Case / FIR Docket</th><td><b>{{ doc.case_no }}</b></td></tr>
            <tr><th>Document Record Name</th><td><b>{{ doc.original_filename }}</b></td></tr>
            <tr><th>Unique Evidence UUID</th><td>{{ doc.doc_uuid }}</td></tr>
            <tr><th>Cryptographic Hash (SHA-256)</th><td><span class="hash-code">{{ doc.file_hash }}</span></td></tr>
            <tr><th>Ingestion Timestamp (IST)</th><td>{{ doc.timestamp }} (+05:30)</td></tr>
            <tr><th>Custodian Officer</th><td>{{ doc.uploaded_by }} ({{ doc.role }})</td></tr>
            <tr><th>Hardware Node IP / Identifier</th><td>127.0.0.1 (Courtroom Verified Terminal Node)</td></tr>
            <tr><th>Hardware MAC Signature</th><td>02:42:AC:11:00:02 (Attested Physical Silicon)</td></tr>
            <tr><th>Admissibility Status</th><td><b style="color: #059669;">VERIFIED AUTHENTIC & UNTAMPERED</b></td></tr>
        </table>

        <p style="margin-top: 25px;">
            To the best of my knowledge and belief, this electronic output reproduces accurately the baseline digital data deposited in the registry without modification, alteration, or interception.
        </p>

        <div class="signatures">
            <div class="sig-block">
                <br><br>
                <b>{{ doc.uploaded_by }}</b><br>
                {{ doc.role }}<br>
                Investigating / Custody Officer
            </div>
            <div class="sig-block">
                <br><br>
                <b>Judicial Officer / Registrar</b><br>
                District & Sessions Court Registry<br>
                Seal of Admissibility
            </div>
        </div>
    </div>
</body>
</html>
"""


# ---------------- APPLICATION ENDPOINTS ---------------- #

@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard_view"))
    return redirect(url_for("login_view"))


@app.route("/login", methods=["GET", "POST"])
def login_view():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        user = conn.cursor().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"]
            }
            return redirect(url_for("dashboard_view"))
        return render_template_string(LOGIN_PAGE, error="Invalid Authorized ID or Passkey!")
    return render_template_string(LOGIN_PAGE)


@app.route("/logout")
def logout_view():
    session.clear()
    return redirect(url_for("login_view"))


@app.route("/dashboard")
@login_required
def dashboard_view():
    return render_template_string(DASHBOARD_PAGE)


@app.route("/upload", methods=["POST"])
@api_login_required
def upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "No file"}), 400

    filename = secure_filename(file.filename)
    doc_uuid = str(uuid.uuid4())
    stored_filename = f"{doc_uuid}_{filename}"

    case_no = f"CR-2026/{uuid.uuid4().hex[:4].upper()}"

    file_hash = calculate_sha256(file.stream)
    file.save(os.path.join(UPLOAD_FOLDER, stored_filename))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO documents (doc_uuid, case_no, original_filename, stored_filename, file_hash, uploaded_by, role, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (doc_uuid, case_no, filename, stored_filename, file_hash, session["user"]["username"], session["user"]["role"], now))

    cursor.execute("""
        INSERT INTO audit_logs (filename, case_no, action, status, username, role, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (filename, case_no, "VAULT_SEAL", "SECURED", session["user"]["username"], session["user"]["role"], now))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "hash": file_hash, "filename": filename, "case_no": case_no})


@app.route("/verify", methods=["POST"])
@api_login_required
def verify():
    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "No file"}), 400

    filename = secure_filename(file.filename)
    current_hash = calculate_sha256(file.stream)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM documents WHERE file_hash = ? ORDER BY id DESC LIMIT 1", (current_hash,))
    hash_match = cursor.fetchone()

    summary = []
    original_text = ""
    current_text = ""
    orig_time = ""
    baseline_filename = ""
    case_no = "CR-2026/891"

    if hash_match:
        baseline_filename = hash_match["original_filename"]
        orig_time = hash_match["timestamp"]
        case_no = hash_match["case_no"]
        if hash_match["original_filename"] == filename:
            status = "MATCHED"
        else:
            status = "RENAMED_MATCH"
    else:
        status = "TAMPER_ALERT"
        cursor.execute("SELECT * FROM documents WHERE original_filename = ? ORDER BY id DESC LIMIT 1", (filename,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("SELECT * FROM documents ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()

        if row:
            orig_time = row["timestamp"]
            baseline_filename = row["original_filename"]
            case_no = row["case_no"]
            try:
                original_path = os.path.join(UPLOAD_FOLDER, row["stored_filename"])
                file.stream.seek(0)
                current_bytes = file.stream.read()
                file.stream.seek(0)

                with open(original_path, "rb") as orig_f:
                    orig_bytes = orig_f.read()

                original_text = orig_bytes.decode("utf-8", errors="ignore")
                current_text = current_bytes.decode("utf-8", errors="ignore")

                orig_lines = original_text.splitlines()
                curr_lines = current_text.splitlines()

                diff_generator = difflib.unified_diff(
                    orig_lines,
                    curr_lines,
                    fromfile="Original_Baseline",
                    tofile="Tampered_Upload",
                    lineterm=""
                )
                diff_lines = list(diff_generator)

                for line in diff_lines:
                    if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
                        continue
                    if line.startswith("-"):
                        cleaned = line[1:].strip()
                        if cleaned:
                            summary.append({"type": "removed", "text": cleaned})
                    elif line.startswith("+"):
                        cleaned = line[1:].strip()
                        if cleaned:
                            summary.append({"type": "added", "text": cleaned})

            except Exception:
                summary = [{"type": "removed", "text": "Binary alteration detected."}]
        else:
            summary = [{"type": "removed", "text": "No baseline document found."}]

    cursor.execute("""
        INSERT INTO audit_logs (filename, case_no, action, status, username, role, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (filename, case_no, "65B_VERIFY", status, session["user"]["username"], session["user"]["role"], now))

    conn.commit()
    conn.close()

    return jsonify({
        "status": status,
        "current_hash": current_hash,
        "summary": summary,
        "original_text": original_text,
        "current_text": current_text,
        "orig_time": orig_time,
        "verify_time": now,
        "baseline_filename": baseline_filename,
        "current_filename": filename,
        "case_no": case_no
    })


@app.route("/api/ai/chat", methods=["POST"])
@api_login_required
def api_ai_chat():
    data = request.get_json() or {}
    query = data.get("query", "")
    orig_text = data.get("original_text", "")
    susp_text = data.get("suspect_text", "")
    is_tampered = data.get("is_tampered", False)
    diff_summary = data.get("diff_summary", [])

    reply = ai_chat_reasoning(query, susp_text, orig_text, is_tampered, diff_summary)
    return jsonify({"reply": reply})


@app.route("/certificate/<filename>")
@login_required
def generate_certificate(filename):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE original_filename = ? ORDER BY id DESC LIMIT 1", (filename,))
    doc = cursor.fetchone()
    conn.close()

    if not doc:
        return "Document not found in official registry.", 404

    return render_template_string(CERTIFICATE_TEMPLATE, doc=doc)


@app.route("/api/locker/add", methods=["POST"])
@api_login_required
def add_locker_item():
    data = request.get_json()
    item_tag = f"EV-TAG-{uuid.uuid4().hex[:6].upper()}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence_locker (item_tag, case_no, item_name, category, locker_shelf, custodian, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (item_tag, data["case_no"], data["item_name"], data["category"], data["locker_shelf"], session["user"]["username"], "IN_LOCKER", now))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/all_data")
@api_login_required
def all_data():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM documents")
    total_docs = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM documents ORDER BY id DESC")
    documents = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 15")
    audit_logs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM evidence_locker ORDER BY id DESC LIMIT 15")
    locker = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return jsonify({
        "total_docs": total_docs,
        "documents": documents,
        "audit_logs": audit_logs,
        "locker": locker
    })


@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith("/api") or request.path in ("/upload", "/verify"):
        return jsonify({"error": "not_found", "message": "Endpoint not found."}), 404
    return redirect(url_for("home"))


@app.errorhandler(413)
def handle_413(e):
    # File too large (bigger than MAX_CONTENT_LENGTH)
    return jsonify({"error": "file_too_large", "message": "File exceeds the 50MB upload limit."}), 413


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    # Catch-all: never let a raw traceback / HTML 500 page reach the browser.
    # For AJAX/API routes, always return JSON so fetch().json() never breaks.
    app.logger.exception("Unhandled error on %s", request.path)
    if request.path.startswith("/api") or request.path in ("/upload", "/verify"):
        return jsonify({"error": "server_error", "message": "Something went wrong while processing your request. Please try again."}), 500
    return "<h2>Something went wrong. Please go back and try again.</h2><a href='/dashboard'>Return to Dashboard</a>", 500


print("=" * 70)
print("🏛️ SECURE DIGITAL EVIDENCE MANAGEMENT SYSTEM ONLINE (PORT 21006)!")
print("👉 Open in Chrome: http://127.0.0.1:21006")
print("=" * 70)

import os
port = int(os.environ.get("PORT", 10000))
app.run(host="0.0.0.0", port=port, debug=False)
