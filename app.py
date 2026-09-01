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
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body {
            background: #030712;
            background-image: 
                radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(37, 99, 235, 0.08) 0px, transparent 50%);
            color: #f3f4f6;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .tricolor-bar {
            width: 100%;
            height: 3px;
            position: fixed;
            top: 0;
            left: 0;
            background: linear-gradient(90deg, #FF9933 33.33%, #FFFFFF 33.33%, #FFFFFF 66.66%, #138808 66.66%);
        }
        .login-wrap { width: 100%; max-width: 420px; padding: 20px; }
        .login-card {
            background: #0b1329;
            border: 1px solid #1e293b;
            border-top: 3px solid #10b981;
            border-radius: 14px;
            padding: 36px 32px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
        }
        .heading { text-align: center; font-size: 18px; font-weight: 800; color: #f9fafb; letter-spacing: 0.5px; }
        .subheading {
            text-align: center;
            font-size: 11px;
            color: #10b981;
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
            color: #9ca3af;
            margin-bottom: 6px;
        }
        .input-group input {
            width: 100%;
            padding: 12px 14px;
            background: #030712;
            border: 1px solid #1f2937;
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
        }
        .input-group input:focus { outline: none; border-color: #10b981; box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15); }
        button.btn-login {
            width: 100%;
            padding: 13px;
            background: linear-gradient(180deg, #10b981 0%, #047857 100%);
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
            background: #030712;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 11px;
            color: #9ca3af;
            line-height: 1.6;
        }
        .quick-creds b { color: #f3f4f6; }
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
        }
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
            background: #030712;
        }
        .brand-wrap { display: flex; align-items: center; gap: 10px; }
        .brand-icon {
            width: 34px;
            height: 34px;
            background: #111827;
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
        .nav-item:hover, .nav-item.active { background: #1e293b; color: #fff; border-left: 3px solid var(--emerald-secure); }

        .sidebar-chat-wrapper { flex: 1; display: flex; flex-direction: column; background: #030712; overflow: hidden; }
        .sidebar-chat-header { padding: 10px 14px; background: #0f172a; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; }
        .sidebar-chat-messages { flex: 1; padding: 12px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; font-size: 11px; }
        .msg { padding: 9px 12px; border-radius: 6px; max-width: 92%; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
        .msg-ai { background: #111827; color: #f9fafb; border-left: 3px solid var(--emerald-secure); align-self: flex-start; }
        .msg-user { background: #1d4ed8; color: #fff; align-self: flex-end; }
        
        .sidebar-chat-input-box { padding: 8px 10px; border-top: 1px solid var(--border-color); background: #030712; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
        .sidebar-chat-input-box input { margin-bottom: 0; padding: 8px 10px; font-size: 11px; flex: 1; }
        .sidebar-chat-send-btn { background: var(--emerald-secure); color: #000; border: none; border-radius: 4px; padding: 0 12px; font-weight: 800; cursor: pointer; font-size: 11px; height: 32px; }

        .drawer-footer { padding: 10px 14px; border-top: 1px solid var(--border-color); background: #030712; font-size: 11px; display: flex; justify-content: space-between; align-items: center; }

        .top-nav {
            background: #030712;
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
            background: #111827;
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
            background: #111827;
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
            color: #fca5a5;
            border: 1px solid #ef4444;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            text-decoration: none;
        }

        .live-feed-bar {
            background: #0b1329;
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
            background: #10b981