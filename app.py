import hashlib
import os
import sqlite3
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB_NAME = "secure_docs.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            hash TEXT,
            role TEXT,
            timestamp TEXT
        )
    """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            action TEXT,
            status TEXT,
            role TEXT,
            timestamp TEXT
        )
    """
    )
    conn.commit()
    conn.close()


init_db()


def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SIH 2026 - Secure Doc System</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen p-8">
    <div class="max-w-4xl mx-auto space-y-8">
        
        <!-- Header -->
        <div class="border-b border-slate-700 pb-4">
            <h1 class="text-3xl font-bold text-indigo-400">Secure Legal Document Management System</h1>
            <p class="text-slate-400 mt-1">Problem Statement 26190 | Real-Time SHA-256 Tamper Detection Demo</p>
        </div>

        <!-- Dashboard Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            <!-- Upload Box -->
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 space-y-4">
                <h2 class="text-xl font-semibold text-emerald-400">1. Upload Legal Document</h2>
                <form id="uploadForm" class="space-y-4">
                    <div>
                        <label class="block text-sm text-slate-300 mb-1">Select User Role</label>
                        <select id="roleSelect" class="w-full bg-slate-900 border border-slate-600 rounded p-2 text-sm">
                            <option value="Police Inspector">Police Inspector</option>
                            <option value="Legal Officer">Legal Officer</option>
                            <option value="District Judge">District Judge</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm text-slate-300 mb-1">Select Document (FIR/Evidence)</label>
                        <input type="file" id="fileInput" required class="w-full text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-indigo-600 file:text-white hover:file:bg-indigo-500">
                    </div>
                    <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded transition">
                        Lock & Upload Document
                    </button>
                </form>
                <div id="uploadResult" class="text-xs break-all text-emerald-300"></div>
            </div>

            <!-- Verify Box -->
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 space-y-4">
                <h2 class="text-xl font-semibold text-amber-400">2. Real-time Tamper Check</h2>
                <form id="verifyForm" class="space-y-4">
                    <div>
                        <label class="block text-sm text-slate-300 mb-1">Select File to Test Integrity</label>
                        <input type="file" id="verifyFileInput" required class="w-full text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-amber-600 file:text-white hover:file:bg-amber-500">
                    </div>
                    <button type="submit" class="w-full bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 rounded transition">
                        Verify Integrity (Hash Match)
                    </button>
                </form>
                <div id="verifyResult" class="p-3 rounded text-center text-sm font-bold"></div>
            </div>

        </div>

        <!-- Audit Log Section -->
        <div class="bg-slate-800 p-6 rounded-xl border border-slate-700">
            <h2 class="text-xl font-semibold text-cyan-400 mb-4">3. Section 65B Immutable Audit Trail</h2>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm text-slate-300">
                    <thead class="bg-slate-900 text-slate-400 uppercase text-xs">
                        <tr>
                            <th class="p-3">Timestamp</th>
                            <th class="p-3">Filename</th>
                            <th class="p-3">Action</th>
                            <th class="p-3">Role</th>
                            <th class="p-3">Status</th>
                        </tr>
                    </thead>
                    <tbody id="auditTable"></tbody>
                </table>
            </div>
        </div>

    </div>

    <script>
        // Upload Handle
        document.getElementById('uploadForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('file', document.getElementById('fileInput').files[0]);
            formData.append('role', document.getElementById('roleSelect').value);

            const res = await fetch('/upload', { method: 'POST', body: formData });
            const data = await res.json();
            document.getElementById('uploadResult').innerText = "SHA-256 Hash Generated: " + data.hash;
            loadLogs();
        };

        // Verify Handle
        document.getElementById('verifyForm').onsubmit = async (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('file', document.getElementById('verifyFileInput').files[0]);

            const res = await fetch('/verify', { method: 'POST', body: formData });
            const data = await res.json();
            const resDiv = document.getElementById('verifyResult');
            
            if(data.status === 'MATCHED') {
                resDiv.className = 'p-3 rounded text-center text-sm font-bold bg-emerald-900 text-emerald-200 border border-emerald-500';
                resDiv.innerText = '✅ INTEGRITY OK: Document is Authentic (Hash Matched)';
            } else {
                resDiv.className = 'p-3 rounded text-center text-sm font-bold bg-red-900 text-red-200 border border-red-500 animate-pulse';
                resDiv.innerText = '🚨 RED ALERT: TAMPER DETECTED! File Modified!';
            }
            loadLogs();
        };

        // Load Audit Logs
        async function loadLogs() {
            const res = await fetch('/logs');
            const logs = await res.json();
            const tbody = document.getElementById('auditTable');
            tbody.innerHTML = logs.map(l => `
                <tr class="border-b border-slate-700">
                    <td class="p-3">${l[5]}</td>
                    <td class="p-3">${l[1]}</td>
                    <td class="p-3">${l[2]}</td>
                    <td class="p-3">${l[4]}</td>
                    <td class="p-3 font-bold ${l[3].includes('ALERT') ? 'text-red-400' : 'text-emerald-400'}">${l[3]}</td>
                </tr>
            `).join('');
        }
        loadLogs();
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    role = request.form.get("role", "Unknown")
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    file_hash = calculate_sha256(filepath)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (filename, hash, role, timestamp) VALUES (?, ?, ?, ?)",
        (file.filename, file_hash, role, now),
    )
    cursor.execute(
        "INSERT INTO audit_logs (filename, action, status, role, timestamp) VALUES (?, ?, ?, ?, ?)",
        (file.filename, "UPLOAD", "SECURED", role, now),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "hash": file_hash})


@app.route("/verify", methods=["POST"])
def verify():
    file = request.files["file"]
    filename = file.filename
    temp_path = os.path.join(UPLOAD_FOLDER, "temp_" + filename)
    file.save(temp_path)

    current_hash = calculate_sha256(temp_path)
    os.remove(temp_path)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT hash FROM documents WHERE filename = ? ORDER BY id DESC LIMIT 1",
        (filename,),
    )
    row = cursor.fetchone()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if row and row[0] == current_hash:
        status = "MATCHED"
        cursor.execute(
            "INSERT INTO audit_logs (filename, action, status, role, timestamp) VALUES (?, ?, ?, ?, ?)",
            (filename, "VERIFY", "INTEGRITY_OK", "Auditor", now),
        )
    else:
        status = "TAMPERED"
        cursor.execute(
            "INSERT INTO audit_logs (filename, action, status, role, timestamp) VALUES (?, ?, ?, ?, ?)",
            (filename, "VERIFY", "TAMPER_ALERT", "Auditor", now),
        )

    conn.commit()
    conn.close()

    return jsonify({"status": status})


@app.route("/logs", methods=["GET"])
def logs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()
    return jsonify(logs)


if __name__ == "__main__":
    app.run(debug=True, port=5000)