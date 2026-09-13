Secure Digital Evidence Management System
Secure Digital Document Management System for law enforcement, courts, and investigative organizations — built for SIH 2026, Problem Statement 26190 (Ministry of Home Affairs — NCRB, Women Safety Division).

Manages the full lifecycle of legal and investigation documents (FIRs, charge sheets, witness statements, forensic reports, court filings) with tamper-evident storage, blockchain-backed audit trails, role-based access control, version history, and Section 65B admissibility support.

Features
Document upload with SHA-256 integrity hashing and encryption at rest
Permissioned local blockchain ledger for tamper-evident audit trail
Role-based access control (document-level ACL, grant/revoke)
Full version history with immutable lineage
Case collaboration between authorized stakeholders
Full-text + OCR-backed search (English + Hindi)
Verifiable Credentials (W3C VC) for evidence integrity certificates
Offline (QR-based) and cross-chain proof verification
Compliance logging (DPDP consent, data residency, audit reports)
Seized-asset locker tracking
Requirements
Python 3.10+
Tesseract OCR installed on the system (required for the OCR search/parse feature; not a pip package)
Ubuntu/Debian: sudo apt install tesseract-ocr tesseract-ocr-hin
Windows: download installer from the Tesseract GitHub releases page
macOS: brew install tesseract
Setup
bash
# 1. Clone and enter the repo
git clone <your-repo-url>
cd <your-repo-folder>

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# edit .env and set FLASK_SECRET_KEY at minimum

# 5. Run
python evidence.py
The app starts on http://127.0.0.1:21006 by default (override with PORT/HOST).

Demo credentials
Pre-seeded accounts exist for demo purposes (see the login page / init_db()). Change or remove these before any real deployment — they are visible in the source and are not meant for production use.

Security notes before deploying
Always set a strong random FLASK_SECRET_KEY via environment variable.
Set SESSION_COOKIE_SECURE=1 when served over HTTPS.
The uploads/ folder and the SQLite database file contain case evidence — never commit them, and back them up securely outside the repo.
The blockchain ledger in this project is a local SHA-256 hash-chain used to make tampering evident; it is not a distributed/consensus blockchain.
License
Add a license of your choice (MIT/Apache-2.0 are common for hackathon submissions) before making the repo public.


