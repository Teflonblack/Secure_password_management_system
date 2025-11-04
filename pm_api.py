# pm_api.py
# ------------------------------------------------------
# Flask API for Chrome Extension Integration
# ------------------------------------------------------

from flask import Flask, request, jsonify
import mysql.connector
import hashlib
from utils.crypto_utils import encrypt_password as encrypt_data, decrypt_password as decrypt_data
from utils.crypto_utils import computeMasterKey

app = Flask(__name__)

# -------------------------------------------------------------------
# Database Connection
# -------------------------------------------------------------------
def db_connect(db_name="pm_data"):
    return mysql.connector.connect(
        host="localhost",
        user="pm",
        password="password",
        database=db_name
    )

# -------------------------------------------------------------------
# Load master password & device secret automatically from pm_auth
# -------------------------------------------------------------------
def get_master_credentials():
    """Fetch master password hash and device secret from pm_auth.secrets."""
    db = db_connect("pm_auth")
    cur = db.cursor()
    cur.execute("SELECT masterkey_hash, device_secret FROM secrets ORDER BY id DESC LIMIT 1")
    result = cur.fetchone()
    cur.close()
    db.close()

    if not result:
        raise ValueError("No master credentials found. Run config_gui first.")
    return result


# -------------------------------------------------------------------
# API TOKEN & MASTER KEY INITIALIZATION
# -------------------------------------------------------------------
API_TOKEN = "MySuperStrongRandomToken123!"
MASTER_HASH, DEVICE_SECRET = get_master_credentials()
MASTER_PASSWORD = None  # Cached once unlocked


# -------------------------------------------------------------------
# Helper: derive master key securely
# -------------------------------------------------------------------
def derive_master_key():
    """Derive AES key using stored password."""
    global MASTER_PASSWORD
    if not MASTER_PASSWORD:
        raise RuntimeError("Vault is locked. Unlock it first.")
    return computeMasterKey(MASTER_PASSWORD, DEVICE_SECRET)


# -------------------------------------------------------------------
# Authorization Decorator
# -------------------------------------------------------------------
def require_auth(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if token != f"Bearer {API_TOKEN}":
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


# -------------------------------------------------------------------
# 🔓 Unlock Vault Route (NEW)
# -------------------------------------------------------------------
@app.route("/unlock_vault", methods=["POST"])
def unlock_vault():
    """
    Verifies the master password and unlocks the vault by caching it in memory.
    """
    global MASTER_PASSWORD

    data = request.get_json(force=True)
    entered_pw = data.get("master_password", "").strip()

    if not entered_pw:
        return jsonify({"status": "error", "message": "Master password missing."}), 400

    entered_hash = hashlib.sha256(entered_pw.encode()).hexdigest()

    if entered_hash != MASTER_HASH:
        return jsonify({"status": "error", "message": "Invalid master password."}), 403

    # Cache the master password in memory (not stored in DB)
    MASTER_PASSWORD = entered_pw
    print("🔓 Vault unlocked successfully.")
    return jsonify({"status": "success", "message": "Vault unlocked successfully."})


# -------------------------------------------------------------------
# Get password for a given domain
# -------------------------------------------------------------------
@app.route("/get_password", methods=["POST"])
@require_auth
def get_password():
    if not MASTER_PASSWORD:
        return jsonify({"status": "error", "message": "Vault is locked. Unlock it first."}), 403

    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"status": "error", "message": "Domain missing."}), 400

    try:
        db = db_connect()
        cur = db.cursor()
        cur.execute("SELECT username, password FROM pm_entries WHERE LOWER(sitename) = %s", (domain,))
        result = cur.fetchone()
        cur.close()
        db.close()

        if not result:
            return jsonify({"status": "error", "message": "No password found for this site."}), 404

        username, enc_password = result
        master_key = derive_master_key()
        decrypted_pw = decrypt_data(master_key, enc_password)

        return jsonify({
            "status": "success",
            "domain": domain,
            "username": username,
            "password": decrypted_pw
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -------------------------------------------------------------------
# Save password for a given domain
# -------------------------------------------------------------------
@app.route("/save_password", methods=["POST"])
@require_auth
def save_password():
    if not MASTER_PASSWORD:
        return jsonify({"status": "error", "message": "Vault is locked. Unlock it first."}), 403

    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not domain or not password:
        return jsonify({"status": "error", "message": "Missing required fields."}), 400

    try:
        master_key = derive_master_key()
        encrypted_pw = encrypt_data(master_key, password)

        db = db_connect()
        cur = db.cursor()

        # Upsert: update existing or insert new
        cur.execute("SELECT id FROM pm_entries WHERE LOWER(sitename) = %s", (domain,))
        existing = cur.fetchone()

        if existing:
            cur.execute(
                "UPDATE pm_entries SET username=%s, password=%s WHERE id=%s",
                (username, encrypted_pw, existing[0])
            )
        else:
            cur.execute(
                "INSERT INTO pm_entries (sitename, siteurl, email, username, password) VALUES (%s, %s, %s, %s, %s)",
                (domain, f"https://{domain}", "", username, encrypted_pw)
            )

        db.commit()
        cur.close()
        db.close()

        return jsonify({"status": "success", "message": "Password saved successfully."})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# -------------------------------------------------------------------
# Server Starter
# -------------------------------------------------------------------
def start_api_server(master_key=None, master_password=None):
    global MASTER_PASSWORD
    if master_password:
        MASTER_PASSWORD = master_password
        print("🔓 Vault automatically unlocked using verified master password.")

    print("✅ Master password and device secret loaded from database.")
    print("🚀 API ready at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)


# -------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------
if __name__ == "__main__":
    start_api_server()
