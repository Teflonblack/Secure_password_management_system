# native_host.py
# --------------------------------------------------------
# Secure Password Manager Native Host (with PyQt unlock prompt)
# --------------------------------------------------------

import sys
import json
import struct
import hashlib
import mysql.connector
from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox
from utils.crypto_utils import computeMasterKey, decrypt_password

# === Config ===
DB_USER = "pm"
DB_PASS = "password"
DB_HOST = "localhost"

master_password_cache = None  # store unlocked master password for the session


# --------------------------------------------------------
# Database helpers
# --------------------------------------------------------

def get_device_secret_and_hash():
    """Retrieve masterkey_hash and device_secret from pm_auth.secrets"""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database="pm_auth"
        )
        cur = conn.cursor()
        cur.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result if result else (None, None)
    except Exception as e:
        return (None, None)


def get_password_for_domain(domain, master_password):
    """Get and decrypt password for a given domain"""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database="pm_data"
        )
        cur = conn.cursor()
        cur.execute(
            "SELECT password FROM pm_entries WHERE siteurl LIKE %s OR sitename LIKE %s LIMIT 1",
            (f"%{domain}%", f"%{domain}%")
        )
        result = cur.fetchone()
        cur.close()
        conn.close()

        if not result:
            return {"error": f"No password found for {domain}"}

        enc_password = result[0]
        masterkey_hash, device_secret = get_device_secret_and_hash()

        if not device_secret or not masterkey_hash:
            return {"error": "Device secret or master password not found"}

        # Verify master password correctness
        if hashlib.sha256(master_password.encode()).hexdigest() != masterkey_hash:
            return {"error": "Invalid master password"}

        # Derive AES key and decrypt
        key = computeMasterKey(master_password, device_secret)
        decrypted = decrypt_password(key, enc_password)
        return {"password": decrypted}

    except Exception as e:
        return {"error": str(e)}


# --------------------------------------------------------
# Chrome Native Messaging I/O
# --------------------------------------------------------

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    message_length = struct.unpack("=I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)


def send_message(message):
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


# --------------------------------------------------------
# PyQt Master Password Prompt
# --------------------------------------------------------

def prompt_for_master_password():
    """Display a PyQt password input dialog to get master password."""
    app = QApplication(sys.argv)
    pwd, ok = QInputDialog.getText(
        None,
        "Unlock Secure Password Manager",
        "Enter your master password:",
        QInputDialog.InputMode.TextInput
    )
    if not ok or not pwd.strip():
        QMessageBox.warning(None, "Access Denied", "Master password required to unlock the password manager.")
        sys.exit(0)
    return pwd.strip()


# --------------------------------------------------------
# Main Loop
# --------------------------------------------------------

def main():
    global master_password_cache

    while True:
        try:
            msg = read_message()
            action = msg.get("action")

            if action == "get_password":
                domain = msg.get("domain", "")

                if not master_password_cache:
                    master_password_cache = prompt_for_master_password()

                result = get_password_for_domain(domain, master_password_cache)

                # If invalid password entered, reset cache and re-prompt next time
                if "Invalid master password" in result.get("error", ""):
                    master_password_cache = None
                    QMessageBox.critical(None, "Authentication Failed", "Incorrect master password.")
                    continue

                send_message(result)

            elif action == "ping":
                send_message({"status": "alive"})

            else:
                send_message({"error": "Unknown action"})

        except Exception as e:
            send_message({"error": str(e)})


if __name__ == "__main__":
    main()
