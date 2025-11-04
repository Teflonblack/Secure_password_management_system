# browser_host.py
import sys, json, struct, os
import mysql.connector
from utils.crypto_utils import computeMasterKey, decrypt_password

DB_CONFIG = {
    "host": "localhost",
    "user": "pm",
    "password": "password",
    "database": "pm_data"
}
AUTH_DB = "pm_auth"

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    message_length = struct.unpack("=I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_message(message):
    data = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.flush()

def get_master_data():
    conn = mysql.connector.connect(**DB_CONFIG, database=AUTH_DB)
    cur = conn.cursor()
    cur.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise Exception("No master key found. Run setup first.")
    return row[0], row[1]

def find_password(domain):
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(
        "SELECT password FROM pm_entries WHERE siteurl LIKE %s OR sitename LIKE %s LIMIT 1",
        (f"%{domain}%", f"%{domain}%")
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return row[0]

def main():
    while True:
        msg = read_message()
        action = msg.get("action")
        if action == "get_password":
            domain = msg.get("domain")
            if not domain:
                send_message({"status": "error", "message": "Missing domain"})
                continue
            try:
                enc_pw = find_password(domain)
                if not enc_pw:
                    send_message({"status": "error", "message": "No entry found"})
                    continue

                _, device_secret = get_master_data()
                master_pw = os.environ.get("PM_MASTER_PASSWORD")
                if not master_pw:
                    send_message({"status": "error", "message": "Master password not loaded"})
                    continue

                master_key = computeMasterKey(master_pw, device_secret)
                pw = decrypt_password(master_key, enc_pw)
                send_message({"status": "ok", "password": pw})
            except Exception as e:
                send_message({"status": "error", "message": str(e)})

if __name__ == "__main__":
    main()
