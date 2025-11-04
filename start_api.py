# start_api.py
# ------------------------------------------------------
# Launches Secure Password Manager Flask API
# Automatically unlocks vault after verifying master password.
# ------------------------------------------------------

import hashlib
import getpass
import mysql.connector
from mysql.connector import Error
from rich.console import Console
from pm_api import start_api_server
from utils.crypto_utils import computeMasterKey

console = Console()


def fetch_auth_secrets():
    """Fetch master password hash and device secret from pm_auth.secrets."""
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="pm",
            password="password",
            database="pm_auth"
        )
        cur = db.cursor()
        cur.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
        result = cur.fetchone()
        cur.close()
        db.close()
        if not result:
            console.print("[red]❌ No master password found. Run config_gui first.[/red]")
            return None, None
        return result
    except Error as e:
        console.print(f"[red]Database connection error: {e}[/red]")
        return None, None


def main():
    console.print("\n[bold cyan]🔐 Secure Password Manager API Launcher[/bold cyan]\n")

    stored_hash, device_secret = fetch_auth_secrets()
    if not stored_hash:
        console.print("[red]Exiting — setup required.[/red]")
        return

    console.print("[yellow]Enter your master password to unlock the vault:[/yellow]")
    entered_password = getpass.getpass("Master Password: ")

    entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
    if entered_hash != stored_hash:
        console.print("[red]❌ Incorrect master password. API not started.[/red]")
        return

    master_key = computeMasterKey(entered_password, device_secret)
    console.print("[green]✅ Master password verified. Vault unlocked automatically.[/green]")

    start_api_server(master_key, entered_password)


if __name__ == "__main__":
    main()
