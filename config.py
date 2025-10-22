import sys
from getpass import getpass
import hashlib
import string
import random
from utils.dbconfig import dbconfig
from rich import print as printc
from rich.console import Console

console = Console()

def generateDeviceSecret(length=10):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))

def config():
    # Step 1: Connect without specifying database
    db = dbconfig()
    if db is None:
        printc("[red]Failed to connect to MySQL[/red]")
        sys.exit(1)
    cursor = db.cursor()

    # Step 2: Create the database
    try:
        cursor.execute("CREATE DATABASE IF NOT EXISTS pm")
        printc("[green][+][/green] Database 'pm' created or already exists")
    except Exception:
        console.print_exception(show_locals=True)
        sys.exit(1)

    # Step 3: Reconnect using the new database
    db = dbconfig(database="pm")
    cursor = db.cursor()

    # Step 4: Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            masterkey_hash TEXT NOT NULL,
            device_secret TEXT NOT NULL
        )
    """)
    printc("[green][+][/green] Table 'secrets' created")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pm_entries (
            sitename TEXT NOT NULL,
            siteurl TEXT NOT NULL,
            email TEXT,
            username TEXT,
            password TEXT NOT NULL
        )
    """)
    printc("[green][+][/green] Table 'pm_entries' created")

    # Step 5: Get and confirm master password
    while True:
        mp = getpass("Choose a MASTER PASSWORD: ")
        if mp == getpass("Re-type: ") and mp != "":
            break
        printc("[yellow][*] Please try again.[/yellow]")

    # Step 6: Hash the master password
    hashed_mp = hashlib.sha256(mp.encode()).hexdigest()
    printc("[green][+][/green] Generated hash of MASTER PASSWORD")

    # Step 7: Generate device secret
    ds = generateDeviceSecret()
    printc("[green][+][/green] Device Secret generated")

    # 🧩 Step 8: Ensure only one secrets row exists
    cursor.execute("DELETE FROM secrets")
    printc("[yellow][*][/yellow] Old secrets cleared (if any)")

    # Step 9: Store the new master hash + device secret
    insert_query = "INSERT INTO secrets (masterkey_hash, device_secret) VALUES (%s, %s)"
    cursor.execute(insert_query, (hashed_mp, ds))
    db.commit()

    printc("[bold green]✓ Configuration complete! (secrets reset successfully)[/bold green]")
    db.close()

if __name__ == "__main__":
    config()
