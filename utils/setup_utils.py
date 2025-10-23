# utils/setup_utils.py
import hashlib
import string
import random
import sys
from mysql.connector import Error
from rich import print as printc
from rich.console import Console

from utils.dbconfig import dbconfig

console = Console()


def generateDeviceSecret(length=10):
    """Generate a random uppercase alphanumeric device secret."""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def setup_master_password(master_password: str) -> bool:
    """
    Creates two databases (pm_auth and pm_data), 
    initializes tables, and stores hashed master password + device secret.
    Returns True if successful, False otherwise.
    """

    # 1️⃣ Connect to MySQL without specifying database
    db_root = dbconfig()
    if db_root is None:
        printc("[red]❌ Failed to connect to MySQL.[/red]")
        return False
    cursor = db_root.cursor()

    try:
        # 2️⃣ Create the two databases
        cursor.execute("CREATE DATABASE IF NOT EXISTS pm_auth")
        cursor.execute("CREATE DATABASE IF NOT EXISTS pm_data")
        printc("[green][+][/green] Databases 'pm_auth' and 'pm_data' created or already exist")
    except Error:
        console.print_exception(show_locals=True)
        return False

    # 3️⃣ Connect to each one
    db_auth = dbconfig(database="pm_auth")
    db_data = dbconfig(database="pm_data")
    if db_auth is None or db_data is None:
        printc("[red]❌ Could not connect to one or both databases.[/red]")
        return False

    cur_auth = db_auth.cursor()
    cur_data = db_data.cursor()

    # 4️⃣ Create tables
    cur_auth.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            masterkey_hash TEXT NOT NULL,
            device_secret TEXT NOT NULL
        )
    """)
    printc("[green][+][/green] Table 'secrets' created in pm_auth")

    cur_data.execute("""
        CREATE TABLE IF NOT EXISTS pm_entries (
            sitename TEXT NOT NULL,
            siteurl TEXT NOT NULL,
            email TEXT,
            username TEXT,
            password TEXT NOT NULL
        )
    """)
    printc("[green][+][/green] Table 'pm_entries' created in pm_data")

    # 5️⃣ Generate and store secrets
    hashed_mp = hashlib.sha256(master_password.encode()).hexdigest()
    device_secret = generateDeviceSecret()

    # Clear any existing entries in secrets
    cur_auth.execute("DELETE FROM secrets")

    insert_query = "INSERT INTO secrets (masterkey_hash, device_secret) VALUES (%s, %s)"
    cur_auth.execute(insert_query, (hashed_mp, device_secret))
    db_auth.commit()

    printc("[bold green]✓ Master password and device secret stored successfully![/bold green]")

    # 6️⃣ Cleanup
    db_root.close()
    db_auth.close()
    db_data.close()
    return True


# Optional CLI test
if __name__ == "__main__":
    import getpass
    mp = getpass.getpass("Enter MASTER PASSWORD: ")
    if mp == getpass.getpass("Confirm MASTER PASSWORD: "):
        setup_master_password(mp)
    else:
        print("Passwords do not match.")
