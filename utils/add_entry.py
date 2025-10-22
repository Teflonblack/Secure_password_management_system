# utils/add_entry.py
from getpass import getpass
import hashlib
from rich import print as printc
from utils.dbconfig import dbconfig
from utils.crypto_utils import computeMasterKey, encrypt_password

def add_entry_interactive():
    """
    Interactive routine to add a new password entry into the pm_entries table.
    Prompts for master password (verifies), then site details, then stores encrypted password.
    """
    # 1. Connect to DB
    db = dbconfig(database="pm")
    if db is None:
        printc("[red]Failed to connect to MySQL. Make sure your DB is up and credentials are correct.[/red]")
        return
    cursor = db.cursor()

    # 2. Fetch stored master hash + device secret
    cursor.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
    row = cursor.fetchone()
    if not row:
        printc("[red]No configuration found. Run config.py first.[/red]")
        db.close()
        return
    stored_hash, device_secret = row

    # 3. Verify master password
    mp = getpass("Enter MASTER PASSWORD: ")
    if hashlib.sha256(mp.encode()).hexdigest() != stored_hash:
        printc("[red]❌ Incorrect master password. Aborting.[/red]")
        db.close()
        return
    printc("[green]✓ Master password verified[/green]")

    # 4. Derive master key
    mk = computeMasterKey(mp, device_secret)

    # 5. Collect entry info
    sitename = input("Site name: ").strip()
    siteurl = input("Site URL: ").strip()
    email = input("Email (optional): ").strip() or None
    username = input("Username (optional): ").strip() or None
    password = getpass("Password for site: ")

    # 6. Encrypt the site password
    enc = encrypt_password(mk, password)

    # 7. Insert into pm_entries
    insert_query = """
        INSERT INTO pm_entries (sitename, siteurl, email, username, password)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(insert_query, (sitename, siteurl, email, username, enc))
    db.commit()

    printc("[bold green]✅ Entry added successfully![/bold green]")
    db.close()


if __name__ == "__main__":
    add_entry_interactive()
