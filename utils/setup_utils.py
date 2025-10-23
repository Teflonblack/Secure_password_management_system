# utils/setup_utils.py
# ------------------------------------------------------
# Handles all setup tasks:
#  - Creates databases: pm_auth and pm_data
#  - Creates tables (with ID primary keys)
#  - Stores hashed master password + device secret
# ------------------------------------------------------

import hashlib
import string
import random
import mysql.connector
from mysql.connector import Error
from rich.console import Console

console = Console()


def generateDeviceSecret(length=10):
    """Generate a random uppercase alphanumeric device secret."""
    import string, random
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


# ------------------------------------------------------
# DATABASE CREATION
# ------------------------------------------------------

def create_database(cursor, db_name: str):
    """Create a database if it doesn't exist."""
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        console.print(f"[green][+][/green] Database '{db_name}' verified/created.")
    except Error as e:
        console.print(f"[red][-][/red] Failed to create database {db_name}: {e}")


def create_auth_table(cursor):
    """Create table for storing master password and device secret."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            masterkey_hash VARCHAR(128) NOT NULL,
            device_secret VARCHAR(128) NOT NULL
        )
    """)
    console.print("[green][+][/green] 'secrets' table verified/created in pm_auth.")


def create_entries_table(cursor):
    """Create table for password entries (with id primary key)."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pm_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sitename VARCHAR(100) NOT NULL,
            siteurl VARCHAR(200) NOT NULL,
            email VARCHAR(150),
            username VARCHAR(150),
            password TEXT NOT NULL
        )
    """)
    console.print("[green][+][/green] 'pm_entries' table verified/created in pm_data.")


def setup():
    """Initialize both databases and tables."""
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="pm",
            password="password"
        )

        cursor = db.cursor()

        # Create databases
        create_database(cursor, "pm_auth")
        create_database(cursor, "pm_data")

        # Create tables in each database
        cursor.execute("USE pm_auth")
        create_auth_table(cursor)

        cursor.execute("USE pm_data")
        create_entries_table(cursor)

        console.print("[bold green]✓ Database structure ready.[/bold green]")

    except Error as e:
        console.print_exception(show_locals=True)
    finally:
        if db.is_connected():
            cursor.close()
            db.close()


# ------------------------------------------------------
# MASTER PASSWORD STORAGE
# ------------------------------------------------------

def setup_master_password(master_password: str) -> bool:
    """
    Stores hashed master password + generated device secret in pm_auth.secrets.
    Returns True if successful, False otherwise.
    """
    try:
        db_auth = mysql.connector.connect(
            host="localhost",
            user="pm",
            password="password",
            database="pm_auth"
        )

        cur = db_auth.cursor()

        # Hash the master password
        hashed_mp = hashlib.sha256(master_password.encode()).hexdigest()
        device_secret = generateDeviceSecret()

        # Remove old secret (only one master should exist)
        cur.execute("DELETE FROM secrets")

        # Insert new one
        insert_query = "INSERT INTO secrets (masterkey_hash, device_secret) VALUES (%s, %s)"
        cur.execute(insert_query, (hashed_mp, device_secret))
        db_auth.commit()

        console.print("[bold green]✓ Master password stored successfully in pm_auth[/bold green]")
        return True

    except Error as e:
        console.print(f"[red]Error saving master password: {e}[/red]")
        return False

    finally:
        if db_auth.is_connected():
            cur.close()
            db_auth.close()


# ------------------------------------------------------
# CLI TEST
# ------------------------------------------------------
if __name__ == "__main__":
    setup()
    mp = input("Enter MASTER PASSWORD: ").strip()
    setup_master_password(mp)
