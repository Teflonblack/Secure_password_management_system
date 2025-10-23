from utils.dbconfig import dbconfig

from rich import print as printc
from rich.console import Console
from rich.table import Table

import utils.crypto_utils
import pyperclip

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import base64

PBKDF2_ITERATIONS = 1_000_000  


def computeMasterKey(master_password: str, device_secret: str) -> bytes:
    """Derive a 32-byte key from master password and device secret (salt)."""
    password = master_password.encode()
    salt = device_secret.encode()
    key = PBKDF2(password, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)
    return key



def retrieveEntries(mp, ds, search, decryptPassword = False):
    db = dbconfig()
    cursor = db.cursor()

    query = ""
    if len(search) == 0:
        query = "SELECT * FROM pm.entries"
    else:
        query = "SELECT * FROM pm.entries WHERE "
        for i in search:
            query += f"{i} = '{search(i)}' AND "
        query = query[: -5]   

    cursor.execute(query)
    results = cursor.fetchall()

    if len(results) == 0:
        printc("[yellow][*][/yellow]No results found for the search")
        return
    
    if (decryptPassword and len(results)>1) or (not decryptPassword):
        table = Table(title="Results")
        table.add_column("Site Name")
        table.add_column("URL")
        table.add_column("Email")
        table.add_column("Username")
        table.add_column("Password")

        for i in results:
            table.add_row(i[0], i[1],i[2],i[3],"{hidden}")

        console = Console()
        console.print(table)

        return
    
    if len(results) == 1 and decryptPassword:
        mk = computeMasterKey(mp, ds)
        decrypted = utils.crypto_utils.decrypt_password(key= mk, source=results[0][4],keyType="bytes")

        pyperclip.copy(decrypted.decode())
        printc("[green][*][/green] Password copied to clipboard")
    
    db.close()