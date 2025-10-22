import mysql.connector
from mysql.connector import Error
from rich.console import Console

console = Console()

def dbconfig(database=None):
    try:
        db = mysql.connector.connect(
            host='localhost',
            user='pm',
            password='password',
            database=database  # connect to specific DB if given
        )
        return db
    except Error as e:
        console.print_exception(show_locals=True)
        return None
