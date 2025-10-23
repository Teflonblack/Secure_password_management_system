# dashboard_gui.py
# ------------------------------------------------------
# Main dashboard for Secure Password Manager
# ------------------------------------------------------

import sys
import mysql.connector
import threading
import pyperclip
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
    QMessageBox, QFormLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from utils.crypto_utils import computeMasterKey, encrypt_password, decrypt_password


class DashboardWindow(QWidget):
    def __init__(self, master_password: str, device_secret: str):
        super().__init__()
        self.master_password = master_password
        self.device_secret = device_secret
        self.master_key = computeMasterKey(master_password, device_secret)

        self.setWindowTitle("🔐 Secure Password Manager - Dashboard")
        self.setGeometry(450, 200, 900, 500)
        self.setStyleSheet("background-color: #101820; color: #E0E0E0;")

        self.init_ui()
        self.load_entries()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("Password Manager Dashboard")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # --- Search bar + top buttons ---
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by site name...")
        self.search_input.textChanged.connect(self.search_entries)

        refresh_btn = QPushButton("🔁 Refresh")
        refresh_btn.clicked.connect(self.refresh_entries)

        add_btn = QPushButton("➕ Add Entry")
        add_btn.clicked.connect(self.open_add_entry_dialog)

        clear_clipboard_btn = QPushButton("🧹 Clear Clipboard")
        clear_clipboard_btn.clicked.connect(self.clear_clipboard_manual)

        for btn in (refresh_btn, add_btn, clear_clipboard_btn):
            btn.setStyleSheet(
                "background-color: #0275d8; color: white; border-radius: 5px; padding: 6px;"
            )

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(refresh_btn)
        search_layout.addWidget(add_btn)
        search_layout.addWidget(clear_clipboard_btn)
        layout.addLayout(search_layout)

        # --- Table of entries ---
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Site", "URL", "Email", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(self.handle_password_action)
        layout.addWidget(self.table)

        # --- Tooltip hint below table ---
        hint_label = QLabel("💡 Double-click a password cell to copy it to clipboard.")
        hint_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        hint_label.setStyleSheet("color: #AAAAAA; font-size: 12px; margin-top: 4px; margin-left: 8px;")
        layout.addWidget(hint_label)

        # --- Spacer + Logout button at bottom right ---
        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch()
        logout_btn = QPushButton("🚪 Logout")
        logout_btn.clicked.connect(self.close)
        logout_btn.setStyleSheet("background-color: #d9534f; color: white; border-radius: 5px; padding: 6px 12px;")
        bottom_layout.addWidget(logout_btn)
        layout.addLayout(bottom_layout)

        self.setLayout(layout)

    # ------------------------------------------------------
    # Database Operations
    # ------------------------------------------------------
    def db_connect(self):
        return mysql.connector.connect(
            host="localhost",
            user="pm",
            password="password",
            database="pm_data"
        )

    def load_entries(self):
        """Load all entries from the database."""
        try:
            db = self.db_connect()
            cur = db.cursor()
            cur.execute("SELECT * FROM pm_entries")
            rows = cur.fetchall()

            self.table.clearContents()
            self.table.setRowCount(len(rows))

            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(row):
                    display_value = "••••••••" if col_idx == 5 else str(value or "")
                    item = QTableWidgetItem(display_value)
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.table.setItem(row_idx, col_idx, item)

            cur.close()
            db.close()

        except Exception as e:
            QMessageBox.critical(self, "Database Error", str(e))

    def refresh_entries(self):
        """Reload data with a confirmation message."""
        self.load_entries()
        QTimer.singleShot(100, lambda: QMessageBox.information(self, "Refreshed", "✅ Entries reloaded successfully!"))

    def search_entries(self):
        """Filter entries by site name."""
        query = self.search_input.text().strip().lower()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 1)
            self.table.setRowHidden(row, query not in item.text().lower())

    # ------------------------------------------------------
    # Password Reveal / Clipboard Copy
    # ------------------------------------------------------
    def handle_password_action(self, row, col):
        """Decrypt and copy password when double-clicked."""
        if col != 5:
            return

        entry_id = self.table.item(row, 0).text()
        try:
            db = self.db_connect()
            cur = db.cursor()
            cur.execute("SELECT password FROM pm_entries WHERE id = %s", (entry_id,))
            enc_value = cur.fetchone()[0]
            cur.close()
            db.close()

            decrypted = decrypt_password(self.master_key, enc_value)
            pyperclip.copy(decrypted)
            QMessageBox.information(self, "Copied", "Password copied to clipboard. It will be cleared in 20 seconds.")

            # Clear clipboard after 20 seconds
            timer = threading.Timer(20.0, lambda: pyperclip.copy(""))
            timer.start()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not decrypt password: {e}")

    def clear_clipboard_manual(self):
        """Manual clipboard clearing button."""
        pyperclip.copy("")
        QMessageBox.information(self, "Clipboard", "Clipboard cleared successfully.")

    # ------------------------------------------------------
    # Add Entry Dialog
    # ------------------------------------------------------
    def open_add_entry_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Entry")
        dialog.setStyleSheet("background-color: #202830; color: #E0E0E0;")
        dialog_layout = QVBoxLayout()

        form_layout = QFormLayout()
        site_input = QLineEdit()
        url_input = QLineEdit()
        email_input = QLineEdit()
        user_input = QLineEdit()
        pass_input = QLineEdit()
        pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Site Name:", site_input)
        form_layout.addRow("Site URL:", url_input)
        form_layout.addRow("Email:", email_input)
        form_layout.addRow("Username:", user_input)
        form_layout.addRow("Password:", pass_input)

        add_btn = QPushButton("✅ Save Entry")
        add_btn.setStyleSheet("background-color: #28a745; color: white; border-radius: 6px; padding: 6px;")
        add_btn.clicked.connect(lambda: self.save_entry(
            dialog, site_input.text(), url_input.text(), email_input.text(), user_input.text(), pass_input.text()
        ))

        dialog_layout.addLayout(form_layout)
        dialog_layout.addWidget(add_btn)
        dialog.setLayout(dialog_layout)
        dialog.exec()

    def save_entry(self, dialog, site, url, email, username, password):
        """Encrypt and store new entry."""
        if not site or not url or not password:
            QMessageBox.warning(dialog, "Error", "Site, URL, and Password are required fields.")
            return

        try:
            db = self.db_connect()
            cur = db.cursor()

            enc_password = encrypt_password(self.master_key, password)
            cur.execute("""
                INSERT INTO pm_entries (sitename, siteurl, email, username, password)
                VALUES (%s, %s, %s, %s, %s)
            """, (site, url, email, username, enc_password))
            db.commit()
            cur.close()
            db.close()

            QMessageBox.information(dialog, "Success", "Entry saved successfully.")
            dialog.close()
            self.load_entries()

        except Exception as e:
            QMessageBox.critical(dialog, "Error", f"Could not save entry: {e}")


# --- Entry Point for Standalone Testing ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    from utils.crypto_utils import computeMasterKey
    test_master = "TestPassword123!"
    test_secret = "ABCDEF1234"
    window = DashboardWindow(test_master, test_secret)
    window.show()
    sys.exit(app.exec())
