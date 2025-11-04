# dashboard_gui.py
# ------------------------------------------------------
# Main dashboard for Secure Password Manager (Enhanced UI + Delete)
# ------------------------------------------------------

import sys
import mysql.connector
import threading
import pyperclip
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
    QMessageBox, QFormLayout, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QCursor

from utils.crypto_utils import computeMasterKey, encrypt_password, decrypt_password


class DashboardWindow(QWidget):
    def __init__(self, master_password: str, device_secret: str):
        super().__init__()
        self.master_password = master_password
        self.device_secret = device_secret
        self.master_key = computeMasterKey(master_password, device_secret)

        # --- Window Settings ---
        self.setWindowTitle("🔐 Secure Password Manager - Dashboard")
        self.resize(1000, 600)
        self.setMinimumSize(850, 500)

        # --- Apply Dark Theme ---
        self.set_dark_palette()

        self.init_ui()
        self.load_entries()

    # ------------------------------------------------------
    # Styling and Setup
    # ------------------------------------------------------
    def set_dark_palette(self):
        """Set global dark palette for entire app."""
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#101820"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.Base, QColor("#202830"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#181E26"))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#101820"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.Button, QColor("#202830"))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#0078D7"))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
        self.setPalette(palette)
        self.setStyleSheet("""
            QPushButton {
                background-color: #0275d8;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #1e90ff;
                cursor: pointer;
            }
            QPushButton:pressed {
                background-color: #005cbf;
            }
            QLineEdit {
                background-color: #1A2430;
                color: #E0E0E0;
                border: 1px solid #3A4A5C;
                border-radius: 6px;
                padding: 6px 8px;
            }
            QTableWidget {
                background-color: #181E26;
                color: #E0E0E0;
                gridline-color: #333;
                selection-background-color: #1e90ff;
                alternate-background-color: #1A2430;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #202830;
                color: #E0E0E0;
                font-weight: 600;
                border: none;
                border-bottom: 1px solid #2A3A4A;
                padding: 6px;
            }
        """)

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)

        # --- Header ---
        title = QLabel("Secure Password Manager")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("🔒 Manage, Search, and Copy Your Passwords Securely")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #A0A0A0; font-size: 13px; margin-bottom: 10px;")
        layout.addWidget(subtitle)

        # --- Search + Buttons ---
        search_layout = QHBoxLayout()
        search_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search by site name...")
        self.search_input.textChanged.connect(self.search_entries)

        refresh_btn = QPushButton("🔁 Refresh")
        add_btn = QPushButton("➕ Add Entry")
        delete_btn = QPushButton("🗑️ Delete Entry")
        clear_clipboard_btn = QPushButton("🧹 Clear Clipboard")

        refresh_btn.clicked.connect(self.refresh_entries)
        add_btn.clicked.connect(self.open_add_entry_dialog)
        delete_btn.clicked.connect(self.delete_selected_entry)
        clear_clipboard_btn.clicked.connect(self.clear_clipboard_manual)

        for btn in (refresh_btn, add_btn, delete_btn, clear_clipboard_btn):
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(refresh_btn)
        search_layout.addWidget(add_btn)
        search_layout.addWidget(delete_btn)
        search_layout.addWidget(clear_clipboard_btn)
        layout.addLayout(search_layout)

        # --- Password Table ---
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Site", "URL", "Email", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(self.table.SelectionMode.SingleSelection)
        self.table.cellDoubleClicked.connect(self.handle_password_action)
        layout.addWidget(self.table)

        hint_label = QLabel("💡 Double-click a password cell to copy it. Clipboard auto-clears after 20s.")
        hint_label.setStyleSheet("color: #AAAAAA; font-size: 12px; margin-top: 6px;")
        layout.addWidget(hint_label)

        # --- Footer ---
        footer_layout = QHBoxLayout()
        footer_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        logout_btn = QPushButton("🚪 Logout")
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #d9534f;
                border-radius: 8px;
                padding: 8px 14px;
            }
            QPushButton:hover { background-color: #c9302c; }
        """)
        logout_btn.clicked.connect(self.close)

        footer_layout.addWidget(logout_btn)
        layout.addLayout(footer_layout)

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
        """Load all entries from database."""
        try:
            db = self.db_connect()
            cur = db.cursor()
            cur.execute("SELECT * FROM pm_entries ORDER BY id DESC")
            rows = cur.fetchall()
            cur.close()
            db.close()

            self.table.clearContents()
            self.table.setRowCount(len(rows))

            for row_idx, row in enumerate(rows):
                for col_idx, value in enumerate(row):
                    display_value = "••••••••" if col_idx == 5 else str(value or "")
                    item = QTableWidgetItem(display_value)
                    # make cells non-editable
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.table.setItem(row_idx, col_idx, item)

        except Exception as e:
            QMessageBox.critical(self, "Database Error", str(e))

    def refresh_entries(self):
        self.load_entries()
        QTimer.singleShot(200, lambda: QMessageBox.information(self, "Refreshed", "✅ Entries updated successfully!"))

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
        if col != 5:
            return

        entry_id_item = self.table.item(row, 0)
        if entry_id_item is None:
            QMessageBox.warning(self, "Error", "Could not determine entry id.")
            return

        entry_id = entry_id_item.text()
        try:
            db = self.db_connect()
            cur = db.cursor()
            cur.execute("SELECT password FROM pm_entries WHERE id = %s", (entry_id,))
            result = cur.fetchone()
            cur.close()
            db.close()

            if not result:
                QMessageBox.warning(self, "Error", "Entry not found.")
                return

            enc_value = result[0]
            decrypted = decrypt_password(self.master_key, enc_value)
            pyperclip.copy(decrypted)
            QMessageBox.information(self, "Copied", "Password copied to clipboard. It will be cleared in 20 seconds.")

            threading.Timer(20.0, lambda: pyperclip.copy("")).start()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not decrypt password: {e}")

    def clear_clipboard_manual(self):
        pyperclip.copy("")
        QMessageBox.information(self, "Clipboard", "Clipboard cleared successfully.")

    # ------------------------------------------------------
    # Delete Entry
    # ------------------------------------------------------
    def delete_selected_entry(self):
        """Delete the currently selected row's entry after confirmation."""
        selected = self.table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No selection", "Please select an entry to delete (click the row).")
            return

        id_item = self.table.item(selected, 0)
        site_item = self.table.item(selected, 1)
        if id_item is None:
            QMessageBox.warning(self, "Error", "Could not identify selected entry.")
            return

        entry_id = id_item.text()
        site_name = site_item.text() if site_item else ""

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to permanently delete the entry for:\n\n{site_name}\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            db = self.db_connect()
            cur = db.cursor()
            cur.execute("DELETE FROM pm_entries WHERE id = %s", (entry_id,))
            db.commit()
            cur.close()
            db.close()

            QMessageBox.information(self, "Deleted", "Entry deleted successfully.")
            self.load_entries()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not delete entry: {e}")

    # ------------------------------------------------------
    # Add Entry Dialog
    # ------------------------------------------------------
    def open_add_entry_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("➕ Add New Entry")
        dialog.setStyleSheet("background-color: #202830; color: #E0E0E0;")
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        form_layout = QFormLayout()
        site_input, url_input, email_input, user_input, pass_input = (
            QLineEdit(), QLineEdit(), QLineEdit(), QLineEdit(), QLineEdit()
        )
        pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("🌐 Site Name:", site_input)
        form_layout.addRow("🔗 Site URL:", url_input)
        form_layout.addRow("📧 Email:", email_input)
        form_layout.addRow("👤 Username:", user_input)
        form_layout.addRow("🔑 Password:", pass_input)
        layout.addLayout(form_layout)

        save_btn = QPushButton("✅ Save Entry")
        save_btn.setStyleSheet("background-color: #28a745; border-radius: 8px; padding: 8px;")
        save_btn.clicked.connect(lambda: self.save_entry(
            dialog, site_input.text(), url_input.text(), email_input.text(), user_input.text(), pass_input.text()
        ))
        layout.addWidget(save_btn)
        dialog.setLayout(layout)
        dialog.exec()

    def save_entry(self, dialog, site, url, email, username, password):
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

            QMessageBox.information(dialog, "Success", "✅ Entry saved successfully.")
            dialog.close()
            self.load_entries()

        except Exception as e:
            QMessageBox.critical(dialog, "Error", f"Could not save entry: {e}")


# --- Entry Point for Testing ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    test_master = "TestPassword123!"
    test_secret = "ABCDEF1234"
    window = DashboardWindow(test_master, test_secret)
    window.show()
    sys.exit(app.exec())
