# login_gui.py
# ------------------------------------------------------
# Secure login screen for the password manager
# ------------------------------------------------------

import sys
import hashlib
import mysql.connector
from mysql.connector import Error
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from dashboard_gui import DashboardWindow  # will create next


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager - Login")
        self.setGeometry(550, 300, 400, 300)
        self.setStyleSheet("background-color: #101820; color: #E0E0E0;")

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Enter Master Password")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master Password")

        # Show/Hide button
        toggle_btn = QPushButton("👁️ Show")
        toggle_btn.setCheckable(True)
        toggle_btn.setStyleSheet("background-color: #333; color: white; border-radius: 5px; padding: 4px;")
        toggle_btn.clicked.connect(self.toggle_password_visibility)

        # Login button
        login_btn = QPushButton("✅ Login")
        login_btn.setStyleSheet("background-color: #28a745; color: white; border-radius: 6px; padding: 6px;")
        login_btn.clicked.connect(self.verify_master_password)

        # Layout arrangement
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.password_input)
        top_layout.addWidget(toggle_btn)

        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(top_layout)
        layout.addSpacing(20)
        layout.addWidget(login_btn)

        self.setLayout(layout)

    def toggle_password_visibility(self, checked):
        """Toggle visibility of the password input field."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def verify_master_password(self):
        """Verify the entered master password against database."""
        mp = self.password_input.text().strip()

        if not mp:
            QMessageBox.warning(self, "Error", "Please enter your master password.")
            return

        try:
            db = mysql.connector.connect(
                host="localhost",
                user="pm",
                password="password",
                database="pm_auth"
            )
            cur = db.cursor()
            cur.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
            row = cur.fetchone()

            if not row:
                QMessageBox.critical(self, "Error", "No master password set up. Run config_gui.py first.")
                return

            stored_hash, device_secret = row
            entered_hash = hashlib.sha256(mp.encode()).hexdigest()

            if entered_hash == stored_hash:
                QMessageBox.information(self, "Access Granted", "Login successful!")
                self.open_dashboard(mp, device_secret)
            else:
                QMessageBox.critical(self, "Access Denied", "Incorrect master password.")

        except Error as e:
            QMessageBox.critical(self, "Database Error", f"Error: {e}")
        finally:
            if 'db' in locals() and db.is_connected():
                cur.close()
                db.close()

    def open_dashboard(self, master_password: str, device_secret: str):
        """Opens dashboard window and hides login."""
        self.hide()
        self.dashboard = DashboardWindow(master_password, device_secret)
        self.dashboard.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
