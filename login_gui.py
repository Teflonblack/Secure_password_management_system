# login_gui.py
# ------------------------------------------------------
# Secure Login Interface for Secure Password Manager
# ------------------------------------------------------

import sys
import hashlib
import mysql.connector
from mysql.connector import Error
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QIcon

from dashboard_gui import DashboardWindow


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Secure Password Manager - Login")
        self.setGeometry(550, 300, 420, 320)
        self.setStyleSheet("""
            QWidget {
                background-color: #0f141a;
                color: #E0E0E0;
                font-family: 'Segoe UI';
            }
            QLineEdit {
                padding: 8px;
                border-radius: 6px;
                border: 1px solid #3A3A3A;
                background-color: #1b232c;
                color: #E0E0E0;
            }
            QLineEdit:focus {
                border: 1px solid #0078D7;
                background-color: #202A33;
            }
            QPushButton {
                font-weight: 600;
                border: none;
                border-radius: 6px;
                padding: 8px;
            }
            QPushButton:hover {
                opacity: 0.85;
            }
        """)

        self.init_ui()
        self.fade_in_animation()

    # ------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Secure Password Manager")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #00A8E8; margin-bottom: 10px;")

        subtitle = QLabel("Enter your Master Password to continue")
        subtitle.setStyleSheet("color: #AAA; font-size: 12px; margin-bottom: 15px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #141c24;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0px 0px 10px rgba(0,0,0,0.4);
            }
        """)
        frame_layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter Master Password")

        # Toggle visibility
        self.toggle_btn = QPushButton("👁️ Show")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setStyleSheet("background-color: #333; color: white;")
        self.toggle_btn.clicked.connect(self.toggle_password_visibility)

        toggle_layout = QHBoxLayout()
        toggle_layout.addWidget(self.password_input)
        toggle_layout.addWidget(self.toggle_btn)

        login_btn = QPushButton("🔓 Unlock Vault")
        login_btn.setStyleSheet("background-color: #28a745; color: white; font-size: 14px;")
        login_btn.clicked.connect(self.verify_master_password)

        frame_layout.addLayout(toggle_layout)
        frame_layout.addSpacing(15)
        frame_layout.addWidget(login_btn)
        frame.setLayout(frame_layout)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(frame)
        layout.setContentsMargins(40, 30, 40, 30)
        self.setLayout(layout)

    # ------------------------------------------------------
    # Animation
    # ------------------------------------------------------
    def fade_in_animation(self):
        """Smooth fade-in animation for the login window."""
        self.setWindowOpacity(0.0)
        anim = QPropertyAnimation(self, b"windowOpacity")
        anim.setDuration(600)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.start()
        self.animation = anim  # Keep reference to avoid garbage collection

    # ------------------------------------------------------
    # Logic
    # ------------------------------------------------------
    def toggle_password_visibility(self, checked):
        """Toggle password visibility and update button text."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("🙈 Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("👁️ Show")

    def verify_master_password(self):
        """Verify entered master password against stored hash."""
        mp = self.password_input.text().strip()

        if not mp:
            QMessageBox.warning(self, "Error", "⚠️ Please enter your master password.")
            return

        try:
            db = mysql.connector.connect(
                host="localhost",
                user="pm",
                password="password",
                database="pm_auth"
            )
            cur = db.cursor()
            cur.execute("SHOW TABLES LIKE 'secrets'")
            if not cur.fetchone():
                QMessageBox.critical(
                    self,
                    "Setup Required",
                    "The authentication table was not found.\nPlease run the configuration setup first."
                )
                return

            cur.execute("SELECT masterkey_hash, device_secret FROM secrets LIMIT 1")
            row = cur.fetchone()

            if not row:
                QMessageBox.critical(
                    self,
                    "Setup Required",
                    "No master password found.\nPlease run the configuration setup first."
                )
                return

            stored_hash, device_secret = row
            entered_hash = hashlib.sha256(mp.encode()).hexdigest()

            if entered_hash == stored_hash:
                QMessageBox.information(self, "Access Granted", "✅ Login successful!")
                self.open_dashboard(mp, device_secret)
            else:
                QMessageBox.critical(self, "Access Denied", "❌ Incorrect master password.")

        except Error as e:
            QMessageBox.critical(self, "Database Error", f"⚙️ Database connection error:\n{e}")

        finally:
            if 'db' in locals() and db.is_connected():
                cur.close()
                db.close()

    def open_dashboard(self, master_password: str, device_secret: str):
        """Open the dashboard window and hide login."""
        self.hide()
        try:
            self.dashboard = DashboardWindow(master_password, device_secret)
        except TypeError:
            # fallback if dashboard only takes one argument
            self.dashboard = DashboardWindow(master_password)
        self.dashboard.show()

    # ------------------------------------------------------
    # Standalone Run
    # ------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("icon.png"))
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
