# config_gui.py (Final Enhanced Secure Version)
# -------------------------------------------------------
# GUI for setting up the master password and initializing
# the Secure Password Manager databases.
# -------------------------------------------------------

import sys
import string
import random
import threading
import re
import hashlib
import mysql.connector
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar, QCheckBox
)

from utils.setup_utils import setup
from login_gui import LoginWindow


# ---------------- Utility helpers ----------------

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?"
    return "".join(random.choice(chars) for _ in range(length))


def setup_master_password(password):
    """Store the master password and device secret in pm_auth."""
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="pm",
            password="password",
            database="pm_auth"
        )
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                masterkey_hash VARCHAR(255) NOT NULL,
                device_secret VARCHAR(255) NOT NULL
            )
        """)
        cur.execute("DELETE FROM secrets")

        master_hash = hashlib.sha256(password.encode()).hexdigest()
        device_secret = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        cur.execute(
            "INSERT INTO secrets (masterkey_hash, device_secret) VALUES (%s, %s)",
            (master_hash, device_secret)
        )
        db.commit()
        cur.close()
        db.close()
    except Exception as e:
        raise RuntimeError(str(e))


# ---------------- Worker with signals ----------------

class SetupWorker(QObject):
    finished = pyqtSignal(bool, str)

    def __init__(self, password):
        super().__init__()
        self.password = password

    def run(self):
        """Run setup logic in background thread."""
        try:
            setup()  # initialize DBs
            setup_master_password(self.password)
            self.finished.emit(True, "Master password configured successfully!")
        except Exception as e:
            self.finished.emit(False, str(e))


# ---------------- GUI Window ----------------

class ConfigWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager - Setup")
        self.setGeometry(500, 250, 450, 440)
        self.setStyleSheet("background-color: #101820; color: #E0E0E0;")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Setup Master Password")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter master password")
        self.password_input.textChanged.connect(self.on_password_change)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Confirm master password")
        self.confirm_input.textChanged.connect(self.check_password_match)

        toggle_btn = QPushButton("👁️ Show")
        toggle_btn.setCheckable(True)
        toggle_btn.clicked.connect(self.toggle_password_visibility)
        toggle_btn.setStyleSheet("background-color: #333; color: white; border-radius: 5px; padding: 4px 8px;")

        suggest_btn = QPushButton("🔁 Suggest Strong Password")
        suggest_btn.clicked.connect(self.suggest_password)
        suggest_btn.setStyleSheet("background-color: #0275d8; color: white; border-radius: 5px; padding: 6px;")

        confirm_btn = QPushButton("✅ Set Master Password")
        confirm_btn.clicked.connect(self.handle_setup)
        confirm_btn.setStyleSheet("background-color: #28a745; color: white; border-radius: 6px; padding: 8px;")

        self.progress = QProgressBar()
        self.progress.setVisible(False)

        # --- Password strength bar + label ---
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 5)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(10)

        self.strength_label = QLabel("Strength: ")
        self.strength_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.strength_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")

        # --- Requirement checkboxes ---
        self.check_length = QCheckBox("At least 8 characters")
        self.check_upper = QCheckBox("Contains uppercase letter")
        self.check_lower = QCheckBox("Contains lowercase letter")
        self.check_number = QCheckBox("Contains number")
        self.check_symbol = QCheckBox("Contains special symbol")

        for chk in [self.check_length, self.check_upper, self.check_lower, self.check_number, self.check_symbol]:
            chk.setEnabled(False)
            chk.setStyleSheet("color: #AAA;")

        # --- Layout building ---
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.password_input)
        top_layout.addWidget(toggle_btn)

        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(top_layout)
        layout.addWidget(self.confirm_input)

        layout.addWidget(self.strength_bar)
        layout.addWidget(self.strength_label)
        layout.addSpacing(10)

        layout.addWidget(self.check_length)
        layout.addWidget(self.check_upper)
        layout.addWidget(self.check_lower)
        layout.addWidget(self.check_number)
        layout.addWidget(self.check_symbol)

        layout.addSpacing(10)
        layout.addWidget(suggest_btn)
        layout.addSpacing(10)
        layout.addWidget(confirm_btn)
        layout.addSpacing(10)
        layout.addWidget(self.progress)

        self.setLayout(layout)
        self.update_strength_ui("")

    # ----------- Password validation -----------

    def on_password_change(self, text):
        self.update_strength_ui(text)
        self.check_password_match()

    def update_strength_ui(self, password):
        length_ok = len(password) >= 8
        upper_ok = bool(re.search(r"[A-Z]", password))
        lower_ok = bool(re.search(r"[a-z]", password))
        num_ok = bool(re.search(r"[0-9]", password))
        sym_ok = bool(re.search(r"[^A-Za-z0-9]", password))

        # Update checkbox states
        self.check_length.setChecked(length_ok)
        self.check_upper.setChecked(upper_ok)
        self.check_lower.setChecked(lower_ok)
        self.check_number.setChecked(num_ok)
        self.check_symbol.setChecked(sym_ok)

        checks = sum([length_ok, upper_ok, lower_ok, num_ok, sym_ok])
        self.strength_bar.setValue(checks)

        # Strength label
        if checks <= 2:
            text = "Weak"
            color = "#d9534f"
        elif checks == 3:
            text = "Fair"
            color = "#f0ad4e"
        elif checks == 4:
            text = "Strong"
            color = "#5bc0de"
        else:
            text = "Very Strong"
            color = "#5cb85c"

        self.strength_label.setText(f"Strength: <b><span style='color:{color}'>{text}</span></b>")

    def check_password_match(self):
        """Update confirm field border color depending on match."""
        pwd = self.password_input.text()
        confirm = self.confirm_input.text()

        if not confirm:
            self.confirm_input.setStyleSheet("border: 1px solid #444; color: white;")
            return

        if pwd == confirm:
            self.confirm_input.setStyleSheet("border: 2px solid #28a745; color: white;")
        else:
            self.confirm_input.setStyleSheet("border: 2px solid #d9534f; color: white;")

    # ----------- Button Handlers -----------

    def toggle_password_visibility(self, checked):
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)

    def suggest_password(self):
        suggested = generate_strong_password()
        self.password_input.setText(suggested)
        self.confirm_input.setText(suggested)
        QMessageBox.information(self, "Suggested Password", "A strong password has been auto-filled for you!")

    def handle_setup(self):
        password = self.password_input.text().strip()
        confirm = self.confirm_input.text().strip()

        if not password or not confirm:
            QMessageBox.warning(self, "Error", "Please fill in both fields.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        # Validate strong password
        if not all([
            len(password) >= 8,
            re.search(r"[A-Z]", password),
            re.search(r"[a-z]", password),
            re.search(r"[0-9]", password),
            re.search(r"[^A-Za-z0-9]", password),
        ]):
            QMessageBox.warning(self, "Weak Password", "Password does not meet all security requirements.")
            return

        self.progress.setVisible(True)
        self.progress.setValue(20)

        # Launch worker in a thread
        self.worker = SetupWorker(password)
        self.worker_thread = threading.Thread(target=self.worker.run, daemon=True)
        self.worker.finished.connect(self.on_setup_finished)
        self.worker_thread.start()

    def on_setup_finished(self, success, message):
        self.progress.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", message)
            QTimer.singleShot(800, self.open_login_window)
        else:
            QMessageBox.critical(self, "Setup Failed", message)

    def open_login_window(self):
        """Open login window after setup."""
        self.hide()
        self.login = LoginWindow()
        self.login.show()


# ---------------- Entry Point ----------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigWindow()
    window.show()
    sys.exit(app.exec())
