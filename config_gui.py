# config_gui.py (Enhanced: auto-syncs master credentials for API)
# ---------------------------------------------------------------

import sys
import string
import random
import threading
import re
import hashlib
import json
import os
import mysql.connector

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar, QFrame,
    QGraphicsOpacityEffect
)

from utils.setup_utils import setup
from login_gui import LoginWindow


# ---------------- Utility helpers ----------------
def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?"
    return "".join(random.choice(chars) for _ in range(length))


def update_master_config(master_password, device_secret):
    """Save master password + device secret for backend API use."""
    os.makedirs("config", exist_ok=True)
    config_data = {
        "master_password": master_password.strip(),
        "device_secret": device_secret.strip()
    }
    with open("config/master_config.json", "w") as f:
        json.dump(config_data, f)


def setup_master_password(password):
    """Store the master password and device secret in pm_auth, and sync config."""
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

    # Save credentials for API auto-load
    update_master_config(password, device_secret)


# ---------------- Worker ----------------
class SetupWorker(QObject):
    """
    Background worker to run setup without blocking the UI.
    Emits: finished(success: bool, message: str)
    """
    finished = pyqtSignal(bool, str)

    def __init__(self, password):
        super().__init__()
        self.password = password

    def run(self):
        try:
            setup()
            setup_master_password(self.password)
            self.finished.emit(True, "Master password configured successfully!")
        except Exception as e:
            self.finished.emit(False, str(e))


# ---------------- GUI Window ----------------
class ConfigWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager - Setup")
        self.setGeometry(500, 250, 450, 480)
        self.setStyleSheet("background-color: #101820; color: #E0E0E0; border-radius: 10px;")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Set Your Master Password")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Password inputs
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter master password")
        self.password_input.textChanged.connect(self.on_password_change)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Confirm master password")
        self.confirm_input.textChanged.connect(self.check_password_match)

        # Toggle buttons
        toggle_btn1 = QPushButton("👁️")
        toggle_btn1.setCheckable(True)
        toggle_btn1.clicked.connect(lambda checked: self.toggle_visibility(self.password_input, checked))
        toggle_btn2 = QPushButton("👁️")
        toggle_btn2.setCheckable(True)
        toggle_btn2.clicked.connect(lambda checked: self.toggle_visibility(self.confirm_input, checked))
        for btn in (toggle_btn1, toggle_btn2):
            btn.setStyleSheet("background-color: #333; color: white; border-radius: 5px; padding: 4px 8px;")

        pw_layout = QHBoxLayout()
        pw_layout.addWidget(self.password_input)
        pw_layout.addWidget(toggle_btn1)

        confirm_layout = QHBoxLayout()
        confirm_layout.addWidget(self.confirm_input)
        confirm_layout.addWidget(toggle_btn2)

        # Password strength & requirements
        self.requirements_panel = QFrame()
        self.requirements_panel.setStyleSheet("""
            background-color: #181F2E;
            border-radius: 8px;
            padding: 10px;
        """)
        self.requirements_panel.setVisible(False)
        self.fade_effect = QGraphicsOpacityEffect()
        self.requirements_panel.setGraphicsEffect(self.fade_effect)
        self.fade_effect.setOpacity(0.0)

        panel_layout = QVBoxLayout()
        self.requirement_labels = {
            "length": QLabel("❌ At least 8 characters"),
            "upper": QLabel("❌ Contains uppercase letter"),
            "lower": QLabel("❌ Contains lowercase letter"),
            "number": QLabel("❌ Contains number"),
            "symbol": QLabel("❌ Contains special symbol"),
        }
        for lbl in self.requirement_labels.values():
            lbl.setStyleSheet("color: #ff6666; font-size: 13px;")
            panel_layout.addWidget(lbl)
        self.requirements_panel.setLayout(panel_layout)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 5)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(8)

        self.strength_label = QLabel("Strength: ")
        self.strength_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.strength_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")

        # Buttons
        suggest_btn = QPushButton("🔁 Suggest Strong Password")
        suggest_btn.clicked.connect(self.suggest_password)
        suggest_btn.setStyleSheet("background-color: #0275d8; color: white; border-radius: 6px; padding: 6px;")

        confirm_btn = QPushButton("✅ Set Master Password")
        confirm_btn.clicked.connect(self.handle_setup)
        confirm_btn.setStyleSheet("background-color: #28a745; color: white; border-radius: 6px; padding: 8px;")

        self.progress = QProgressBar()
        self.progress.setVisible(False)

        # Layout
        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(pw_layout)
        layout.addWidget(self.requirements_panel)
        layout.addWidget(self.strength_bar)
        layout.addWidget(self.strength_label)
        layout.addSpacing(10)
        layout.addLayout(confirm_layout)
        layout.addSpacing(10)
        layout.addWidget(suggest_btn)
        layout.addSpacing(10)
        layout.addWidget(confirm_btn)
        layout.addWidget(self.progress)
        self.setLayout(layout)

    # --- Password Logic ---
    def fade_in_panel(self):
        self.requirements_panel.setVisible(True)
        anim = QPropertyAnimation(self.fade_effect, b"opacity")
        anim.setDuration(250)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.start()
        self.anim = anim

    def fade_out_panel(self):
        anim = QPropertyAnimation(self.fade_effect, b"opacity")
        anim.setDuration(250)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.finished.connect(lambda: self.requirements_panel.setVisible(False))
        anim.start()
        self.anim = anim

    def on_password_change(self, text):
        if text and not self.requirements_panel.isVisible():
            self.fade_in_panel()
        elif not text and self.requirements_panel.isVisible():
            self.fade_out_panel()
        self.update_requirements_ui(text)
        self.update_strength_ui(text)
        self.check_password_match()

    def update_requirements_ui(self, password):
        checks = {
            "length": len(password) >= 8,
            "upper": bool(re.search(r"[A-Z]", password)),
            "lower": bool(re.search(r"[a-z]", password)),
            "number": bool(re.search(r"[0-9]", password)),
            "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
        }
        for key, passed in checks.items():
            lbl = self.requirement_labels[key]
            if passed:
                lbl.setText(f"✅ {lbl.text()[2:]}")
                lbl.setStyleSheet("color: #00FF7F; font-size: 13px;")
            else:
                lbl.setText(f"❌ {lbl.text()[2:]}")
                lbl.setStyleSheet("color: #ff6666; font-size: 13px;")

    def update_strength_ui(self, password):
        checks = [
            len(password) >= 8,
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[0-9]", password)),
            bool(re.search(r"[^A-Za-z0-9]", password)),
        ]
        satisfied = sum(checks)
        self.strength_bar.setValue(satisfied)
        colors = ["#d9534f", "#f0ad4e", "#5bc0de", "#5cb85c"]
        texts = ["Weak", "Fair", "Strong", "Very Strong"]
        idx = min(satisfied - 2, 3)
        if satisfied <= 2:
            color, text = colors[0], texts[0]
        else:
            color, text = colors[idx], texts[idx]
        self.strength_label.setText(f"Strength: <b><span style='color:{color}'>{text}</span></b>")

    def check_password_match(self):
        pwd, confirm = self.password_input.text(), self.confirm_input.text()
        if not confirm:
            self.confirm_input.setStyleSheet("border: 1px solid #444; color: white;")
            return
        color = "#28a745" if pwd == confirm else "#d9534f"
        self.confirm_input.setStyleSheet(f"border: 2px solid {color}; color: white;")

    # --- Buttons ---
    def toggle_visibility(self, field, checked):
        field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)

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
        self.worker = SetupWorker(password)
        self.worker.finished.connect(self.on_setup_finished)
        threading.Thread(target=self.worker.run, daemon=True).start()

    def on_setup_finished(self, success, message):
        self.progress.setVisible(False)
        if success:
            QMessageBox.information(self, "Success", message)
            QTimer.singleShot(800, self.open_login_window)
        else:
            QMessageBox.critical(self, "Setup Failed", message)

    def open_login_window(self):
        self.hide()
        self.login = LoginWindow()
        self.login.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigWindow()
    window.show()
    sys.exit(app.exec())
