# config_gui.py
# -------------------------------------------------------
# GUI for setting up the master password and initializing
# the Secure Password Manager databases.
# -------------------------------------------------------

import sys
import string
import random
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from utils.setup_utils import setup
from utils.setup_utils import setup_master_password


def generate_strong_password(length=16):
    """Generate a strong random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))


class ConfigWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager - Setup")
        self.setGeometry(500, 250, 450, 350)
        self.setStyleSheet("background-color: #101820; color: #E0E0E0;")

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Setup Master Password")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Password fields
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter master password")

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("Confirm master password")

        # Show/Hide button
        toggle_btn = QPushButton("👁️ Show")
        toggle_btn.setCheckable(True)
        toggle_btn.setStyleSheet("background-color: #333; color: white; border-radius: 5px; padding: 4px 8px;")
        toggle_btn.clicked.connect(self.toggle_password_visibility)

        # Suggest password button
        suggest_btn = QPushButton("🔁 Suggest Strong Password")
        suggest_btn.setStyleSheet("background-color: #0275d8; color: white; border-radius: 5px; padding: 6px;")
        suggest_btn.clicked.connect(self.suggest_password)

        # Progress bar (for setup process)
        self.progress = QProgressBar()
        self.progress.setVisible(False)

        # Confirm button
        confirm_btn = QPushButton("✅ Set Master Password")
        confirm_btn.setStyleSheet("background-color: #28a745; color: white; border-radius: 6px; padding: 8px;")
        confirm_btn.clicked.connect(self.handle_setup)

        # Layout
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.password_input)
        top_layout.addWidget(toggle_btn)

        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addLayout(top_layout)
        layout.addWidget(self.confirm_input)
        layout.addSpacing(10)
        layout.addWidget(suggest_btn)
        layout.addSpacing(10)
        layout.addWidget(confirm_btn)
        layout.addSpacing(10)
        layout.addWidget(self.progress)

        self.setLayout(layout)

    # --- Button Handlers ---

    def toggle_password_visibility(self, checked):
        """Show/hide password fields."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

    def suggest_password(self):
        """Generate a strong random password and display it."""
        suggested = generate_strong_password()
        self.password_input.setText(suggested)
        self.confirm_input.setText(suggested)
        QMessageBox.information(self, "Suggested Password", "A strong password has been auto-filled for you!")

    def handle_setup(self):
        """Run full DB setup and store master password."""
        password = self.password_input.text().strip()
        confirm = self.confirm_input.text().strip()

        if not password or not confirm:
            QMessageBox.warning(self, "Error", "Please fill in both password fields.")
            return

        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        self.progress.setVisible(True)
        self.progress.setValue(10)

        # Step 1: Initialize databases
        threading.Thread(target=self.run_setup, args=(password,)).start()

    def run_setup(self, password):
        """Run setup in background thread."""
        try:
            self.progress.setValue(40)
            setup()  # initialize databases
            self.progress.setValue(70)
            setup_master_password(password)  # store master password securely
            self.progress.setValue(100)

            QMessageBox.information(self, "Success", "Master password configured successfully!")
            self.close()

        except Exception as e:
            QMessageBox.critical(self, "Setup Failed", f"Error: {str(e)}")
        finally:
            self.progress.setVisible(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigWindow()
    window.show()
    sys.exit(app.exec())
