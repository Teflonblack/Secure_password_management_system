# config_gui.py
import sys
import random
import string
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QHBoxLayout, QSpacerItem, QSizePolicy
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

from utils.setup_utils import setup_master_password


class ConfigGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Manager – Setup")
        self.setGeometry(400, 200, 450, 350)
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E2E;
                color: #FFFFFF;
                font-family: 'Segoe UI';
            }
            QLabel {
                font-size: 16px;
            }
            QLineEdit {
                background-color: #2E2E3E;
                border: 1px solid #8B5CF6;
                border-radius: 8px;
                padding: 8px;
                color: #FFFFFF;
                font-size: 14px;
            }
            QPushButton {
                background-color: #8B5CF6;
                border: none;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #7C3AED;
            }
        """)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Setup Master Password")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(15)

        # Master password
        self.mp_input = QLineEdit()
        self.mp_input.setPlaceholderText("Enter Master Password")
        self.mp_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.mp_input)

        # Confirm password
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm Master Password")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        # Toggle + Suggest buttons
        btn_layout = QHBoxLayout()
        self.toggle_btn = QPushButton("👁️ Show Passwords")
        self.toggle_btn.clicked.connect(self.toggle_passwords)
        btn_layout.addWidget(self.toggle_btn)

        self.suggest_btn = QPushButton("🔁 Suggest Strong Password")
        self.suggest_btn.clicked.connect(self.suggest_password)
        btn_layout.addWidget(self.suggest_btn)

        layout.addLayout(btn_layout)
        layout.addSpacing(10)

        # Confirm setup button
        self.setup_btn = QPushButton("✅ Set Master Password")
        self.setup_btn.clicked.connect(self.save_master_password)
        layout.addWidget(self.setup_btn)

        # Spacer for aesthetics
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.setLayout(layout)

    def toggle_passwords(self):
        """Toggle between showing and hiding password text."""
        if self.mp_input.echoMode() == QLineEdit.EchoMode.Password:
            self.mp_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("🙈 Hide Passwords")
        else:
            self.mp_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("👁️ Show Passwords")

    def suggest_password(self):
        """Generate a strong random password and fill both fields."""
        length = 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        suggestion = ''.join(random.choice(chars) for _ in range(length))
        self.mp_input.setText(suggestion)
        self.confirm_input.setText(suggestion)

        QMessageBox.information(self, "Suggested Password",
                                f"Suggested strong password:\n\n{suggestion}",
                                QMessageBox.StandardButton.Ok)

    def save_master_password(self):
        """Validate input and trigger backend setup."""
        mp = self.mp_input.text().strip()
        confirm = self.confirm_input.text().strip()

        if not mp or not confirm:
            QMessageBox.warning(self, "Input Error", "Please enter and confirm your password.")
            return

        if mp != confirm:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return

        # Call backend setup
        success = setup_master_password(mp)
        if success:
            QMessageBox.information(self, "Success",
                                    "Master password and databases configured successfully!",
                                    QMessageBox.StandardButton.Ok)
            self.close()
        else:
            QMessageBox.critical(self, "Error",
                                 "An error occurred while setting up the database.",
                                 QMessageBox.StandardButton.Ok)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigGUI()
    window.show()
    sys.exit(app.exec())
