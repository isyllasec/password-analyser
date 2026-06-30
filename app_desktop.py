"""
app_desktop.py
Point d'entree PyQt6 -- orchestration UI uniquement (cf. decisions_projet.md
section 1). Aucune logique metier ici : tout passe par core/analyzer.py.
Aucun log/print du mot de passe.

Decisions actees pour cette version (session script_reprise PyQt6) :
- Analyse declenchee sur clic du bouton "Analyser" (pas en temps reel),
  coherent avec le mockup valide.
- Verification HIBP executee dans un QThread separe (AnalysisWorker) pour
  ne jamais geler l'UI pendant l'appel reseau (~200-500ms).
"""
import sys
from datetime import date as date_cls

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QDateEdit,
    QPushButton,
    QScrollArea,
    QFrame,
    QCheckBox,
)
from PyQt6.QtCore import QDate

from core.analyzer import analyze_password
from ui.result_view_qt import ResultViewQt

_BG = "#1A1F2E"
_BG_PANEL = "#242C3E"
_BORDER = "#3A4A60"
_TEXT = "#C8D8F0"
_TEXT_DIM = "#8A9BB5"
_ACCENT = "#2563EB"
_ACCENT_HOVER = "#1D4ED8"


# --- Worker HIBP : appel reseau hors du thread UI ----------------------------

class HibpWorker(QThread):
    """Relance analyze_password() avec check_hibp=True dans un thread separe.
    Le mot de passe transite uniquement en memoire (argument de fonction),
    jamais log/print, conforme au contrat de securite du projet."""

    finished_with_result = pyqtSignal(object)

    def __init__(self, password: str, prenom, nom, date_naissance, parent=None):
        super().__init__(parent)
        self._password = password
        self._prenom = prenom
        self._nom = nom
        self._date_naissance = date_naissance

    def run(self) -> None:
        result = analyze_password(
            self._password,
            prenom=self._prenom,
            nom=self._nom,
            date_naissance=self._date_naissance,
            word_ranks=None,
            check_hibp=True,
        )
        self.finished_with_result.emit(result)


# --- Panneau de gauche : formulaire -------------------------------------------

class LeftPanel(QWidget):
    analyze_requested = pyqtSignal()
    hibp_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(240)
        self.setStyleSheet(f"background-color: {_BG}; border-right: 0.5px solid {_BORDER};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 20, 16, 20)
        layout.setSpacing(10)

        layout.addWidget(self._label("Mot de passe"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet(self._input_style())
        layout.addWidget(self.password_input)

        divider1 = QFrame()
        divider1.setFrameShape(QFrame.Shape.HLine)
        divider1.setStyleSheet(f"color: {_BORDER}; background-color: {_BORDER};")
        layout.addWidget(divider1)

        identity_title = QLabel("Infos personnelles (optionnel)")
        identity_title.setStyleSheet(f"color: {_ACCENT}; font-size: 11px; font-weight: 500;")
        layout.addWidget(identity_title)

        layout.addWidget(self._label("Prenom"))
        self.prenom_input = QLineEdit()
        self.prenom_input.setStyleSheet(self._input_style())
        layout.addWidget(self.prenom_input)

        layout.addWidget(self._label("Nom"))
        self.nom_input = QLineEdit()
        self.nom_input.setStyleSheet(self._input_style())
        layout.addWidget(self.nom_input)

        layout.addWidget(self._label("Date de naissance"))
        self.date_known_checkbox = QCheckBox("Date de naissance connue")
        self.date_known_checkbox.setStyleSheet(
            f"color: {_TEXT_DIM}; font-size: 11px;"
        )
        self.date_known_checkbox.toggled.connect(self._on_date_known_toggled)
        layout.addWidget(self.date_known_checkbox)

        self.date_input = QDateEdit()
        self.date_input.setCalendarPopup(True)
        self.date_input.setDisplayFormat("dd/MM/yyyy")
        self.date_input.setDate(QDate.currentDate())
        self.date_input.setMinimumDate(QDate(1920, 1, 1))
        self.date_input.setMaximumDate(QDate.currentDate())
        self.date_input.setStyleSheet(self._input_style())
        self.date_input.setEnabled(False)
        layout.addWidget(self.date_input)

        divider2 = QFrame()
        divider2.setFrameShape(QFrame.Shape.HLine)
        divider2.setStyleSheet(f"color: {_BORDER}; background-color: {_BORDER};")
        layout.addWidget(divider2)

        self.analyze_btn = QPushButton("Analyser")
        self.analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.analyze_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {_ACCENT}; color: white; border: none;
                border-radius: 6px; padding: 8px 12px; font-size: 13px;
            }}
            QPushButton:hover {{ background-color: {_ACCENT_HOVER}; }}
            """
        )
        self.analyze_btn.clicked.connect(self.analyze_requested.emit)
        layout.addWidget(self.analyze_btn)

        self.hibp_btn = QPushButton("Verifier les fuites (HIBP)")
        self.hibp_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.hibp_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {_BG_PANEL}; color: {_ACCENT_HOVER};
                border: 1px solid {_BORDER}; border-radius: 6px;
                padding: 7px 12px; font-size: 13px;
            }}
            QPushButton:hover {{ background-color: {_BORDER}; }}
            QPushButton:disabled {{ color: {_TEXT_DIM}; }}
            """
        )
        self.hibp_btn.setEnabled(False)
        self.hibp_btn.clicked.connect(self.hibp_requested.emit)
        layout.addWidget(self.hibp_btn)

        layout.addStretch()

    def _on_date_known_toggled(self, checked: bool) -> None:
        self.date_input.setEnabled(checked)

    def _label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(f"color: {_TEXT_DIM}; font-size: 11px;")
        return label

    def _input_style(self) -> str:
        return f"""
            QLineEdit, QDateEdit {{
                background-color: {_BG_PANEL}; border: 1px solid {_BORDER};
                border-radius: 6px; padding: 7px 10px; color: {_TEXT}; font-size: 13px;
            }}
            QDateEdit::drop-down {{ border: none; width: 20px; }}
        """

    # --- accesseurs de contrat avec core/analyzer.py ---

    def get_password(self) -> str:
        return self.password_input.text()

    def get_prenom(self):
        text = self.prenom_input.text().strip()
        return text or None

    def get_nom(self):
        text = self.nom_input.text().strip()
        return text or None

    def get_date_naissance(self):
        if not self.date_known_checkbox.isChecked():
            return None
        qd = self.date_input.date()
        return date_cls(qd.year(), qd.month(), qd.day())

    def identity_provided(self) -> bool:
        return bool(self.get_prenom() or self.get_nom() or self.get_date_naissance())


# --- Fenetre principale --------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analyseur de mots de passe")
        self.resize(820, 560)
        self.setStyleSheet(f"background-color: {_BG};")

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.left_panel = LeftPanel()
        root.addWidget(self.left_panel)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"background-color: {_BG}; border: none;")
        right_container = QWidget()
        right_container.setStyleSheet(f"background-color: {_BG};")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(20, 20, 20, 20)
        right_layout.setSpacing(12)

        self.placeholder = QLabel("Saisissez un mot de passe puis cliquez sur \u00ab Analyser \u00bb.")
        self.placeholder.setStyleSheet(f"color: {_TEXT_DIM}; font-size: 13px;")
        right_layout.addWidget(self.placeholder)

        self.result_view = ResultViewQt()
        self.result_view.setVisible(False)
        right_layout.addWidget(self.result_view)
        right_layout.addStretch()

        scroll.setWidget(right_container)
        root.addWidget(scroll)

        self.left_panel.analyze_requested.connect(self.run_analysis)
        self.left_panel.hibp_requested.connect(self.run_hibp_check)

        self._current_result = None
        self._hibp_worker = None

    def run_analysis(self) -> None:
        password = self.left_panel.get_password()
        if not password:
            return

        result = analyze_password(
            password,
            prenom=self.left_panel.get_prenom(),
            nom=self.left_panel.get_nom(),
            date_naissance=self.left_panel.get_date_naissance(),
            word_ranks=None,
            check_hibp=False,
        )
        self._current_result = result

        self.placeholder.setVisible(False)
        self.result_view.setVisible(True)
        self.result_view.render_result(
            result, password, self.left_panel.identity_provided()
        )
        self.left_panel.hibp_btn.setEnabled(True)

    def run_hibp_check(self) -> None:
        password = self.left_panel.get_password()
        if not password or self._current_result is None:
            return

        self.left_panel.hibp_btn.setEnabled(False)
        self.left_panel.hibp_btn.setText("Verification en cours...")

        self._hibp_worker = HibpWorker(
            password,
            self.left_panel.get_prenom(),
            self.left_panel.get_nom(),
            self.left_panel.get_date_naissance(),
        )
        self._hibp_worker.finished_with_result.connect(self._on_hibp_finished)
        self._hibp_worker.start()

    def _on_hibp_finished(self, result) -> None:
        password = self.left_panel.get_password()
        self._current_result = result
        self.result_view.render_result(
            result, password, self.left_panel.identity_provided()
        )
        self.left_panel.hibp_btn.setEnabled(True)
        self.left_panel.hibp_btn.setText("Verifier les fuites (HIBP)")


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()