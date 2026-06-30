"""
ui/result_view_qt.py
Equivalent PyQt6 de ui/result_view.py -- AUCUN recalcul ici, lecture seule
des champs de AnalysisResult (cf. decisions_projet.md section 1).

Meme contrat que la version Streamlit : render_result() recoit le mot de
passe en clair uniquement pour l'affichage des segments textuels dans les
accordeons. Aucun print()/log du mot de passe nulle part dans ce module.
"""
import math

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QFrame,
)

# --- Seuils du verdict qualitatif (echelle zxcvbn, decisions_projet.md section 12) ---
_VERDICT_LEVELS = [
    (28, "Tres faible", "c-red"),
    (36, "Faible", "c-amber"),
    (60, "Moyen", "c-amber"),
    (128, "Fort", "c-teal"),
    (float("inf"), "Tres fort", "c-teal"),
]

_RAMP_COLORS = {
    "c-red": ("#501313", "#F7C1C1"),
    "c-amber": ("#4D3A12", "#F7D9A1"),
    "c-teal": ("#0F3D30", "#A1F0D5"),
}

_TYPE_LABELS = {
    "dictionary": "contient un mot de passe tres courant",
    "leet_dictionary": "contient un mot courant deguise (substitutions type 4/0)",
    "qwerty": "contient une suite de touches du clavier",
    "date": "contient une date ou une annee reconnaissable",
    "osint": "contient des informations personnelles devinables",
}
_TYPE_PRIORITY = ["dictionary", "leet_dictionary", "osint", "qwerty", "date"]

# Palette coherente avec .streamlit/config.toml
_BG = "#1A1F2E"
_BG_PANEL = "#242C3E"
_BG_BODY = "#1E2638"
_BORDER = "#3A4A60"
_TEXT = "#C8D8F0"
_TEXT_DIM = "#8A9BB5"
_ACCENT = "#60A5FA"


def _verdict(h_adjusted: float):
    for threshold, label, ramp in _VERDICT_LEVELS:
        if h_adjusted < threshold:
            return label, ramp
    return _VERDICT_LEVELS[-1][1], _VERDICT_LEVELS[-1][2]


def _pessimistic_crack_time(cracking_time_estimate: dict) -> dict:
    """Meme logique que result_view.py section 12 (pire cas realiste)."""
    bf = cracking_time_estimate["brute_force"]["md5"]
    da = cracking_time_estimate["dictionary_attack"]
    if da["applicable"] and da["md5"]["seconds"] < bf["seconds"]:
        return da["md5"]
    return bf


def _top_reasons(retained_matches: list) -> list:
    types_found = {m["type"] for m in retained_matches if m["type"] in _TYPE_LABELS}
    ordered = [t for t in _TYPE_PRIORITY if t in types_found]
    return [_TYPE_LABELS[t] for t in ordered[:3]]


def _segment_text(password: str, match: dict) -> str:
    return password[match["start"]:match["end"]]


# --- Widget table generique (style sombre coherent) -------------------------

def _make_table(headers: list) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.setStyleSheet(
        f"""
        QTableWidget {{
            background-color: {_BG_BODY};
            color: {_TEXT};
            gridline-color: {_BORDER};
            border: none;
            font-size: 12px;
        }}
        QHeaderView::section {{
            background-color: {_BG_PANEL};
            color: {_TEXT_DIM};
            border: none;
            padding: 4px;
            font-size: 11px;
        }}
        """
    )
    return table


def _fill_table(table: QTableWidget, rows: list) -> None:
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            table.setItem(r, c, QTableWidgetItem(str(value)))
    table.resizeRowsToContents()
    # Hauteur compacte : pas de scroll imbrique pour un nombre raisonnable de lignes
    total_height = table.horizontalHeader().height() + sum(
        table.rowHeight(r) for r in range(table.rowCount())
    ) + 4
    table.setFixedHeight(min(total_height, 240))


def _caption(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(f"color: {_TEXT_DIM}; font-size: 12px;")
    label.setWordWrap(True)
    return label


# --- Accordeon reutilisable ---------------------------------------------------

class AccordionSection(QWidget):
    """Section repliable : header cliquable + corps show/hide.
    Equivalent du st.expander() de la version Streamlit."""

    def __init__(self, title: str, start_open: bool = False, enabled: bool = True, parent=None):
        super().__init__(parent)
        self._open = start_open

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ border: 0.5px solid {_BORDER}; border-radius: 6px; }}"
        )
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)

        self._header_btn = QPushButton()
        self._header_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._header_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {_BG_PANEL};
                color: {_TEXT if enabled else _TEXT_DIM};
                border: none;
                border-radius: 0px;
                padding: 8px 12px;
                text-align: left;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {_BORDER if enabled else _BG_PANEL};
            }}
            """
        )
        self._header_btn.clicked.connect(self._toggle)
        self._header_btn.setEnabled(enabled)

        self._body = QWidget()
        self._body.setStyleSheet(f"background-color: {_BG_BODY};")
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(12, 10, 12, 10)
        self._body_layout.setSpacing(8)

        frame_layout.addWidget(self._header_btn)
        frame_layout.addWidget(self._body)
        outer.addWidget(frame)

        self._title = title
        self._set_header_text()
        self._body.setVisible(self._open)

    def _set_header_text(self) -> None:
        arrow = "\u25B2" if self._open else "\u25BC"
        self._header_btn.setText(f"{self._title}                                            {arrow}")

    def _toggle(self) -> None:
        self._open = not self._open
        self._body.setVisible(self._open)
        self._set_header_text()

    def body_layout(self) -> QVBoxLayout:
        return self._body_layout


# --- Section resume (toujours visible) ----------------------------------------

class SummaryWidget(QWidget):
    """Equivalent de _render_summary() : badge + temps de cassage + barre + raisons."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._badge = QLabel()
        self._badge.setStyleSheet("font-size: 11px; padding: 3px 10px; border-radius: 6px; font-weight: 500;")
        self._badge.setFixedWidth(90)
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._crack_label = QLabel()
        self._crack_label.setStyleSheet(f"font-size: 14px; font-weight: 500; color: {_TEXT};")
        self._crack_label.setWordWrap(True)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(5)
        self._progress.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: {_BORDER};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {_ACCENT};
                border-radius: 4px;
            }}
            """
        )

        self._reasons_layout = QVBoxLayout()
        self._reasons_layout.setSpacing(2)

        self._osint_warning = QLabel()
        self._osint_warning.setWordWrap(True)
        self._osint_warning.setStyleSheet(
            "background-color: #4D3A12; color: #F7D9A1; border-radius: 6px; padding: 8px; font-size: 12px;"
        )
        self._osint_warning.setVisible(False)

        layout.addWidget(self._badge)
        layout.addWidget(self._crack_label)
        layout.addWidget(self._progress)
        layout.addLayout(self._reasons_layout)
        layout.addWidget(self._osint_warning)

    def update_result(self, result, password: str) -> None:
        label, ramp = _verdict(result.adjusted_entropy_bits)
        bg, fg = _RAMP_COLORS[ramp]
        self._badge.setText(label)
        self._badge.setStyleSheet(
            f"background-color: {bg}; color: {fg}; font-size: 11px; "
            f"padding: 3px 10px; border-radius: 6px; font-weight: 500;"
        )

        crack = _pessimistic_crack_time(result.cracking_time_estimate)
        self._crack_label.setText(f"Cassable en : {crack['human_readable']} (pire cas realiste)")

        capped_ratio = min(result.adjusted_entropy_bits / 128, 1.0)
        self._progress.setValue(int(capped_ratio * 100))

        # Vide les anciennes raisons
        while self._reasons_layout.count():
            item = self._reasons_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        reasons = _top_reasons(result.retained_matches)
        if reasons:
            for r in reasons:
                self._reasons_layout.addWidget(_caption(f"- {r.capitalize()}"))
        else:
            self._reasons_layout.addWidget(
                _caption("- Aucun motif previsible detecte parmi les regles testees")
            )

        osint_retained = any(m["type"] == "osint" for m in result.retained_matches)
        self._osint_warning.setVisible(osint_retained)
        if osint_retained:
            self._osint_warning.setText(
                "Ce mot de passe contient des informations personnelles devinables."
            )


# --- Vue resultats complete : 5 accordeons -------------------------------------

class ResultViewQt(QWidget):
    """Equivalent de render_result() : assemble les 5 sections repliables.
    AUCUN calcul ici, lecture seule des champs de AnalysisResult."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.summary = SummaryWidget()
        layout.addWidget(self.summary)

        self._entropy_section = AccordionSection("Entropie", start_open=True)
        self._patterns_section = AccordionSection("Motifs detectes")
        self._osint_section = AccordionSection("Exposition OSINT")
        self._cracking_section = AccordionSection("Temps de cassage detaille")
        self._hibp_section = AccordionSection("Verification de fuite", enabled=True)

        for section in (
            self._entropy_section,
            self._patterns_section,
            self._osint_section,
            self._cracking_section,
            self._hibp_section,
        ):
            layout.addWidget(section)

        layout.addStretch()

        self._hibp_checked = False

    # --- helpers de remplissage par section ---

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _fill_entropy(self, result, password: str) -> None:
        layout = self._entropy_section.body_layout()
        self._clear_layout(layout)

        metrics = QHBoxLayout()
        for label_text, value in (
            ("Theorique", f"{result.theoretical_entropy_bits:.1f} bits"),
            ("Ajustee", f"{result.adjusted_entropy_bits:.1f} bits"),
        ):
            box = QFrame()
            box.setStyleSheet(f"background-color: {_BG_PANEL}; border-radius: 6px;")
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(8, 6, 8, 6)
            lab = QLabel(label_text)
            lab.setStyleSheet(f"color: {_TEXT_DIM}; font-size: 10px;")
            val = QLabel(value)
            val.setStyleSheet(f"color: {_ACCENT}; font-size: 15px; font-weight: 500;")
            box_layout.addWidget(lab)
            box_layout.addWidget(val)
            metrics.addWidget(box)
        layout.addLayout(metrics)

        if result.retained_matches:
            layout.addWidget(_caption("Segments retenus dans le calcul :"))
            table = _make_table(["Segment", "Type", "Cout (bits)"])
            rows = [
                (_segment_text(password, m), m["type"], round(m["cost_bits"], 2))
                for m in result.retained_matches
            ]
            _fill_table(table, rows)
            layout.addWidget(table)

        if result.unmatched_segments:
            layout.addWidget(_caption("Segments non reconnus :"))
            table2 = _make_table(["Segment", "Alphabet local", "Cout (bits)"])
            rows2 = [
                (
                    password[seg["start"]:seg["end"]],
                    seg["alphabet_size"],
                    round(seg["cost"], 2),
                )
                for seg in result.unmatched_segments
            ]
            _fill_table(table2, rows2)
            layout.addWidget(table2)

    def _fill_patterns(self, result, password: str) -> None:
        layout = self._patterns_section.body_layout()
        self._clear_layout(layout)

        if not result.pattern_matches:
            layout.addWidget(_caption("Aucun motif detecte."))
            return

        retained_keys = {(m["start"], m["end"], m["type"]) for m in result.retained_matches}
        table = _make_table(["Segment", "Type", "Retenu dans le score"])
        rows = []
        for m in result.pattern_matches:
            key = (m["start"], m["end"], m["type"])
            rows.append(
                (
                    _segment_text(password, m),
                    m["type"],
                    "Oui" if key in retained_keys else "Non (chevauchement)",
                )
            )
        _fill_table(table, rows)
        layout.addWidget(table)

    def _fill_osint(self, result, password: str, identity_provided: bool) -> None:
        layout = self._osint_section.body_layout()
        self._clear_layout(layout)
        self._osint_section.setVisible(identity_provided)

        if not identity_provided:
            return

        if not result.osint_matches:
            layout.addWidget(_caption("Aucune correspondance trouvee avec les informations fournies."))
            return

        retained_keys = {(m["start"], m["end"], m["type"]) for m in result.retained_matches}
        table = _make_table(["Segment", "Regle", "Retenu dans le score"])
        rows = []
        for m in result.osint_matches:
            key = (m["start"], m["end"], m["type"])
            rows.append(
                (
                    _segment_text(password, m),
                    m["data"].get("rule", "?"),
                    "Oui" if key in retained_keys else "Non (chevauchement)",
                )
            )
        _fill_table(table, rows)
        layout.addWidget(table)

    def _fill_cracking_time(self, result) -> None:
        layout = self._cracking_section.body_layout()
        self._clear_layout(layout)

        cte = result.cracking_time_estimate
        algos = ["md5", "sha1", "sha256", "bcrypt"]
        applicable = cte["dictionary_attack"]["applicable"]

        headers = ["Algorithme", "Brute force"]
        if applicable:
            headers.append("Dictionnaire + regles")
        table = _make_table(headers)

        rows = []
        for a in algos:
            row = [a.upper(), cte["brute_force"][a]["human_readable"]]
            if applicable:
                row.append(cte["dictionary_attack"][a]["human_readable"])
            rows.append(tuple(row))
        _fill_table(table, rows)
        layout.addWidget(table)

        if not applicable:
            layout.addWidget(
                _caption(
                    "Attaque dictionnaire+regles non applicable "
                    "(aucun motif dictionnaire/OSINT retenu)."
                )
            )

    def _fill_hibp(self, result) -> None:
        layout = self._hibp_section.body_layout()
        self._clear_layout(layout)

        if result.hibp_breached is None:
            layout.addWidget(
                _caption(
                    "Verification non effectuee. Utilisez le bouton "
                    "\u00ab Verifier les fuites (HIBP) \u00bb pour interroger l'API."
                )
            )
        elif result.hibp_breached is True:
            warn = QLabel("Ce mot de passe a ete trouve dans une fuite de donnees connue.")
            warn.setWordWrap(True)
            warn.setStyleSheet(
                "background-color: #501313; color: #F7C1C1; border-radius: 6px; padding: 8px; font-size: 12px;"
            )
            layout.addWidget(warn)
        else:
            ok = QLabel("Aucune correspondance trouvee dans les fuites connues (HIBP).")
            ok.setWordWrap(True)
            ok.setStyleSheet(
                "background-color: #0F3D30; color: #A1F0D5; border-radius: 6px; padding: 8px; font-size: 12px;"
            )
            layout.addWidget(ok)

    # --- point d'entree -----------------------------------------------------

    def render_result(self, result, password: str, identity_provided: bool) -> None:
        """Affiche le resultat complet. N'effectue AUCUN calcul -- lit
        uniquement les champs de `result` (AnalysisResult) et le mot de
        passe (pour le rendu textuel des segments, jamais log/print)."""
        self.summary.update_result(result, password)
        self._fill_entropy(result, password)
        self._fill_patterns(result, password)
        self._fill_osint(result, password, identity_provided)
        self._fill_cracking_time(result)
        self._fill_hibp(result)