"""
ui/result_view.py
Affichage des resultats -- AUCUN recalcul ici, lecture seule des champs de
AnalysisResult (cf. decisions_projet.md section 1).

Hypothese de contrat (a confirmer / documenter dans decisions_projet.md) :
render_result() recoit le mot de passe en clair en plus de `result`,
uniquement pour pouvoir afficher les segments textuels (ex. "password" en
rouge) dans les expanders axes 1/2/3. AnalysisResult ne stocke pas le mot
de passe lui-meme (cf. analyzer.py) -- aucune fonction de ce module ne le
log/print, il est uniquement garde en memoire pour le rendu Streamlit.
"""
import math

import pandas as pd
import streamlit as st

# --- Seuils du verdict qualitatif (echelle zxcvbn, decisions_projet.md section 12) ---
_VERDICT_LEVELS = [
    (28, "Tres faible", "c-red"),
    (36, "Faible", "c-amber"),
    (60, "Moyen", "c-amber"),
    (128, "Fort", "c-teal"),
    (float("inf"), "Tres fort", "c-teal"),
]

_RAMP_COLORS = {
    "c-red": ("#FCEBEB", "#791F1F"),
    "c-amber": ("#FAEEDA", "#854F0B"),
    "c-teal": ("#E1F5EE", "#085041"),
}

_TYPE_LABELS = {
    "dictionary": "contient un mot de passe tres courant",
    "leet_dictionary": "contient un mot courant deguise (substitutions type 4/0)",
    "qwerty": "contient une suite de touches du clavier",
    "date": "contient une date ou une annee reconnaissable",
    "osint": "contient des informations personnelles devinables",
}
_TYPE_PRIORITY = ["dictionary", "leet_dictionary", "osint", "qwerty", "date"]


def _verdict(h_adjusted: float):
    for threshold, label, ramp in _VERDICT_LEVELS:
        if h_adjusted < threshold:
            return label, ramp
    return _VERDICT_LEVELS[-1][1], _VERDICT_LEVELS[-1][2]


def _badge_html(label: str, ramp: str) -> str:
    bg, fg = _RAMP_COLORS[ramp]
    return (
        f'<span style="background:{bg};color:{fg};font-size:13px;'
        f'padding:3px 10px;border-radius:6px;font-weight:500">{label}</span>'
    )


def _pessimistic_crack_time(cracking_time_estimate: dict) -> dict:
    """Pire cas realiste : MD5 (hash le plus rapide a casser) + methode la
    plus rapide applicable (dictionnaire+regles si applicable et plus
    rapide, sinon brute force). Decision : decisions_projet.md section 12."""
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


# --- Section resume (toujours visible) --------------------------------------

def _render_summary(result, password: str) -> None:
    label, ramp = _verdict(result.adjusted_entropy_bits)
    st.markdown(_badge_html(label, ramp), unsafe_allow_html=True)

    crack = _pessimistic_crack_time(result.cracking_time_estimate)
    st.markdown(f"**Cassable en : {crack['human_readable']}** (pire cas realiste)")

    capped_ratio = min(result.adjusted_entropy_bits / 128, 1.0)
    st.progress(capped_ratio)

    reasons = _top_reasons(result.retained_matches)
    if reasons:
        for r in reasons:
            st.markdown(f"- {r.capitalize()}")
    else:
        st.markdown("- Aucun motif previsible detecte parmi les regles testees")

    osint_retained = any(m["type"] == "osint" for m in result.retained_matches)
    if osint_retained:
        st.warning("Ce mot de passe contient des informations personnelles devinables.")


# --- Expander axe 1 : entropie -----------------------------------------------

def _render_entropy_expander(result, password: str) -> None:
    with st.expander("Entropie"):
        col1, col2 = st.columns(2)
        col1.metric("Theorique", f"{result.theoretical_entropy_bits:.1f} bits")
        col2.metric("Ajustee", f"{result.adjusted_entropy_bits:.1f} bits")

        if result.retained_matches:
            st.caption("Segments retenus dans le calcul :")
            rows = [
                {
                    "Segment": _segment_text(password, m),
                    "Type": m["type"],
                    "Cout (bits)": round(m["cost_bits"], 2),
                }
                for m in result.retained_matches
            ]
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

        if result.unmatched_segments:
            st.caption("Segments non reconnus :")
            rows = [
                {
                    "Segment": password[seg["start"]:seg["end"]],
                    "Alphabet local": seg["alphabet_size"],
                    "Cout (bits)": round(seg["cost"], 2),
                }
                for seg in result.unmatched_segments
            ]
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


# --- Expander axe 2 : motifs --------------------------------------------------

def _render_patterns_expander(result, password: str) -> None:
    with st.expander("Motifs detectes"):
        if not result.pattern_matches:
            st.caption("Aucun motif detecte.")
            return
        retained_keys = {(m["start"], m["end"], m["type"]) for m in result.retained_matches}
        rows = []
        for m in result.pattern_matches:
            key = (m["start"], m["end"], m["type"])
            rows.append({
                "Segment": _segment_text(password, m),
                "Type": m["type"],
                "Retenu dans le score": "Oui" if key in retained_keys else "Non (chevauchement)",
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


# --- Expander axe 3 : OSINT ---------------------------------------------------

def _render_osint_expander(result, password: str, identity_provided: bool) -> None:
    if not identity_provided:
        return
    with st.expander("Exposition OSINT"):
        if not result.osint_matches:
            st.caption("Aucune correspondance trouvee avec les informations fournies.")
            return
        retained_keys = {(m["start"], m["end"], m["type"]) for m in result.retained_matches}
        rows = []
        for m in result.osint_matches:
            key = (m["start"], m["end"], m["type"])
            rows.append({
                "Segment": _segment_text(password, m),
                "Regle": m["data"].get("rule", "?"),
                "Retenu dans le score": "Oui" if key in retained_keys else "Non (chevauchement)",
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


# --- Expander axe 4 : temps de cassage ----------------------------------------

def _render_cracking_time_expander(result) -> None:
    with st.expander("Temps de cassage detaille"):
        cte = result.cracking_time_estimate
        algos = ["md5", "sha1", "sha256", "bcrypt"]
        applicable = cte["dictionary_attack"]["applicable"]

        chart_data = {
            "Brute force": [
                math.log10(max(cte["brute_force"][a]["seconds"], 1e-6)) for a in algos
            ]
        }
        if applicable:
            chart_data["Dictionnaire + regles"] = [
                math.log10(max(cte["dictionary_attack"][a]["seconds"], 1e-6))
                for a in algos
            ]

        st.caption("Temps de cassage (log10 secondes -- plus bas = plus rapide a casser)")
        st.bar_chart(pd.DataFrame(chart_data, index=[a.upper() for a in algos]))

        rows = []
        for a in algos:
            row = {"Algorithme": a.upper(), "Brute force": cte["brute_force"][a]["human_readable"]}
            if applicable:
                row["Dictionnaire + regles"] = cte["dictionary_attack"][a]["human_readable"]
            rows.append(row)
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

        if not applicable:
            st.caption(
                "Attaque dictionnaire+regles non applicable "
                "(aucun motif dictionnaire/OSINT retenu)."
            )


# --- Expander bonus : HIBP (a venir) ------------------------------------------

def _render_hibp_expander() -> None:
    with st.expander("Verification de fuite (a venir)"):
        st.caption("Fonctionnalite k-anonymat / API HIBP non encore implementee.")


# --- Point d'entree -----------------------------------------------------------

def render_result(result, password: str, identity_provided: bool) -> None:
    """Affiche le resultat complet. N'effectue AUCUN calcul -- lit uniquement
    les champs de `result` (AnalysisResult) et le mot de passe (pour le
    rendu textuel des segments, jamais log/print)."""
    _render_summary(result, password)
    st.divider()
    _render_entropy_expander(result, password)
    _render_patterns_expander(result, password)
    _render_osint_expander(result, password, identity_provided)
    _render_cracking_time_expander(result)
    _render_hibp_expander()