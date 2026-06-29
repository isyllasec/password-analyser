"""
app.py
Point d'entree Streamlit -- orchestration UI uniquement
(cf. decisions_projet.md section 1). Aucune logique metier ici : tout
passe par core/analyzer.py. Aucun log/print du mot de passe.
"""
from datetime import date

import streamlit as st

from core.analyzer import analyze_password
from ui.result_view import render_result

st.set_page_config(page_title="Analyseur de mots de passe", page_icon=":lock:")
st.title("Analyseur de mots de passe")

password = st.text_input("Mot de passe a analyser", type="password")

with st.expander("Tester l'exposition a des infos personnelles (optionnel)"):
    prenom = st.text_input("Prenom", value="")
    nom = st.text_input("Nom", value="")
    date_naissance = st.date_input(
        "Date de naissance",
        value=None,
        min_value=date(1920, 1, 1),
        max_value=date.today(),
    )

identity_provided = bool(prenom or nom or date_naissance)

if password != st.session_state.get("last_password"):
    st.session_state.hibp_breached = None
    st.session_state.last_password = password

if password:
    if st.button("Verifier les fuites connues (HIBP)"):
        checked = analyze_password(
            password, prenom=prenom or None, nom=nom or None,
            date_naissance=date_naissance, check_hibp=True,
        )
        st.session_state.hibp_breached = checked.hibp_breached

    result = analyze_password(
        password,
        prenom=prenom or None,
        nom=nom or None,
        date_naissance=date_naissance,
        word_ranks=None,
    )
    result.hibp_breached = st.session_state.get("hibp_breached")
    render_result(result, password, identity_provided)
else:
    st.caption("Saisissez un mot de passe pour lancer l'analyse.")