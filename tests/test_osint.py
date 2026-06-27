"""Tests pour core/osint.py (axe 3 : génération de variantes OSINT type CUPP)."""
from datetime import date

import pytest

from core.osint import (
    normalize_text,
    build_case_variants,
    build_fullname_variants,
    extract_date_parts,
    build_birthdate_variants,
    build_name_date_variants,
    find_firstname_matches,
    find_lastname_matches,
    find_fullname_matches,
    find_birthdate_matches,
    find_name_date_matches,
    detect_osint_patterns,
)


def test_normalize_text_deaccentue():
    assert normalize_text("Éric") == "Eric"
    assert normalize_text("François") == "Francois"


def test_normalize_text_vide_ou_none():
    assert normalize_text("") == ""
    assert normalize_text(None) == ""


def test_normalize_text_sans_accent_inchange():
    assert normalize_text("Jean") == "Jean"


def test_build_case_variants_contenu_et_compte():
    variants = build_case_variants("Jean")
    assert len(variants) == 4
    assert variants == ["jean", "Jean", "JEAN", "naej"]


def test_build_case_variants_deaccentue_avant_casse():
    variants = build_case_variants("Éric")
    assert variants == ["eric", "Eric", "ERIC", "cire"]


def test_build_case_variants_none_ou_vide():
    assert build_case_variants(None) == []
    assert build_case_variants("") == []


def test_build_case_variants_chaine_un_caractere():
    variants = build_case_variants("a")
    assert len(variants) == 4


def test_build_fullname_variants_compte_et_ordres():
    variants = build_fullname_variants("Jean", "Dupont")
    assert len(variants) == 8
    assert "jeandupont" in variants
    assert "dupontjean" in variants
    assert "JeanDupont" in variants
    assert "DupontJean" in variants


def test_build_fullname_variants_champ_manquant():
    assert build_fullname_variants("Jean", None) == []
    assert build_fullname_variants(None, "Dupont") == []
    assert build_fullname_variants("", "Dupont") == []
    assert build_fullname_variants(None, None) == []


def test_extract_date_parts_formats():
    parts = extract_date_parts(date(1995, 3, 14))
    assert parts == {"YYYY": "1995", "YY": "95", "DDMM": "1403", "MMDD": "0314"}


def test_extract_date_parts_none():
    assert extract_date_parts(None) == {}


def test_extract_date_parts_jour_mois_a_un_chiffre_padding():
    parts = extract_date_parts(date(2001, 1, 5))
    assert parts == {"YYYY": "2001", "YY": "01", "DDMM": "0501", "MMDD": "0105"}


def test_build_birthdate_variants_compte():
    variants = build_birthdate_variants(date(1995, 3, 14))
    assert len(variants) == 4
    assert set(variants) == {"1995", "95", "1403", "0314"}


def test_build_birthdate_variants_none():
    assert build_birthdate_variants(None) == []


def test_build_name_date_variants_deux_noms_compte_huit():
    variants = build_name_date_variants("Jean", "Dupont", date(1995, 3, 14))
    assert len(variants) == 8
    assert "jean1995" in variants
    assert "1995jean" in variants
    assert "dupont95" in variants
    assert "95dupont" in variants


def test_build_name_date_variants_un_seul_nom_compte_quatre():
    variants = build_name_date_variants("Jean", None, date(1995, 3, 14))
    assert len(variants) == 4
    assert set(variants) == {"jean1995", "1995jean", "jean95", "95jean"}


def test_build_name_date_variants_aucune_date():
    assert build_name_date_variants("Jean", "Dupont", None) == []


def test_build_name_date_variants_aucun_nom():
    assert build_name_date_variants(None, None, date(1995, 3, 14)) == []


def _assert_match_format(match, expected_type="osint"):
    assert set(match.keys()) == {"start", "end", "type", "data"}
    assert isinstance(match["start"], int)
    assert isinstance(match["end"], int)
    assert match["start"] < match["end"]
    assert match["type"] == expected_type
    assert "rule_variant_count" in match["data"]
    assert "rule" in match["data"]


def test_find_firstname_matches_trouve_et_format():
    matches = find_firstname_matches("xxjeanxx", "Jean")
    assert len(matches) == 1
    _assert_match_format(matches[0])
    assert matches[0]["start"] == 2
    assert matches[0]["end"] == 6
    assert matches[0]["data"]["rule_variant_count"] == 4
    assert matches[0]["data"]["rule"] == "firstname"


def test_find_firstname_matches_aucune_correspondance():
    assert find_firstname_matches("xkpqrz9", "Jean") == []


def test_find_firstname_matches_champ_absent():
    assert find_firstname_matches("jean123", None) == []


def test_find_lastname_matches_trouve():
    matches = find_lastname_matches("dupont99", "Dupont")
    assert len(matches) == 1
    assert matches[0]["data"]["rule"] == "lastname"
    assert matches[0]["data"]["rule_variant_count"] == 4


def test_find_fullname_matches_trouve_et_compte():
    matches = find_fullname_matches("jeandupont", "Jean", "Dupont")
    assert len(matches) >= 1
    assert all(m["data"]["rule_variant_count"] == 8 for m in matches)
    assert all(m["data"]["rule"] == "fullname" for m in matches)


def test_find_fullname_matches_champ_manquant_retourne_vide():
    assert find_fullname_matches("jeandupont", "Jean", None) == []


def test_find_birthdate_matches_trouve():
    # "1995" contient "95" comme sous-chaîne -> 2 matchs bruts attendus (YYYY et YY).
    # La segmentation gloutonne d'entropy.py choisira le plus long ; osint.py ne déduplique pas.
    matches = find_birthdate_matches("pwd1995x", date(1995, 3, 14))
    assert len(matches) == 2
    starts_ends = {(m["start"], m["end"]) for m in matches}
    assert (3, 7) in starts_ends  # "1995"
    assert (5, 7) in starts_ends  # "95"
    assert all(m["data"]["rule_variant_count"] == 4 for m in matches)
    assert all(m["data"]["rule"] == "birthdate" for m in matches)


def test_find_birthdate_matches_aucune_date():
    assert find_birthdate_matches("pwd1995x", None) == []


def test_find_name_date_matches_trouve():
    matches = find_name_date_matches("jean1995", "Jean", "Dupont", date(1995, 3, 14))
    assert len(matches) >= 1
    assert any(m["data"]["rule"] == "name_date" for m in matches)


def test_find_matches_occurrences_multiples():
    matches = find_firstname_matches("jeanXjean", "Jean")
    assert len(matches) == 2
    assert matches[0]["start"] == 0
    assert matches[1]["start"] == 5


def test_find_matches_variante_trop_courte_ignoree():
    matches = find_firstname_matches("xaxax", "A")
    assert matches == []


def test_detect_osint_patterns_aucun_champ_retourne_vide():
    assert detect_osint_patterns("whatever123") == []
    assert detect_osint_patterns("whatever123", prenom=None, nom=None, date_naissance=None) == []


def test_detect_osint_patterns_un_seul_champ_prenom():
    matches = detect_osint_patterns("xjeanx", prenom="Jean")
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert rules_declenchees == {"firstname"}


def test_detect_osint_patterns_un_seul_champ_nom():
    matches = detect_osint_patterns("xdupontx", nom="Dupont")
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert rules_declenchees == {"lastname"}


def test_detect_osint_patterns_un_seul_champ_date():
    matches = detect_osint_patterns("x1995x", date_naissance=date(1995, 3, 14))
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert rules_declenchees == {"birthdate"}


def test_detect_osint_patterns_deux_champs_prenom_nom():
    matches = detect_osint_patterns("jeandupont", prenom="Jean", nom="Dupont")
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert "birthdate" not in rules_declenchees
    assert "name_date" not in rules_declenchees
    assert "fullname" in rules_declenchees


def test_detect_osint_patterns_deux_champs_prenom_date():
    matches = detect_osint_patterns("jean1995", prenom="Jean", date_naissance=date(1995, 3, 14))
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert "lastname" not in rules_declenchees
    assert "fullname" not in rules_declenchees
    assert "name_date" in rules_declenchees


def test_detect_osint_patterns_trois_champs_complets():
    matches = detect_osint_patterns(
        "jeandupont1995",
        prenom="Jean",
        nom="Dupont",
        date_naissance=date(1995, 3, 14),
    )
    rules_declenchees = {m["data"]["rule"] for m in matches}
    assert rules_declenchees == {"firstname", "lastname", "fullname", "birthdate", "name_date"}


def test_detect_osint_patterns_mot_de_passe_sans_correspondance():
    matches = detect_osint_patterns(
        "xKp9!qRzL2",
        prenom="Jean",
        nom="Dupont",
        date_naissance=date(1995, 3, 14),
    )
    assert matches == []


def test_detect_osint_patterns_tous_les_matchs_au_bon_format():
    matches = detect_osint_patterns(
        "jeandupont1995",
        prenom="Jean",
        nom="Dupont",
        date_naissance=date(1995, 3, 14),
    )
    assert len(matches) > 0
    for m in matches:
        _assert_match_format(m)


def test_detect_osint_patterns_mot_de_passe_vide():
    assert detect_osint_patterns("", prenom="Jean", nom="Dupont", date_naissance=date(1995, 3, 14)) == []


def test_detect_osint_patterns_prenom_avec_accent_matche_version_deaccentuee():
    matches = detect_osint_patterns("xericx", prenom="Éric")
    assert any(m["data"]["rule"] == "firstname" for m in matches)


def test_detect_osint_patterns_unicode_non_latin_ne_plante_pas():
    matches = detect_osint_patterns("пароль123", prenom="Jean", nom="Dupont", date_naissance=date(1995, 3, 14))
    assert isinstance(matches, list)