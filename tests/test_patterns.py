"""
tests/test_patterns.py
Tests unitaires pour l'axe 2 (detection de patterns).
A lancer depuis la racine du projet : pytest
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.patterns import (
    load_word_ranks,
    find_dictionary_matches,
    find_leet_matches,
    find_qwerty_matches,
    find_date_matches,
    detect_all_patterns,
)


# Liste de test isolee, independante de data/common_passwords.txt
# (pour ne pas que des tests cassent si le vrai fichier change de contenu/ordre)
WORD_RANKS = {
    "password": 1,
    "qwerty": 5,
    "letmein": 10,
    "dragon": 20,
}


# --- load_word_ranks -----------------------------------------------------------

def test_load_word_ranks_assigns_rank_by_line_order(tmp_path):
    test_file = tmp_path / "test_list.txt"
    test_file.write_text("# commentaire a ignorer\npassword\n\nqwerty\nletmein\n")

    word_ranks = load_word_ranks(str(test_file))

    assert word_ranks == {"password": 1, "qwerty": 2, "letmein": 3}


def test_load_word_ranks_is_case_insensitive_on_load(tmp_path):
    test_file = tmp_path / "test_list.txt"
    test_file.write_text("Password\n")

    word_ranks = load_word_ranks(str(test_file))

    assert "password" in word_ranks


# --- find_dictionary_matches ---------------------------------------------------

def test_find_dictionary_matches_simple_case():
    matches = find_dictionary_matches("password", WORD_RANKS)
    assert {"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 1}} in matches


def test_find_dictionary_matches_case_insensitive():
    matches = find_dictionary_matches("PaSSwoRD", WORD_RANKS)
    assert any(m["data"]["rank"] == 1 for m in matches)


def test_find_dictionary_matches_respects_min_length():
    # "qw" ne doit jamais matcher meme s'il existe une entree "qwerty"
    matches = find_dictionary_matches("qw12", WORD_RANKS, min_length=4)
    assert matches == []


def test_find_dictionary_matches_no_match_returns_empty_list():
    matches = find_dictionary_matches("xyzz1234", WORD_RANKS)
    assert matches == []


# --- find_leet_matches -----------------------------------------------------------

def test_find_leet_matches_detects_substitution():
    matches = find_leet_matches("p4ssw0rd", WORD_RANKS)
    assert len(matches) == 1
    assert matches[0]["type"] == "leet_dictionary"
    assert matches[0]["data"]["rank"] == 1
    assert matches[0]["data"]["substitution_count"] == 2  # '4' et '0'


def test_find_leet_matches_no_duplicate_when_no_substitution_needed():
    # "password" est deja un match dictionnaire pur, sans aucun caractere
    # leetspeak -- ne doit PAS apparaitre dans find_leet_matches (substitution_count=0)
    matches = find_leet_matches("password", WORD_RANKS)
    assert matches == []


# --- find_qwerty_matches -----------------------------------------------------------

def test_find_qwerty_matches_detects_horizontal_run():
    matches = find_qwerty_matches("qwer", min_length=4)
    assert len(matches) == 1
    assert matches[0]["start"] == 0
    assert matches[0]["end"] == 4


def test_find_qwerty_matches_digit_row():
    matches = find_qwerty_matches("1234", min_length=4)
    assert len(matches) == 1


def test_find_qwerty_matches_below_min_length_not_detected():
    matches = find_qwerty_matches("qwe", min_length=4)
    assert matches == []


def test_find_qwerty_matches_non_adjacent_chars_not_detected():
    # 'a' et 'b' ne sont pas sur la meme ligne de clavier -> pas de run
    matches = find_qwerty_matches("abcd", min_length=4)
    assert matches == []


def test_find_qwerty_matches_branching_factor_is_computed_dynamically():
    matches = find_qwerty_matches("qwer", min_length=4)
    assert matches[0]["data"]["branching_factor"] > 0
    assert matches[0]["data"]["start_positions"] > 0


# --- find_date_matches -----------------------------------------------------------

def test_find_date_matches_detects_plausible_year():
    matches = find_date_matches("x1999x")
    assert any(m["start"] == 1 and m["end"] == 5 for m in matches)


def test_find_date_matches_detects_ddmm():
    matches = find_date_matches("0112")
    assert len(matches) == 1
    assert matches[0]["data"]["date_space_size"] == 31 * 12


def test_find_date_matches_rejects_implausible_digits():
    # 1234 : ni annee plausible (hors 1900-2099), ni jour/mois valide (34 > 31 et > 12)
    matches = find_date_matches("1234")
    assert matches == []


def test_find_date_matches_ignores_non_digit_segments():
    matches = find_date_matches("abcd")
    assert matches == []


# --- detect_all_patterns (integration) ---------------------------------------------

def test_detect_all_patterns_combines_all_detectors():
    # mot de passe avec un match dictionnaire ET un motif qwerty
    password = "passwordqwer"
    matches = detect_all_patterns(password, WORD_RANKS)
    types_found = {m["type"] for m in matches}
    assert "dictionary" in types_found
    assert "qwerty" in types_found


def test_detect_all_patterns_empty_for_random_password():
    # mot de passe sans aucun pattern reconnaissable par cette liste de test
    password = "xK9#mZ4vQ"
    matches = detect_all_patterns(password, WORD_RANKS)
    assert matches == []


# --- Cas limites -----------------------------------------------------------------

def test_find_dictionary_matches_empty_password_no_crash():
    assert find_dictionary_matches("", WORD_RANKS) == []


def test_find_leet_matches_empty_password_no_crash():
    assert find_leet_matches("", WORD_RANKS) == []


def test_find_qwerty_matches_empty_password_no_crash():
    assert find_qwerty_matches("", min_length=4) == []


def test_find_date_matches_empty_password_no_crash():
    assert find_date_matches("") == []


def test_detect_all_patterns_empty_password_no_crash():
    assert detect_all_patterns("", WORD_RANKS) == []


def test_find_qwerty_matches_single_character_no_crash():
    # Un seul caractere : aucune transition possible, ne doit pas planter
    # sur l'acces a l'index suivant.
    assert find_qwerty_matches("q", min_length=4) == []


def test_find_date_matches_password_shorter_than_four_chars_no_crash():
    # range(n - 3) avec n < 3 doit rester une plage vide, pas une erreur.
    assert find_date_matches("12") == []


def test_find_dictionary_matches_unicode_no_crash_and_no_false_positive():
    # Un caractere accentue casse l'egalite exacte avec l'entree "password"
    # du dictionnaire -- comportement attendu (pas de detection floue/fuzzy
    # en MVP), mais ca ne doit pas planter.
    matches = find_dictionary_matches("pâssword", WORD_RANKS)
    assert matches == []


def test_find_leet_matches_unicode_no_crash():
    # normalize_leetspeak doit gerer un caractere unicode sans lever d'erreur
    # (meme s'il n'est pas dans la table de substitution leetspeak).
    matches = find_leet_matches("pâssw0rd", WORD_RANKS)
    assert isinstance(matches, list)  # ne plante pas, peu importe le contenu


def test_detect_all_patterns_unicode_password_no_crash():
    password = "pâssw0rd1999"
    matches = detect_all_patterns(password, WORD_RANKS)
    assert isinstance(matches, list)