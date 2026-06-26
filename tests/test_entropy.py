"""
tests/test_entropy.py
Tests unitaires pour l'axe 1 (entropie theorique + ajustee).
A lancer depuis la racine du projet : pytest
"""

import math
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.entropy import (
    detect_charsets,
    alphabet_size,
    theoretical_entropy,
    calculate_segment_cost,
    greedy_segmentation,
    unmatched_segments,
    adjusted_entropy,
)


# --- detect_charsets / alphabet_size ----------------------------------------

def test_detect_charsets_lower_only():
    assert detect_charsets("abcd") == {"lower"}


def test_detect_charsets_mixed():
    assert detect_charsets("Ab1!") == {"lower", "upper", "digit", "symbol"}


def test_alphabet_size_matches_charset_table():
    assert alphabet_size({"lower"}) == 26
    assert alphabet_size({"lower", "digit"}) == 36
    assert alphabet_size({"lower", "upper", "digit", "symbol"}) == 95


# --- theoretical_entropy -----------------------------------------------------

def test_theoretical_entropy_empty_password():
    assert theoretical_entropy("") == 0.0


def test_theoretical_entropy_known_value():
    # 4 caracteres minuscules -> N=26
    expected = 4 * math.log2(26)
    assert math.isclose(theoretical_entropy("abcd"), expected)


def test_theoretical_entropy_single_char_class_size_one():
    # cas degenere : un seul caractere repete, mais la classe a une taille > 1
    # donc H_theo n'est pas nul (le modele ne sait pas qu'il est repete)
    assert theoretical_entropy("aaaa") > 0.0


# --- calculate_segment_cost ---------------------------------------------------

def test_segment_cost_dictionary():
    match = {"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 1}}
    assert calculate_segment_cost(match) == 0.0  # log2(1) = 0


def test_segment_cost_dictionary_rank_8():
    match = {"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 8}}
    assert math.isclose(calculate_segment_cost(match), 3.0)  # log2(8) = 3


def test_segment_cost_leet_dictionary_adds_substitution_bits():
    match = {
        "start": 0, "end": 8, "type": "leet_dictionary",
        "data": {"rank": 1, "substitution_count": 2},
    }
    assert calculate_segment_cost(match) == 2.0  # log2(1) + 2*1


def test_segment_cost_osint():
    match = {"start": 0, "end": 5, "type": "osint", "data": {"total_variant_count": 16}}
    assert math.isclose(calculate_segment_cost(match), 4.0)  # log2(16) = 4


def test_segment_cost_unknown_type_is_infinite():
    match = {"start": 0, "end": 3, "type": "ce_type_n_existe_pas", "data": {}}
    assert calculate_segment_cost(match) == float("inf")


# --- greedy_segmentation -------------------------------------------------------

def test_greedy_segmentation_picks_longest_on_overlap():
    matches = [
        {"start": 0, "end": 5, "type": "dictionary", "data": {"rank": 1}},
        {"start": 2, "end": 4, "type": "qwerty", "data": {"start_positions": 40, "branching_factor": 2}},
    ]
    retained = greedy_segmentation(matches)
    assert len(retained) == 1
    assert retained[0]["end"] - retained[0]["start"] == 5


def test_greedy_segmentation_keeps_non_overlapping_matches():
    matches = [
        {"start": 0, "end": 4, "type": "dictionary", "data": {"rank": 1}},
        {"start": 4, "end": 8, "type": "date", "data": {"date_space_size": 200}},
    ]
    retained = greedy_segmentation(matches)
    assert len(retained) == 2


# --- unmatched_segments ---------------------------------------------------------

def test_unmatched_segments_gap_in_middle():
    retained = [
        {"start": 0, "end": 3, "type": "dictionary", "data": {"rank": 1}},
        {"start": 7, "end": 10, "type": "date", "data": {"date_space_size": 200}},
    ]
    gaps = unmatched_segments(10, retained)
    assert gaps == [(3, 7)]


def test_unmatched_segments_no_gap_when_fully_covered():
    retained = [{"start": 0, "end": 10, "type": "dictionary", "data": {"rank": 1}}]
    gaps = unmatched_segments(10, retained)
    assert gaps == []


# --- adjusted_entropy (integration des sous-fonctions) -------------------------

def test_adjusted_entropy_no_matches_equals_theoretical():
    password = "kT9!mQ2xR"
    result = adjusted_entropy(password, [])
    assert math.isclose(result["h_adjusted"], result["h_theoretical"])


def test_adjusted_entropy_full_match_uses_only_segment_cost():
    password = "password"
    matches = [{"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 1}}]
    result = adjusted_entropy(password, matches)
    assert result["h_adjusted"] == 0.0  # rang 1 -> log2(1) = 0, aucun segment non matche


def test_adjusted_entropy_never_exceeds_theoretical_in_simple_case():
    # Verifie l'intuition de base : detecter un pattern ne doit jamais
    # AUGMENTER l'entropie par rapport au theorique, dans ce cas simple.
    password = "password1234"
    matches = [
        {"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 1}},
        {"start": 8, "end": 12, "type": "date", "data": {"date_space_size": 200}},
    ]
    result = adjusted_entropy(password, matches)
    assert result["h_adjusted"] <= result["h_theoretical"]


def test_unmatched_segment_uses_local_charset_not_global():
    # Regression test pour le bug corrige : un gap 100% chiffres alors que
    # le reste du mot de passe contient d'autres classes ne doit PAS etre
    # facture au tarif du charset global (cf. discussion sur N_local).
    password = "password12345678"
    matches = [{"start": 0, "end": 8, "type": "dictionary", "data": {"rank": 1}}]
    result = adjusted_entropy(password, matches)

    gap_info = result["unmatched_segments"][0]
    assert gap_info["alphabet_size"] == 10  # chiffres uniquement dans le gap
    expected_gap_cost = 8 * math.log2(10)
    assert math.isclose(gap_info["cost"], expected_gap_cost)