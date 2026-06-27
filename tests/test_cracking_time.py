import math

import pytest

from core.cracking_time import (
    _bcrypt_speed_hashes_per_sec,
    _format_duration,
    estimate_cracking_time,
)


# ---------- _format_duration ----------

@pytest.mark.parametrize(
    "seconds,expected_substring",
    [
        (0.3, "< 1 seconde"),
        (5, "secondes"),
        (90, "minutes"),
        (7200, "heures"),
        (2 * 86400, "jours"),
        (5 * 365 * 86400, "années"),
    ],
)
def test_format_duration_units(seconds, expected_substring):
    assert expected_substring in _format_duration(seconds)


def test_format_duration_large_scientific_notation():
    huge_seconds = 10**20
    result = _format_duration(huge_seconds)
    assert "e+" in result or "e" in result.lower()
    assert "années" in result


def test_format_duration_moderate_years_no_scientific_notation():
    # 50 000 ans : grand mais pas assez pour notation scientifique
    seconds = 50_000 * 365 * 86400
    result = _format_duration(seconds)
    assert "e+" not in result
    assert "années" in result


# ---------- bcrypt scaling ----------

def test_bcrypt_speed_cost5_matches_reference():
    assert _bcrypt_speed_hashes_per_sec(5) == pytest.approx(180_100)


def test_bcrypt_speed_cost12_is_128x_slower_than_cost5():
    speed5 = _bcrypt_speed_hashes_per_sec(5)
    speed12 = _bcrypt_speed_hashes_per_sec(12)
    assert speed5 / speed12 == pytest.approx(128)


# ---------- brute force ----------

def test_brute_force_uses_keyspace_over_two():
    h_adjusted = 20  # keyspace = 2**20
    result = estimate_cracking_time(h_adjusted, matches=[])
    expected_attempts = (2**20) / 2
    expected_seconds_md5 = expected_attempts / 160_000_000_000
    assert result["brute_force"]["md5"]["seconds"] == pytest.approx(
        expected_seconds_md5
    )


def test_brute_force_present_for_all_four_algos():
    result = estimate_cracking_time(30, matches=[])
    assert set(result["brute_force"].keys()) == {"md5", "sha1", "sha256", "bcrypt"}


# ---------- dictionary_attack : non applicable ----------

def test_dictionary_attack_not_applicable_without_trigger_match():
    matches = [{"start": 0, "end": 4, "type": "qwerty", "data": {}, "cost_bits": 5.0}]
    result = estimate_cracking_time(40, matches=matches)
    da = result["dictionary_attack"]
    assert da["applicable"] is False
    assert da["trigger_match_types"] == []
    assert da["md5"] is None
    assert da["bcrypt"] is None


def test_dictionary_attack_not_applicable_with_empty_matches():
    result = estimate_cracking_time(40, matches=[])
    assert result["dictionary_attack"]["applicable"] is False


# ---------- dictionary_attack : applicable, sélection du meilleur match ----------

def test_dictionary_attack_picks_lowest_cost_bits_match():
    # rang 10 -> cost_bits = log2(10) ; rang 1000 -> cost_bits = log2(1000)
    # le match "dictionary" (rang 10, moins coûteux) doit être retenu
    matches = [
        {
            "start": 0,
            "end": 4,
            "type": "dictionary",
            "data": {"rank": 10},
            "cost_bits": math.log2(10),
        },
        {
            "start": 4,
            "end": 8,
            "type": "osint",
            "data": {"rule": "find_firstname_matches"},
            "cost_bits": math.log2(1000),
        },
    ]
    result = estimate_cracking_time(40, matches=matches)
    da = result["dictionary_attack"]
    assert da["applicable"] is True
    assert da["trigger_match_types"] == ["dictionary", "osint"]

    expected_seconds_md5 = 10 / 160_000_000_000  # rang 10, pas de division par 2
    assert da["md5"]["seconds"] == pytest.approx(expected_seconds_md5)


def test_dictionary_attack_ignores_non_trigger_matches_when_picking_best():
    matches = [
        {
            "start": 0,
            "end": 4,
            "type": "qwerty",
            "data": {},
            "cost_bits": 1.0,  # très faible coût, mais type non déclencheur
        },
        {
            "start": 4,
            "end": 8,
            "type": "leet_dictionary",
            "data": {"rank": 50},
            "cost_bits": math.log2(50),
        },
    ]
    result = estimate_cracking_time(40, matches=matches)
    da = result["dictionary_attack"]
    assert da["applicable"] is True
    assert da["trigger_match_types"] == ["leet_dictionary"]
    expected_seconds_sha256 = 50 / 21_500_000_000
    assert da["sha256"]["seconds"] == pytest.approx(expected_seconds_sha256)


def test_dictionary_attack_custom_bcrypt_cost_propagates():
    matches = [
        {
            "start": 0,
            "end": 4,
            "type": "dictionary",
            "data": {"rank": 5},
            "cost_bits": math.log2(5),
        }
    ]
    result_cost5 = estimate_cracking_time(40, matches=matches, bcrypt_cost=5)
    result_cost12 = estimate_cracking_time(40, matches=matches, bcrypt_cost=12)
    # même rang, bcrypt plus lent à cost 12 -> temps plus long
    assert (
        result_cost12["dictionary_attack"]["bcrypt"]["seconds"]
        > result_cost5["dictionary_attack"]["bcrypt"]["seconds"]
    )