"""
Test d'INTÉGRATION réel de analyze_password() : core/entropy.py, core/patterns.py,
core/osint.py, core/cracking_time.py sont les vrais modules du projet (copiés
depuis la base de connaissances). Seules data/keyboard_layout.py,
data/leetspeak_map.py et data/common_passwords.txt sont des fixtures de test
(stand-ins explicites, pas les vraies données de prod -- voir commentaires
dans ces fichiers). La logique d'assemblage testée ici est donc réelle.
"""
from datetime import date

import pytest

from core.analyzer import AnalysisResult, analyze_password


# ---------- Cas de base : structure et types ----------

def test_returns_analysis_result_with_all_fields_populated():
    result = analyze_password("password123")
    assert isinstance(result, AnalysisResult)
    assert isinstance(result.theoretical_entropy_bits, float)
    assert isinstance(result.adjusted_entropy_bits, float)
    assert isinstance(result.retained_matches, list)
    assert isinstance(result.discarded_matches, list)
    assert isinstance(result.unmatched_segments, list)
    assert isinstance(result.cracking_time_estimate, dict)
    assert result.hibp_breached is None  # bonus pas encore implémenté


def test_all_matches_property_combines_pattern_and_osint():
    result = analyze_password("jean1995", prenom="Jean")
    assert result.all_matches == result.pattern_matches + result.osint_matches


# ---------- Mot de passe vide (cas testé manuellement avant, formalisé ici) ----------

def test_empty_password_does_not_crash():
    result = analyze_password("")
    assert result.password_length == 0
    assert result.theoretical_entropy_bits == 0.0
    assert result.adjusted_entropy_bits == 0.0
    assert result.cracking_time_estimate["dictionary_attack"]["applicable"] is False
    # brute force : keyspace = 2**0 = 1, attente quasi nulle, ne doit pas lever d'exception
    assert "md5" in result.cracking_time_estimate["brute_force"]


# ---------- Mot de passe faible (dictionnaire) ----------

def test_weak_dictionary_password_triggers_dictionary_attack():
    # word_ranks injecté : déterministe, indépendant du contenu réel ou
    # factice de data/common_passwords.txt (voir correction post test123).
    custom_ranks = {"password123": 1}
    result = analyze_password("password123", word_ranks=custom_ranks)
    assert any(m["type"] == "dictionary" for m in result.retained_matches)
    da = result.cracking_time_estimate["dictionary_attack"]
    assert da["applicable"] is True
    assert "dictionary" in da["trigger_match_types"]
    # rang connu et faible -> cassage quasi instantané en MD5
    assert da["md5"]["seconds"] < 1


def test_test123_pattern_detected_and_cracking_time_present():
    # CORRECTIF : la version précédente appelait analyze_password("test123")
    # avec le dictionnaire par défaut et supposait un match, ce qui ne
    # dépendait que d'une coïncidence de mon fixture de test (qui contenait
    # littéralement "test123") -- pas une garantie du vrai dictionnaire.
    # word_ranks injecté ici pour rendre le test déterministe.
    custom_ranks = {"test123": 5}
    result = analyze_password("test123", word_ranks=custom_ranks)
    assert len(result.retained_matches) >= 1
    assert result.cracking_time_estimate is not None


def test_default_dictionary_smoke_test_no_crash():
    # Smoke test sur le VRAI dictionnaire par défaut (pas injecté) : ne
    # vérifie aucun contenu spécifique (dépendrait du fichier réel), juste
    # que le pipeline complet s'exécute sans erreur, conforme à ce qui avait
    # été validé manuellement avant ce test formel.
    for pwd in ("test123", "password1234", "qwerty", "Tr0ub4dor&3"):
        result = analyze_password(pwd)
        assert isinstance(result.retained_matches, list)
        assert result.cracking_time_estimate is not None


# ---------- Axe 3 : OSINT déclenché avec au moins un champ ----------

def test_osint_triggered_with_firstname_only():
    result = analyze_password("jean1995", prenom="Jean")
    assert len(result.osint_matches) > 0
    assert any(m["type"] == "osint" for m in result.osint_matches)


def test_osint_not_triggered_without_identity_fields():
    result = analyze_password("randompass99")
    assert result.osint_matches == []


def test_osint_with_full_identity_does_not_crash():
    result = analyze_password(
        "DupontJean1995",
        prenom="Jean",
        nom="Dupont",
        date_naissance=date(1995, 3, 14),
    )
    assert isinstance(result, AnalysisResult)
    assert result.cracking_time_estimate is not None


# ---------- Cohérence axe 1 -> axe 4 ----------

def test_cracking_time_dictionary_attack_uses_lowest_cost_retained_match():
    result = analyze_password("password123")
    retained_dict_or_osint = [
        m
        for m in result.retained_matches
        if m["type"] in {"dictionary", "leet_dictionary", "osint"}
    ]
    if retained_dict_or_osint:
        best = min(retained_dict_or_osint, key=lambda m: m["cost_bits"])
        expected_rank = 2 ** best["cost_bits"]
        actual_seconds = result.cracking_time_estimate["dictionary_attack"]["md5"][
            "seconds"
        ]
        expected_seconds = expected_rank / 160_000_000_000
        assert actual_seconds == pytest.approx(expected_seconds)


def test_strong_random_password_no_dictionary_attack():
    # Chaîne aléatoire peu probable de matcher le dictionnaire/qwerty/dates/osint
    result = analyze_password("xK9#mQ2$vL7&wZ4")
    assert result.cracking_time_estimate["dictionary_attack"]["applicable"] is False
    # Mais le brute force doit toujours être renseigné, basé sur h_adjusted
    bf = result.cracking_time_estimate["brute_force"]
    assert bf["bcrypt"]["seconds"] > bf["md5"]["seconds"]  # bcrypt toujours plus lent


# ---------- word_ranks injectable pour tests isolés ----------

def test_custom_word_ranks_override_default():
    custom_ranks = {"motdepasse": 1}
    result = analyze_password("motdepasse", word_ranks=custom_ranks)
    assert any(
        m["type"] == "dictionary" and m["data"]["rank"] == 1
        for m in result.pattern_matches
    )