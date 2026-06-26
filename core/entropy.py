"""
core/entropy.py
Axe 1 : calcul de l'entropie theorique et de l'entropie ajustee.

Contrat d'entree attendu pour les matchs (produits par patterns.py et osint.py) :
    {
        "start": int,       # index inclusif de debut dans le mot de passe
        "end": int,         # index exclusif de fin (longueur = end - start)
        "type": str,        # "dictionary" | "leet_dictionary" | "qwerty" | "osint" | "date"
        "data": dict,       # informations specifiques au type (voir calculate_segment_cost)
    }

Decision de reference : decisions_projet.md, section 7
(segmentation gloutonne, pas de programmation dynamique).
"""

import math


# --- 1. Entropie theorique (force brute) -----------------------------------

CHARSET_SIZES = {
    "lower": 26,
    "upper": 26,
    "digit": 10,
    "symbol": 33,  # a ajuster selon le jeu de symboles vise
}


def detect_charsets(password: str) -> set:
    """Determine quelles classes de caracteres sont presentes."""
    charsets = set()
    if any(c.islower() for c in password):
        charsets.add("lower")
    if any(c.isupper() for c in password):
        charsets.add("upper")
    if any(c.isdigit() for c in password):
        charsets.add("digit")
    if any(not c.isalnum() for c in password):
        charsets.add("symbol")
    return charsets


def alphabet_size(charsets: set) -> int:
    return sum(CHARSET_SIZES[c] for c in charsets)


def theoretical_entropy(password: str) -> float:
    """H_theo = L x log2(N), N = taille de l'alphabet effectif (classes presentes)."""
    if not password:
        return 0.0
    n = alphabet_size(detect_charsets(password))
    if n <= 1:
        return 0.0
    return len(password) * math.log2(n)


# --- 2. Cout reel par segment matche ----------------------------------------

def calculate_segment_cost(match: dict) -> float:
    """
    Calcule le cout en bits d'un segment matche, selon son type.
    Table de couts a calibrer au fil des tests (journal de decisions, section 8).
    """
    match_type = match["type"]
    data = match.get("data", {})

    if match_type == "dictionary":
        rank = max(1, data.get("rank", 1))
        return math.log2(rank)

    if match_type == "leet_dictionary":
        rank = max(1, data.get("rank", 1))
        n_subs = data.get("substitution_count", 0)
        bits_per_sub = 1.0  # a calibrer
        return math.log2(rank) + n_subs * bits_per_sub

    if match_type == "qwerty":
        # a calculer dynamiquement depuis keyboard_layout.py plutot que figer en dur
        n_start = data.get("start_positions", 40)
        branching = data.get("branching_factor", 3.5)
        k = match["end"] - match["start"]
        if k <= 0:
            return 0.0
        return math.log2(n_start) + (k - 1) * math.log2(branching)

    if match_type == "osint":
        # Cout par REGLE (decisions_projet.md section 7), pas un total global
        variant_count = max(1, data.get("rule_variant_count", 1))
        return math.log2(variant_count)

    if match_type == "date":
        space_size = max(1, data.get("date_space_size", 1))
        return math.log2(space_size)

    # Type inconnu : pas de reduction d'entropie (comportement prudent par defaut)
    return float("inf")


# --- 3. Segmentation gloutonne ----------------------------------------------

def greedy_segmentation(matches: list) -> list:
    """
    Trie les matchs par longueur decroissante puis les place un par un,
    en rejetant tout match qui chevauche une zone deja occupee par
    un match plus long deja retenu (decision section 7 du journal).
    """
    sorted_matches = sorted(matches, key=lambda m: m["end"] - m["start"], reverse=True)
    occupied = []  # liste de (start, end) deja retenus
    retained = []

    for m in sorted_matches:
        overlaps = any(
            not (m["end"] <= o_start or m["start"] >= o_end)
            for o_start, o_end in occupied
        )
        if overlaps:
            continue
        occupied.append((m["start"], m["end"]))
        retained.append(m)

    return retained


def unmatched_segments(password_length: int, retained_matches: list) -> list:
    """Renvoie les intervalles [start, end) non couverts par un match retenu."""
    covered = sorted((m["start"], m["end"]) for m in retained_matches)
    gaps = []
    cursor = 0
    for start, end in covered:
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < password_length:
        gaps.append((cursor, password_length))
    return gaps


# --- 4. Entropie ajustee -----------------------------------------------------

def unmatched_cost(password: str, gaps: list) -> tuple:
    """
    Calcule le cout des segments non matches en utilisant le charset
    REELLEMENT present dans chaque segment (pas le charset global du mot
    de passe entier). N_local <= N_global toujours : reutiliser N_global
    surestimerait l'entropie d'un gap plus pauvre en classes que le reste
    du mot de passe (ex. un gap 100% chiffres alors que le mot de passe
    contient aussi des majuscules/symboles ailleurs).
    """
    total = 0.0
    breakdown = []
    for start, end in gaps:
        segment = password[start:end]
        local_n = alphabet_size(detect_charsets(segment))
        local_log2_n = math.log2(local_n) if local_n > 1 else 0.0
        cost = (end - start) * local_log2_n
        total += cost
        breakdown.append(
            {"start": start, "end": end, "alphabet_size": local_n, "cost": cost}
        )
    return total, breakdown


def adjusted_entropy(password: str, matches: list) -> dict:
    """
    Calcule l'entropie ajustee par segmentation gloutonne (decision section 7).

    Note : H_theo utilise le charset GLOBAL du mot de passe (definition
    standard de la force brute). H_ajustee, elle, recalcule le charset
    LOCALEMENT pour chaque segment non matche -- raffinement coherent avec
    l'esprit de l'option B (remplacer une estimation grossiere par le cout
    reel, segment par segment), voir decisions_projet.md section 7.

    Retourne un dict detaille, utile pour result_view.py (affichage du detail
    par segment dans l'expander "entropie").
    """
    global_n = alphabet_size(detect_charsets(password))
    global_log2_n = math.log2(global_n) if global_n > 1 else 0.0

    retained = greedy_segmentation(matches)
    retained_ids = {id(m) for m in retained}
    gaps = unmatched_segments(len(password), retained)

    matched_cost = sum(calculate_segment_cost(m) for m in retained)
    gaps_cost, gaps_breakdown = unmatched_cost(password, gaps)

    h_theo = len(password) * global_log2_n
    h_adjusted = max(0.0, matched_cost + gaps_cost)

    return {
        "h_theoretical": h_theo,
        "h_adjusted": h_adjusted,
        "retained_matches": retained,
        "discarded_matches": [m for m in matches if id(m) not in retained_ids],
        "unmatched_segments": gaps_breakdown,
        "alphabet_size": global_n,
    }