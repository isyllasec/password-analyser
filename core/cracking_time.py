"""
Axe 4 : estimation du temps de cassage réel.

Hypothèses actées (voir decisions_projet.md, section 8) :
- Scénario exclusivement offline (attaque post-fuite de base de hashs).
- GPU de référence unique : NVIDIA RTX 4090, vitesses issues de benchmarks
  hashcat publiés (sources multiples concordantes).
- Brute force : cas moyen (keyspace / 2), base = h_adjusted (axe 1).
- Dictionnaire+règles : applicable seulement si au moins un match retenu
  (axe 1) est de type "dictionary", "leet_dictionary" ou "osint". Le temps
  est dérivé du match retenu le moins coûteux en bits parmi ceux-là.
  Pas de division par 2 : cost_bits encode un rang/position connu
  (log2(r)), pas un espace de recherche flou.
"""

from __future__ import annotations

# Vitesses de référence (hashes/seconde), GPU unique RTX 4090,
# sources : benchmarks hashcat publiés (modes 0, 100, 1400).
GPU_SPEEDS_HASHES_PER_SEC = {
    "md5": 160_000_000_000,       # ~160 GH/s
    "sha1": 50_000_000_000,       # ~50 GH/s
    "sha256": 21_500_000_000,     # ~21.5 GH/s
}

# bcrypt : vitesse de référence au cost factor 5 (baseline hashcat),
# mise à l'échelle ensuite selon le cost factor demandé.
_BCRYPT_COST5_SPEED_H_PER_SEC = 180_100  # ~180.1 kH/s, RTX 4090, cost=5

# Types de matches déclenchant l'attaque dictionnaire+règles.
DICTIONARY_TRIGGER_TYPES = {"dictionary", "leet_dictionary", "osint"}

_SECOND = 1
_MINUTE = 60
_HOUR = 3600
_DAY = 86400
_YEAR = 365 * _DAY
_CENTURY = 100 * _YEAR


def _bcrypt_speed_hashes_per_sec(cost: int) -> float:
    """Vitesse bcrypt mise à l'échelle depuis la référence cost=5."""
    return _BCRYPT_COST5_SPEED_H_PER_SEC / (2 ** (cost - 5))


def _format_duration(seconds: float) -> str:
    """Convertit une durée en secondes en chaîne lisible (français)."""
    if seconds < _SECOND:
        return "< 1 seconde"
    if seconds < _MINUTE:
        return f"{seconds:.0f} secondes"
    if seconds < _HOUR:
        return f"{seconds / _MINUTE:.1f} minutes"
    if seconds < _DAY:
        return f"{seconds / _HOUR:.1f} heures"
    if seconds < _YEAR:
        return f"{seconds / _DAY:.1f} jours"
    if seconds < _CENTURY:
        return f"{seconds / _YEAR:.1f} années"

    years = seconds / _YEAR
    if years < 1_000_000:
        return f"{years:,.0f} années".replace(",", " ")
    return f"{years:.2e} années"


def _time_for_attempts(attempts: float, speed: float) -> dict:
    seconds = attempts / speed
    return {"seconds": seconds, "human_readable": _format_duration(seconds)}


def _speeds_for_cost(bcrypt_cost: int) -> dict:
    speeds = dict(GPU_SPEEDS_HASHES_PER_SEC)
    speeds["bcrypt"] = _bcrypt_speed_hashes_per_sec(bcrypt_cost)
    return speeds


def estimate_cracking_time(
    h_adjusted: float,
    matches: list[dict],
    *,
    bcrypt_cost: int = 12,
) -> dict:
    """
    Estime le temps de cassage offline pour 4 algorithmes de hash,
    selon deux méthodes d'attaque : brute force et dictionnaire+règles.

    Args:
        h_adjusted: entropie ajustée en bits (axe 1, analyzer.py).
        matches: retained_matches produit par adjusted_entropy (axe 1),
            chaque élément portant {"start", "end", "type", "data", "cost_bits"}.
        bcrypt_cost: cost factor bcrypt (défaut 12, recommandation actuelle
            pour un système de production ; voir decisions_projet.md).

    Returns:
        {
            "brute_force": {"md5": {...}, "sha1": {...}, "sha256": {...}, "bcrypt": {...}},
            "dictionary_attack": {
                "applicable": bool,
                "trigger_match_types": list[str],
                "md5": {...} | None, "sha1": {...} | None,
                "sha256": {...} | None, "bcrypt": {...} | None,
            },
        }
    """
    speeds = _speeds_for_cost(bcrypt_cost)

    # --- Brute force (cas moyen) ---
    keyspace = 2 ** h_adjusted
    bf_attempts = keyspace / 2
    brute_force = {
        algo: _time_for_attempts(bf_attempts, speed)
        for algo, speed in speeds.items()
    }

    # --- Dictionnaire + règles ---
    candidate_matches = [
        m for m in matches if m.get("type") in DICTIONARY_TRIGGER_TYPES
    ]

    if not candidate_matches:
        dictionary_attack = {
            "applicable": False,
            "trigger_match_types": [],
            "md5": None,
            "sha1": None,
            "sha256": None,
            "bcrypt": None,
        }
    else:
        best_match = min(candidate_matches, key=lambda m: m["cost_bits"])
        rank = 2 ** best_match["cost_bits"]
        dictionary_attack = {
            "applicable": True,
            "trigger_match_types": sorted(
                {m["type"] for m in candidate_matches}
            ),
        }
        for algo, speed in speeds.items():
            dictionary_attack[algo] = _time_for_attempts(rank, speed)

    return {
        "brute_force": brute_force,
        "dictionary_attack": dictionary_attack,
    }