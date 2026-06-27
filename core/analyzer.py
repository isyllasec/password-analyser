"""Orchestrateur des 4 axes (analyzer.py).

Pipeline séquentiel (cf. decisions_projet.md section 5) :
1. patterns.py (axe 2) sur le mot de passe brut
2. osint.py (axe 3) si au moins un champ d'identité est fourni
3. entropy.py (axe 1) à partir des matchs combinés (patterns + osint)
4. cracking_time.py (axe 4) -- PAS ENCORE IMPLÉMENTÉ, champ laissé à None
5. hibp.py (bonus) -- PAS ENCORE IMPLÉMENTÉ, champ laissé à None

`analyzer.py` ne recalcule jamais rien lui-même : il appelle les fonctions des
modules core/ et assemble un objet résultat unique. `result_view.py` ne devra
jamais recalculer quoi que ce soit non plus.
"""
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from core.patterns import detect_all_patterns, load_word_ranks
from core.osint import detect_osint_patterns
from core.entropy import adjusted_entropy

# Chemin du dictionnaire de mots de passe courants (axe 2), relatif à la racine du projet.
WORD_RANKS_PATH = "data/common_passwords.txt"

# Cache paresseux : chargé au premier appel de analyze_password(), pas à chaque mot de passe testé.
_word_ranks_cache: Optional[dict] = None


def _get_default_word_ranks() -> dict:
    global _word_ranks_cache
    if _word_ranks_cache is None:
        _word_ranks_cache = load_word_ranks(WORD_RANKS_PATH)
    return _word_ranks_cache


@dataclass
class AnalysisResult:
    """Objet résultat unique produit par analyze_password().

    Les champs axe 4 et bonus sont déjà présents (Optional, défaut None) pour
    figer le schéma final dès maintenant et éviter de retoucher result_view.py
    quand ces modules seront prêts.
    """
    password_length: int
    pattern_matches: list = field(default_factory=list)   # axe 2
    osint_matches: list = field(default_factory=list)      # axe 3
    theoretical_entropy_bits: float = 0.0                  # axe 1
    adjusted_entropy_bits: float = 0.0                     # axe 1
    cracking_time_estimate: Optional[dict] = None          # axe 4 -- pas encore implémenté
    hibp_breached: Optional[bool] = None                   # bonus -- pas encore implémenté

    @property
    def all_matches(self) -> list:
        """Vue combinée patterns + osint, pratique pour le debug / l'affichage détaillé."""
        return self.pattern_matches + self.osint_matches


def analyze_password(
    password: str,
    prenom: Optional[str] = None,
    nom: Optional[str] = None,
    date_naissance: Optional[date] = None,
    word_ranks: Optional[dict] = None,
) -> AnalysisResult:
    """Exécute le pipeline complet sur un mot de passe et retourne l'objet résultat unique.

    Les champs d'identité (prenom/nom/date_naissance) sont optionnels : l'axe 3 (OSINT)
    se déclenche dès qu'au moins un est fourni, et est silencieusement ignoré sinon
    (cf. detect_osint_patterns, déjà géré par osint.py lui-même -- aucune logique de
    déclenchement à dupliquer ici).

    `word_ranks` est optionnel : si non fourni, le dictionnaire par défaut
    (data/common_passwords.txt) est chargé une seule fois et mis en cache. Permet
    d'injecter un dictionnaire de test dans tests/test_analyzer.py sans toucher au disque.
    """
    ranks = word_ranks if word_ranks is not None else _get_default_word_ranks()

    pattern_matches = detect_all_patterns(password, ranks)
    osint_matches = detect_osint_patterns(
        password, prenom=prenom, nom=nom, date_naissance=date_naissance
    )
    combined_matches = pattern_matches + osint_matches

    entropy_result = adjusted_entropy(password, combined_matches)

    return AnalysisResult(
        password_length=len(password),
        pattern_matches=pattern_matches,
        osint_matches=osint_matches,
        theoretical_entropy_bits=entropy_result["h_theoretical"],
        adjusted_entropy_bits=entropy_result["h_adjusted"],
    )