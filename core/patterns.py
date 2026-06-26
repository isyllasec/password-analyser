"""
core/patterns.py
Axe 2 : detection de motifs predictibles -- dictionnaire, leetspeak, qwerty, dates.

Produit une liste de "matchs" candidats, au format attendu par entropy.py :
    {
        "start": int,
        "end": int,
        "type": "dictionary" | "leet_dictionary" | "qwerty" | "date",
        "data": dict,
    }

Important : ce module ENUMERE les candidats, y compris ceux qui se
chevauchent. Le choix de la meilleure combinaison non chevauchante est
delegue a entropy.greedy_segmentation() (decision section 7 du journal).
Coherent avec analyzer.py qui appelle patterns -> osint -> entropy -> cracking_time.
"""

from data.keyboard_layout import ADJACENCY
from data.leetspeak_map import normalize_leetspeak


# --- Chargement de la liste de mots de passe courants -----------------------

def load_word_ranks(path: str) -> dict:
    """
    Charge la liste de mots de passe courants et construit un dict
    {mot_en_minuscule: rang}. Le rang = position dans le fichier (1 = le
    plus frequent), en ignorant les lignes vides et les commentaires (#).
    """
    word_ranks = {}
    rank = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            rank += 1
            word_ranks.setdefault(word.lower(), rank)
    return word_ranks


# --- Detection dictionnaire ---------------------------------------------------

def find_dictionary_matches(password: str, word_ranks: dict, min_length: int = 4) -> list:
    """
    Cherche toutes les sous-chaines du mot de passe qui correspondent
    exactement (insensible a la casse) a une entree de la liste.
    Complexite O(L^2) -- acceptable pour des mots de passe de longueur usuelle.
    """
    matches = []
    n = len(password)
    for start in range(n):
        for end in range(start + min_length, n + 1):
            substring = password[start:end].lower()
            if substring in word_ranks:
                matches.append({
                    "start": start,
                    "end": end,
                    "type": "dictionary",
                    "data": {"rank": word_ranks[substring]},
                })
    return matches


# --- Detection leetspeak -------------------------------------------------------

def find_leet_matches(password: str, word_ranks: dict, min_length: int = 4) -> list:
    """
    Cherche les sous-chaines qui, une fois normalisees (substitution
    leetspeak -> lettre canonique), correspondent a une entree de la liste.
    Ne remonte un match que si au moins une substitution a ete necessaire
    (sinon c'est deja capture par find_dictionary_matches, pas de doublon).
    """
    matches = []
    n = len(password)
    for start in range(n):
        for end in range(start + min_length, n + 1):
            substring = password[start:end]
            normalized, substitution_count = normalize_leetspeak(substring)
            if substitution_count == 0:
                continue
            if normalized in word_ranks:
                matches.append({
                    "start": start,
                    "end": end,
                    "type": "leet_dictionary",
                    "data": {
                        "rank": word_ranks[normalized],
                        "substitution_count": substitution_count,
                    },
                })
    return matches


# --- Detection qwerty -----------------------------------------------------------

def _compute_branching_factor(sequence: str) -> float:
    """
    Branchement moyen calcule dynamiquement depuis la vraie table d'adjacence
    (decision : pas de constante figee en dur, voir entropy.py).
    """
    transitions = sequence[1:]
    if not transitions:
        return 1.0
    degrees = [len(ADJACENCY.get(c, [])) for c in transitions]
    return sum(degrees) / len(degrees)


def find_qwerty_matches(password: str, min_length: int = 4) -> list:
    """
    Detecte les sequences de touches adjacentes (meme ligne de clavier
    uniquement -- decision de scope, voir module keyboard_layout.py).
    Recherche de runs maximaux : une fois un run identifie, on ne le
    fragmente pas en sous-runs plus courts.
    """
    matches = []
    lower = password.lower()
    n = len(lower)
    i = 0
    while i < n - 1:
        j = i
        while j + 1 < n and lower[j + 1] in ADJACENCY.get(lower[j], []):
            j += 1
        run_length = j - i + 1
        if run_length >= min_length:
            sequence = lower[i:j + 1]
            matches.append({
                "start": i,
                "end": j + 1,
                "type": "qwerty",
                "data": {
                    "start_positions": len(ADJACENCY),
                    "branching_factor": _compute_branching_factor(sequence),
                },
            })
            i = j + 1
        else:
            i += 1
    return matches


# --- Detection dates --------------------------------------------------------------

def _is_plausible_year(four_digits: str) -> bool:
    year = int(four_digits)
    return 1900 <= year <= 2099


def _is_plausible_ddmm_or_mmdd(four_digits: str) -> bool:
    a, b = int(four_digits[:2]), int(four_digits[2:])
    ddmm = 1 <= a <= 31 and 1 <= b <= 12
    mmdd = 1 <= a <= 12 and 1 <= b <= 31
    return ddmm or mmdd


def find_date_matches(password: str) -> list:
    """
    Detecte les motifs de 4 chiffres plausibles comme date (annee 1900-2099,
    ou jour/mois). Decision de scope : pas de dates completes 6-8 chiffres
    en MVP (voir notes de scope, a developper en amelioration possible).
    En cas d'ambiguite (le motif est a la fois une annee ET un jour/mois
    plausible), on retient l'espace le plus petit -- hypothese prudente,
    qui ne surestime pas la difficulte pour l'attaquant.
    """
    matches = []
    n = len(password)
    YEAR_SPACE = 200       # 1900-2099
    DDMM_SPACE = 31 * 12   # approximation jour x mois

    for start in range(n - 3):
        segment = password[start:start + 4]
        if not segment.isdigit():
            continue

        candidate_spaces = []
        if _is_plausible_year(segment):
            candidate_spaces.append(YEAR_SPACE)
        if _is_plausible_ddmm_or_mmdd(segment):
            candidate_spaces.append(DDMM_SPACE)

        if candidate_spaces:
            matches.append({
                "start": start,
                "end": start + 4,
                "type": "date",
                "data": {"date_space_size": min(candidate_spaces)},
            })
    return matches


# --- Orchestrateur axe 2 -----------------------------------------------------------

def detect_all_patterns(password: str, word_ranks: dict) -> list:
    """
    Point d'entree appele par analyzer.py. Combine les 4 sous-detections
    en une seule liste de matchs candidats (chevauchements possibles,
    resolus plus tard par entropy.greedy_segmentation).
    """
    matches = []
    matches.extend(find_dictionary_matches(password, word_ranks))
    matches.extend(find_leet_matches(password, word_ranks))
    matches.extend(find_qwerty_matches(password))
    matches.extend(find_date_matches(password))
    return matches