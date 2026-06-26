"""
data/leetspeak_map.py
Table de substitution leetspeak -> lettre d'origine.

Decision : une seule substitution canonique par caractere (ex. '1' -> 'i'
uniquement, pas 'l' en alternative). Simplification deliberee : gerer
plusieurs interpretations possibles par caractere demanderait de tester
plusieurs normalisations candidates par segment, hors scope du projet.
"""

LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "+": "t",
    "|": "l",
    "!": "i",
}


def normalize_leetspeak(segment: str) -> tuple:
    """
    Remplace chaque caractere leetspeak connu par sa lettre canonique.
    Renvoie (chaine_normalisee, nombre_de_substitutions_effectuees).
    """
    normalized_chars = []
    substitution_count = 0
    for char in segment:
        lower_char = char.lower()
        if lower_char in LEET_MAP:
            normalized_chars.append(LEET_MAP[lower_char])
            substitution_count += 1
        else:
            normalized_chars.append(lower_char)
    return "".join(normalized_chars), substitution_count