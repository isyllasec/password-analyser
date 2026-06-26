"""Axe 3 : génération de variantes OSINT (type CUPP) à partir d'infos publiques."""
import unicodedata
from datetime import date
from typing import Optional


def normalize_text(s: str) -> str:
    """Déaccentue une chaîne (les mots de passe omettent presque toujours les accents)."""
    if not s:
        return ""
    nfkd = unicodedata.normalize('NFKD', s)
    return ''.join(c for c in nfkd if not unicodedata.combining(c)).strip()


def build_case_variants(s: str) -> list[str]:
    """4 variantes : lower, Capitalize, UPPER, reversed(lower)."""
    if not s:
        return []
    base = normalize_text(s)
    if not base:
        return []
    return [base.lower(), base.capitalize(), base.upper(), base.lower()[::-1]]


def build_fullname_variants(prenom: str, nom: str) -> list[str]:
    """8 variantes : {lower,Capitalize} x {lower,Capitalize}, 2 ordres."""
    if not prenom or not nom:
        return []
    p = normalize_text(prenom)
    n = normalize_text(nom)
    if not p or not n:
        return []
    p_forms = [p.lower(), p.capitalize()]
    n_forms = [n.lower(), n.capitalize()]
    variants = []
    for pf in p_forms:
        for nf in n_forms:
            variants.append(pf + nf)
            variants.append(nf + pf)
    return variants


def extract_date_parts(date_naissance: Optional[date]) -> dict:
    if date_naissance is None:
        return {}
    yyyy = f"{date_naissance.year:04d}"
    dd = f"{date_naissance.day:02d}"
    mm = f"{date_naissance.month:02d}"
    return {"YYYY": yyyy, "YY": yyyy[-2:], "DDMM": dd + mm, "MMDD": mm + dd}


def build_birthdate_variants(date_naissance: Optional[date]) -> list[str]:
    parts = extract_date_parts(date_naissance)
    return list(parts.values())


def build_name_date_variants(prenom: Optional[str], nom: Optional[str], date_naissance: Optional[date]) -> list[str]:
    """{prenom,nom} x {YYYY,YY} x {nom+date, date+nom} -- jusqu'à 8 si les 2 noms sont fournis."""
    parts = extract_date_parts(date_naissance)
    if not parts:
        return []
    years = [parts["YYYY"], parts["YY"]]
    variants = []
    for name in (prenom, nom):
        if not name:
            continue
        base = normalize_text(name).lower()
        if not base:
            continue
        for y in years:
            variants.append(base + y)
            variants.append(y + base)
    return variants


def _find_matches_for_variants(password: str, variants: list[str], rule_name: str) -> list[dict]:
    """Recherche en substring (case-sensitive) de chaque variante dans le mot de passe.
    rule_variant_count = nombre de variantes générées par CETTE règle (cohérent avec le coût
    en entropie ajustée : log2(rule_variant_count))."""
    matches = []
    rule_count = len(variants)
    if rule_count == 0:
        return matches
    for variant in variants:
        if len(variant) < 2:
            continue  # évite le bruit de matchs triviaux à 1 caractère
        start = password.find(variant)
        while start != -1:
            matches.append({
                "start": start,
                "end": start + len(variant),
                "type": "osint",
                "data": {"rule_variant_count": rule_count, "rule": rule_name},
            })
            start = password.find(variant, start + 1)
    return matches


def find_firstname_matches(password: str, prenom: Optional[str]) -> list[dict]:
    return _find_matches_for_variants(password, build_case_variants(prenom), "firstname")


def find_lastname_matches(password: str, nom: Optional[str]) -> list[dict]:
    return _find_matches_for_variants(password, build_case_variants(nom), "lastname")


def find_fullname_matches(password: str, prenom: Optional[str], nom: Optional[str]) -> list[dict]:
    return _find_matches_for_variants(password, build_fullname_variants(prenom, nom), "fullname")


def find_birthdate_matches(password: str, date_naissance: Optional[date]) -> list[dict]:
    return _find_matches_for_variants(password, build_birthdate_variants(date_naissance), "birthdate")


def find_name_date_matches(password: str, prenom: Optional[str], nom: Optional[str], date_naissance: Optional[date]) -> list[dict]:
    return _find_matches_for_variants(password, build_name_date_variants(prenom, nom, date_naissance), "name_date")


def detect_osint_patterns(password: str, prenom: Optional[str] = None, nom: Optional[str] = None,
                           date_naissance: Optional[date] = None) -> list[dict]:
    """Orchestrateur axe 3. Déclenché dès qu'au moins un champ est fourni."""
    if not prenom and not nom and date_naissance is None:
        return []
    matches = []
    matches += find_firstname_matches(password, prenom)
    matches += find_lastname_matches(password, nom)
    matches += find_fullname_matches(password, prenom, nom)
    matches += find_birthdate_matches(password, date_naissance)
    matches += find_name_date_matches(password, prenom, nom, date_naissance)
    return matches