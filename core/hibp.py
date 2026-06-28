"""
core/hibp.py
Bonus -- verification de fuite via l'API Have I Been Pwned (k-anonymity).

Principe (cf. decisions_projet.md section 6) :
1. On calcule le SHA-1 du mot de passe en local.
2. On envoie uniquement les 5 premiers caracteres du hash a l'API
   (GET /range/{prefix}) -- jamais le mot de passe, jamais le hash complet.
3. L'API renvoie toutes les suffixes connues pour ce prefixe (des centaines
   de hashs partageant les memes 5 premiers caracteres).
4. On compare le suffixe complet EN LOCAL, sans jamais le transmettre.

Comportement sur erreur reseau (decision actee) : ne fait JAMAIS planter le
pipeline. Retourne None (= "non verifie") plutot que de lever une exception,
distingue explicitement de False (= "verifie, pas trouve dans les fuites").
"""

import hashlib
from typing import Optional

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
DEFAULT_TIMEOUT_SECONDS = 5.0


def _sha1_hex_upper(password: str) -> str:
    """SHA-1 du mot de passe, en hexadecimal majuscule (format attendu par HIBP)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_hibp_breach(password: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Optional[bool]:
    """
    Verifie si le mot de passe apparait dans une fuite connue, via k-anonymity.

    Returns:
        True  -> trouve dans au moins une fuite connue
        False -> verifie avec succes, aucune correspondance trouvee
        None  -> verification impossible (erreur reseau, timeout, statut HTTP
                 inattendu) -- ne represente PAS "mot de passe sain", juste
                 "on ne sait pas". A distinguer clairement de False cote UI.
    """
    full_hash = _sha1_hex_upper(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            timeout=timeout,
            headers={"Add-Padding": "false"},
        )
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    for line in response.text.splitlines():
        if not line:
            continue
        line_suffix, _, _count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            return True

    return False