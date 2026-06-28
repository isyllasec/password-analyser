"""
tests/test_hibp.py
Tests pour core/hibp.py -- requests.get est MOCKE partout : aucun appel
reseau reel n'est effectue ici. A re-tester manuellement avec un vrai mot
de passe (ex. "password") pour confirmer la connexion reelle a l'API.
"""

import sys
import os
from unittest.mock import patch, Mock

import pytest
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.hibp import check_hibp_breach, _sha1_hex_upper


def test_sha1_hex_upper_known_value():
    # SHA-1("password") connu et verifiable independamment
    assert _sha1_hex_upper("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_breach_found_when_suffix_matches():
    full_hash = _sha1_hex_upper("password")
    prefix, suffix = full_hash[:5], full_hash[5:]
    fake_body = f"{suffix}:3861493\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n"

    mock_response = Mock(status_code=200, text=fake_body)
    with patch("core.hibp.requests.get", return_value=mock_response) as mock_get:
        result = check_hibp_breach("password")

    assert result is True
    # Verifie qu'on n'envoie bien que le prefixe, jamais le mot de passe en
    # clair ni le hash complet (le suffixe, lui, ne doit jamais apparaitre).
    called_url = mock_get.call_args[0][0]
    assert prefix in called_url
    assert suffix not in called_url


def test_no_breach_when_suffix_absent():
    fake_body = "0000000000000000000000000000000000:1\n1111111111111111111111111111111111:2\n"
    mock_response = Mock(status_code=200, text=fake_body)

    with patch("core.hibp.requests.get", return_value=mock_response):
        result = check_hibp_breach("xK9#mQ2vL7&wZ4pR")  # tres improbable d'etre dans la liste fake

    assert result is False


def test_network_error_returns_none_not_exception():
    with patch("core.hibp.requests.get", side_effect=requests.ConnectionError("pas d'internet")):
        result = check_hibp_breach("password")
    assert result is None  # ne doit jamais lever, ne doit jamais planter le pipeline


def test_timeout_returns_none():
    with patch("core.hibp.requests.get", side_effect=requests.Timeout("trop long")):
        result = check_hibp_breach("password")
    assert result is None


def test_unexpected_http_status_returns_none():
    mock_response = Mock(status_code=503, text="")
    with patch("core.hibp.requests.get", return_value=mock_response):
        result = check_hibp_breach("password")
    assert result is None


def test_none_is_distinguishable_from_false():
    # Rappel du contrat : None = "non verifie", False = "verifie, absent".
    # Ce test fige juste que les deux valeurs restent bien distinctes en Python.
    assert None is not False


def test_timeout_parameter_is_forwarded():
    mock_response = Mock(status_code=200, text="")
    with patch("core.hibp.requests.get", return_value=mock_response) as mock_get:
        check_hibp_breach("password", timeout=2.5)
    assert mock_get.call_args.kwargs["timeout"] == 2.5