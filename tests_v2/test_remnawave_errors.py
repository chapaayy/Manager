"""Remnawave HTTP 400 details must be actionable without exposing secrets."""
import json
from v2.remnawave import _panel_error_details


def test_remnawave_business_error_includes_code_and_message():
    payload = {"errorCode": "A112", "message": "Invalid Xray inbound configuration"}
    detail = _panel_error_details(json.dumps(payload).encode())
    assert "A112" in detail
    assert "Invalid Xray inbound configuration" in detail


def test_remnawave_validation_error_includes_field():
    payload = {"message": ["Validation failed"], "errors": [
        {"property": "inbounds[0].streamSettings", "constraints": {
            "invalid": "Invalid TLS certificate settings"}}
    ]}
    detail = _panel_error_details(json.dumps(payload).encode())
    assert "inbounds[0].streamSettings" in detail
    assert "Invalid TLS certificate settings" in detail


def test_remnawave_error_never_returns_private_key_or_token():
    private_key = "-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----"
    long_token = "S" * 110
    payload = {"errorCode": "A112", "message": [
        "Authorization: Bearer test-api-token",
        "privateKey: " + private_key,
        "token: " + long_token,
    ], "errors": [{"message": "secret=" + long_token}]}
    detail = _panel_error_details(json.dumps(payload).encode())
    assert "A112" in detail
    assert "PRIVATE KEY" not in detail
    assert "Bearer" not in detail
    assert long_token not in detail
    assert "token:" not in detail


def test_remnawave_error_unknown_or_oversized_body_stays_generic():
    assert _panel_error_details(b"<html>login</html>") == ""
    assert _panel_error_details(b"{}") == ""
    assert _panel_error_details(b"x" * 8193) == ""
