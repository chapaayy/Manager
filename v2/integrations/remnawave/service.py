"""Small cross-resource Remnawave operations."""


def panel_status(list_profiles_fn, request) -> dict:
    profiles = list_profiles_fn()
    key_response = request("GET", "/api/keygen").get("response", {})
    key_exists = isinstance(key_response, dict) and bool(
        key_response.get("secretKey") or key_response.get("pubKey")
    )
    return {
        "connected": True,
        "config_profiles": profiles,
        "node_key_available": key_exists,
    }
