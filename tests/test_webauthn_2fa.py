import asyncio
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock


def _real_core_package():
    root = Path(__file__).resolve().parent.parent
    core_path = str(root / "core")
    core = sys.modules.get("core")
    if core is None:
        core = types.ModuleType("core")
        sys.modules["core"] = core
    core.__path__ = [core_path]
    if hasattr(core, "auth"):
        delattr(core, "auth")
    sys.modules.pop("core.auth", None)
    return core


def _auth_module():
    _real_core_package()
    return importlib.import_module("core.auth")


def test_webauthn_credentials_are_per_user_and_removable(tmp_path):
    auth_mod = _auth_module()
    auth_mod._hash_password = lambda password: f"hash:{password}"
    auth_mod._verify_password = lambda password, hashed: hashed == f"hash:{password}"

    mgr = auth_mod.AuthManager(str(tmp_path / "auth.json"))
    assert mgr.create_user("alice", "alice-password") is True
    assert mgr.create_user("bob", "bob-password") is True

    mgr._config["users"]["alice"]["webauthn_credentials"] = [
        {"credential_id": "YWxpY2UtMQ", "name": "Alice laptop", "created": 1},
        {"credential_id": "YWxpY2UtMg", "name": "Alice backup", "created": 2},
    ]
    mgr._config["users"]["bob"]["webauthn_credentials"] = [
        {"credential_id": "Ym9iLTE", "name": "Bob key", "created": 3},
    ]
    mgr._save()

    assert mgr.webauthn_enabled("alice") is True
    assert [c["name"] for c in mgr.webauthn_list_credentials("alice")] == ["Alice laptop", "Alice backup"]
    assert [c["name"] for c in mgr.webauthn_list_credentials("bob")] == ["Bob key"]

    assert mgr.webauthn_delete_credential("alice", "YWxpY2UtMQ", "wrong-password") is False
    assert mgr.webauthn_delete_credential("alice", "Ym9iLTE", "alice-password") is False
    assert mgr.webauthn_delete_credential("alice", "YWxpY2UtMQ", "alice-password") is True

    assert [c["id"] for c in mgr.webauthn_list_credentials("alice")] == ["YWxpY2UtMg"]
    assert [c["id"] for c in mgr.webauthn_list_credentials("bob")] == ["Ym9iLTE"]


def test_login_password_stage_returns_webauthn_challenge():
    from routes.auth_routes import LoginRequest, setup_auth_routes

    auth = MagicMock()
    auth.verify_password.return_value = True
    auth.totp_enabled.return_value = False
    auth.webauthn_enabled.return_value = True
    auth.webauthn_begin_authentication.return_value = {
        "challenge": "abc",
        "allowCredentials": [{"id": "cred", "type": "public-key"}],
    }

    router = setup_auth_routes(auth)
    login = next(
        r.endpoint
        for r in router.routes
        if getattr(r, "path", None) == "/api/auth/login" and "POST" in getattr(r, "methods", set())
    )
    request = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.10"),
        cookies={},
        headers={"host": "localhost:7000"},
        url=SimpleNamespace(scheme="http", netloc="localhost:7000"),
    )
    response = MagicMock()
    body = LoginRequest(username="alice", password="alice-password", remember=True)

    result = asyncio.run(login(body=body, request=request, response=response))

    assert result["ok"] is False
    assert result["requires_2fa"] is True
    assert result["requires_webauthn"] is True
    assert result["requires_totp"] is False
    assert result["webauthn_options"]["challenge"] == "abc"
    auth.create_session.assert_not_called()
    response.set_cookie.assert_not_called()
