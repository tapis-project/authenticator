"""
Unit tests for the nih_ras branch of OAuth2ProviderExtension. No network and no DB: the tenant config cache,
tenant cache and `requests` are all mocked.
"""
import json
from types import SimpleNamespace
from unittest import mock

import pytest
import requests
from tapisservice import errors

from service import oauth2ext
from service.api import app

TENANT = "dev"
RAS = {
    "client_id": "ras-client",
    "client_secret": "ras-secret",
    "identity_redirect_url": "https://ras.example/authorize",
    "oauth2_token_url": "https://ras.example/token",
    "user_info_url": "https://ras.example/userinfo",
}


def _patch_caches(monkeypatch, config_dict, ext_type="nih_ras"):
    cfg = SimpleNamespace(custom_idp_configuration=json.dumps(config_dict))
    fake_configs = mock.Mock()
    fake_configs.get_config.return_value = cfg
    fake_configs.get_custom_oa2_extension_type.return_value = ext_type
    monkeypatch.setattr(oauth2ext, "tenant_configs_cache", fake_configs)
    fake_t = mock.Mock()
    fake_t.tenant_cache.get_tenant_config.return_value = SimpleNamespace(base_url="https://tenant.example")
    monkeypatch.setattr(oauth2ext, "t", fake_t)


@pytest.fixture
def ext(monkeypatch):
    _patch_caches(monkeypatch, {"nih_ras": RAS})
    return oauth2ext.OAuth2ProviderExtension(TENANT)


def _resp(status=200, json_body=None, text=None):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = json_body
    if json_body is None and text is not None:
        r.json.side_effect = ValueError("no json")
    r.text = text if text is not None else json.dumps(json_body)
    r.content = r.text.encode()
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"{status}")
    return r


def _callback_request(**args):
    return SimpleNamespace(args=args)


# ---------------------------------------------------------------- __init__


def test_init_sets_ras_attributes(ext):
    assert ext.ext_type == "nih_ras"
    assert ext.client_id == RAS["client_id"]
    assert ext.client_key == RAS["client_secret"]
    assert ext.identity_redirect_url == RAS["identity_redirect_url"]
    assert ext.oauth2_token_url == RAS["oauth2_token_url"]
    assert ext.user_info_url == RAS["user_info_url"]
    assert ext.callback_url == "https://tenant.example/v3/oauth2/extensions/oa2/callback"


def test_init_local_development_callback(monkeypatch):
    _patch_caches(monkeypatch, {"nih_ras": RAS})
    e = oauth2ext.OAuth2ProviderExtension(TENANT, is_local_development=True)
    assert e.callback_url == "http://localhost:5000/v3/oauth2/extensions/oa2/callback"


def test_init_multi_idps_resolves_nih_ras(monkeypatch):
    cfg = {"multi_idps": {"idps": [
        {"idp_id": "other", "idp_description": {"github": {"client_id": "x", "client_secret": "y"}}},
        {"idp_id": "ras", "idp_description": {"nih_ras": RAS}},
    ]}}
    _patch_caches(monkeypatch, cfg, ext_type="multi_idps")
    e = oauth2ext.OAuth2ProviderExtension(TENANT, idp_id_for_multi="ras")
    assert e.ext_type == "nih_ras"
    assert e.client_id == RAS["client_id"]
    assert e.user_info_url == RAS["user_info_url"]


# ---------------------------------------------------------------- callback: code and state


def test_callback_valid_state_and_code(ext):
    with app.test_request_context():
        from flask import session
        session["oa2ext_state"] = "abc"
        ext.get_auth_code_from_callback(_callback_request(code="the-code", state="abc"))
        assert ext.authorization_code == "the-code"
        # state is single use
        assert "oa2ext_state" not in session


def test_callback_state_mismatch_rejected(ext):
    with app.test_request_context():
        from flask import session
        session["oa2ext_state"] = "abc"
        with pytest.raises(errors.ServiceConfigError):
            ext.get_auth_code_from_callback(_callback_request(code="c", state="WRONG"))


def test_callback_without_state_rejected(ext):
    """A forged callback that simply omits state must not be accepted (login CSRF)."""
    with app.test_request_context():
        from flask import session
        session["oa2ext_state"] = "abc"
        with pytest.raises(errors.ServiceConfigError):
            ext.get_auth_code_from_callback(_callback_request(code="c"))


def test_callback_no_state_in_session_rejected(ext):
    with app.test_request_context():
        with pytest.raises(errors.ServiceConfigError):
            ext.get_auth_code_from_callback(_callback_request(code="c", state="abc"))


def test_callback_missing_code(ext):
    with app.test_request_context():
        from flask import session
        session["oa2ext_state"] = "abc"
        with pytest.raises(errors.ServiceConfigError):
            ext.get_auth_code_from_callback(_callback_request(state="abc"))


def test_callback_provider_error(ext):
    with app.test_request_context():
        from flask import session
        session["oa2ext_state"] = "abc"
        with pytest.raises(errors.ServiceConfigError):
            ext.get_auth_code_from_callback(_callback_request(error="access_denied", state="abc"))


# ---------------------------------------------------------------- token exchange


def test_token_exchange_request_shape(ext):
    ext.authorization_code = "the-code"
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(json_body={"access_token": "tok"})) as post:
        assert ext.get_token_using_auth_code() == "tok"
    args, kwargs = post.call_args
    assert args[0] == RAS["oauth2_token_url"]
    # form encoded (a dict), not a JSON string
    assert kwargs["data"] == {
        "client_id": RAS["client_id"],
        "client_secret": RAS["client_secret"],
        "code": "the-code",
        "redirect_uri": ext.callback_url,
        "grant_type": "authorization_code",
    }
    assert kwargs["headers"]["Accept"] == "application/json"


@pytest.mark.parametrize("status", [400, 401, 500])
def test_token_exchange_http_error(ext, status):
    ext.authorization_code = "c"
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(status, {"error": "invalid_grant"})):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_token_using_auth_code()


def test_token_exchange_connection_error_is_clean(ext):
    """requests raising before a response exists used to hit AttributeError on rsp.text."""
    ext.authorization_code = "c"
    with mock.patch.object(oauth2ext.requests, "post", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_token_using_auth_code()


def test_token_exchange_non_json(ext):
    ext.authorization_code = "c"
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(200, text="<html>")):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_token_using_auth_code()


def test_token_exchange_no_access_token(ext):
    ext.authorization_code = "c"
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(200, {"id_token": "x"})):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_token_using_auth_code()


def test_token_exchange_does_not_log_secrets(ext, caplog):
    ext.authorization_code = "super-secret-code"
    caplog.set_level("DEBUG")
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(json_body={"access_token": "tok-secret"})):
        ext.get_token_using_auth_code()
    with mock.patch.object(oauth2ext.requests, "post", return_value=_resp(400, {"error": "x"})):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_token_using_auth_code()
    logged = caplog.text
    for secret in (RAS["client_secret"], "super-secret-code", "tok-secret"):
        assert secret not in logged


# ---------------------------------------------------------------- user lookup


def test_user_lookup_success(ext):
    ext.access_token = "tok"
    with mock.patch.object(oauth2ext.requests, "get", return_value=_resp(json_body={"userid": "ras-user"})) as get:
        assert ext.get_user_from_token() == "ras-user"
    assert get.call_args[0][0] == RAS["user_info_url"]
    assert get.call_args[1]["headers"] == {"Authorization": "Bearer tok"}


def test_user_lookup_appends_idp(ext):
    ext.access_token = "tok"
    with mock.patch.object(oauth2ext.requests, "get", return_value=_resp(json_body={"userid": "ras-user"})):
        assert ext.get_user_from_token(idp_id="ras") == "ras-user@ras"


@pytest.mark.parametrize("status", [401, 403, 500])
def test_user_lookup_http_error(ext, status):
    ext.access_token = "tok"
    with mock.patch.object(oauth2ext.requests, "get", return_value=_resp(status, {"error": "x"})):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_user_from_token()


def test_user_lookup_connection_error_is_clean(ext):
    ext.access_token = "tok"
    with mock.patch.object(oauth2ext.requests, "get", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_user_from_token()


@pytest.mark.parametrize("body", [{}, {"userid": ""}, {"userid": None}, {"email": "a@b.c"}])
def test_user_lookup_missing_userid(ext, body):
    ext.access_token = "tok"
    with mock.patch.object(oauth2ext.requests, "get", return_value=_resp(json_body=body)):
        with pytest.raises(errors.ServiceConfigError):
            ext.get_user_from_token()
    assert ext.username is None
