"""
Integration tests for the OAuth2 flow with the nih_ras IdP. A fake RAS server (authorize/token/userinfo) runs in a
background thread, and the tenant's custom_idp_configuration points at it. The whole Tapis side (authorize ->
callback -> authorize page -> authorization code -> /tokens) runs through the Flask test client and the local DB.

Like basic_test.py these tests are intended to be run locally.
"""
import datetime
import json
import threading
from base64 import b64encode
from urllib.parse import urlparse, parse_qs

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from tapisservice.auth import validate_token
from service import models
from service.api import app
from service.models import tenant_configs_cache

TENANT_ID = "dev"
CLIENT_ID = "tapis_authn_ras_test_client"
CLIENT_KEY = "RasTestKey123"
CLIENT_REDIRECT = "http://localhost:5000/testsuite"
RAS_CLIENT_ID = "ras-test-client"
RAS_CLIENT_SECRET = "ras-test-secret"
RAS_USERID = "RASUSER1"
RAS_CODE = "ras-auth-code"
RAS_TOKEN = "ras-access-token"
BASE = "http://localhost:5000"


# ---------------------------------------------------------------- fake RAS server


class FakeRAS:
    """Fake NIH RAS. Behavior is controlled through attributes; every request is recorded in .calls."""

    def __init__(self):
        self.calls = []
        self.reset()
        self.flask = Flask("fake_ras")
        self.flask.add_url_rule("/token", "token", self._token, methods=["POST"])
        self.flask.add_url_rule("/userinfo", "userinfo", self._userinfo, methods=["GET"])
        self.server = make_server("127.0.0.1", 0, self.flask)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def reset(self):
        self.calls.clear()
        self.token_status = 200
        self.userinfo_status = 200
        self.userinfo_body = {"userid": RAS_USERID}
        self.used_codes = set()

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def _token(self):
        form = request.form.to_dict()
        self.calls.append(("token", form))
        if self.token_status != 200:
            return jsonify({"error": "server_error"}), self.token_status
        if (form.get("grant_type") != "authorization_code"
                or form.get("client_id") != RAS_CLIENT_ID
                or form.get("client_secret") != RAS_CLIENT_SECRET
                or form.get("code") != RAS_CODE
                or form.get("code") in self.used_codes):
            return jsonify({"error": "invalid_grant"}), 400
        self.used_codes.add(form["code"])
        return jsonify({"access_token": RAS_TOKEN, "token_type": "Bearer", "id_token": "x"})

    def _userinfo(self):
        self.calls.append(("userinfo", dict(request.headers)))
        if self.userinfo_status != 200:
            return jsonify({"error": "x"}), self.userinfo_status
        if request.headers.get("Authorization") != f"Bearer {RAS_TOKEN}":
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(self.userinfo_body)


@pytest.fixture(scope="module")
def ras():
    server = FakeRAS()
    server.start()
    yield server
    server.stop()


@pytest.fixture(autouse=True)
def _reset_ras(ras):
    ras.reset()


# ---------------------------------------------------------------- tenant / client setup


def _ras_config(ras):
    return {
        "nih_ras": {
            "client_id": RAS_CLIENT_ID,
            "client_secret": RAS_CLIENT_SECRET,
            "identity_redirect_url": f"{ras.url}/authorize",
            "oauth2_token_url": f"{ras.url}/token",
            "user_info_url": f"{ras.url}/userinfo",
        }
    }


def _multi_config(ras, append):
    return {
        "multi_idps": {
            "idps": [{
                "idp_id": "ras",
                "append_idp_to_username": append,
                "idp_description": _ras_config(ras),
            }]
        }
    }


def _tenant_row_values(custom_idp_config):
    return {
        "tenant_id": TENANT_ID,
        "allowable_grant_types": json.dumps(["authorization_code", "refresh_token"]),
        "use_ldap": False,
        "use_token_webapp": False,
        "mfa_config": json.dumps({}),
        "default_access_token_ttl": 14400,
        "default_refresh_token_ttl": 31536000,
        "max_access_token_ttl": 31536000,
        "max_refresh_token_ttl": 63072000,
        "custom_idp_configuration": json.dumps(custom_idp_config),
        "token_url": f"{BASE}/v3/oauth2/tokens",
        "impers_oauth_client_id": "",
        "impers_oauth_client_secret": "",
        "impersadmin_username": "",
        "impersadmin_password": "",
    }


def _install_tenant(custom_idp_config):
    """Point the dev tenant at the given custom idp config (updating the row in place; models.delete_tenant_from_db
    renames rows to 'deleted', which collides on a second run) and make sure the test client exists."""
    with app.app_context():
        tenant = models.TenantConfig.query.filter_by(tenant_id=TENANT_ID).first()
        if tenant:
            tenant.custom_idp_configuration = json.dumps(custom_idp_config)
            tenant.allowable_grant_types = json.dumps(["authorization_code", "refresh_token"])
            models.db.session.commit()
        else:
            models.add_tenant_to_db(_tenant_row_values(custom_idp_config))
        if not models.Client.query.filter_by(client_id=CLIENT_ID).first():
            models.add_client_to_db({
                "tenant_id": TENANT_ID,
                "username": "tapis-authn-testsuite",
                "client_id": CLIENT_ID,
                "client_key": CLIENT_KEY,
                "display_name": "RAS test client",
                "callback_url": CLIENT_REDIRECT,
                "create_time": datetime.datetime.utcnow(),
                "last_update_time": datetime.datetime.utcnow(),
                "active": True,
            })
        models.Users.query.filter_by(client_id=CLIENT_ID).delete()  # no auto-approve
        models.db.session.commit()
        tenant_configs_cache.load_tenant_config_cache()


@pytest.fixture(scope="module", autouse=True)
def _restore_tenant():
    """Put the dev tenant back to a plain (no custom idp) config so other test modules are unaffected."""
    yield
    with app.app_context():
        tenant = models.TenantConfig.query.filter_by(tenant_id=TENANT_ID).first()
        if tenant:
            tenant.custom_idp_configuration = json.dumps({})
            models.db.session.commit()
        models.Users.query.filter_by(client_id=CLIENT_ID).delete()
        models.AuthorizationCode.query.filter_by(client_id=CLIENT_ID).delete()
        models.db.session.commit()
        tenant_configs_cache.load_tenant_config_cache()


@pytest.fixture
def ras_tenant(ras):
    _install_tenant(_ras_config(ras))


@pytest.fixture
def client():
    app.debug = True
    return app.test_client()


# ---------------------------------------------------------------- helpers


def start_login(client, state="client-state"):
    """GET /authorize with no session; returns the redirect Location parsed into (url, query)."""
    rsp = client.get(
        f"{BASE}/v3/oauth2/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": CLIENT_REDIRECT,
            "response_type": "code",
            "state": state,
        },
    )
    assert rsp.status_code == 302
    loc = urlparse(rsp.headers["Location"])
    return loc, parse_qs(loc.query)


def callback(client, **args):
    return client.get(f"{BASE}/v3/oauth2/extensions/oa2/callback", query_string=args)


def complete_login(client, ras):
    """Run start_login and a valid callback; returns the callback response."""
    _, q = start_login(client)
    return callback(client, code=RAS_CODE, state=q["state"][0])


def basic(user, pw):
    return "Basic " + b64encode(f"{user}:{pw}".encode()).decode()


# ---------------------------------------------------------------- tests


def test_authorize_redirects_to_ras(client, ras, ras_tenant):
    loc, q = start_login(client)
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ras.url}/authorize"
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [RAS_CLIENT_ID]
    assert q["redirect_uri"] == [f"{BASE}/v3/oauth2/extensions/oa2/callback"]
    assert q["scope"] == ["openid email profile ga4gh_passport_v1 federated_identities"]
    assert q["prompt"] == ["login"]
    # a fresh, unguessable state is sent and remembered in the session
    assert len(q["state"][0]) >= 32
    with client.session_transaction() as sess:
        assert sess["oa2ext_state"] == q["state"][0]
        assert sess["orig_client_id"] == CLIENT_ID


def test_state_is_unique_per_login(client, ras, ras_tenant):
    _, q1 = start_login(client)
    _, q2 = start_login(client)
    assert q1["state"] != q2["state"]


def test_full_flow_issues_tapis_token_for_ras_user(client, ras, ras_tenant):
    rsp = complete_login(client, ras)
    # callback -> back to the authorize page for the original client
    assert rsp.status_code == 302
    assert urlparse(rsp.headers["Location"]).path == "/v3/oauth2/authorize"
    with client.session_transaction() as sess:
        assert sess["username"] == RAS_USERID
    # RAS was called as expected
    kinds = [c[0] for c in ras.calls]
    assert kinds == ["token", "userinfo"]
    assert ras.calls[0][1]["code"] == RAS_CODE
    # the user approves the client -> Tapis authorization code
    rsp = client.post(f"{BASE}/v3/oauth2/authorize", data={
        "tenant_id": TENANT_ID, "approve": True, "client_id": CLIENT_ID,
        "client_redirect_uri": CLIENT_REDIRECT, "client_response_type": "code",
        "client_state": "client-state",
    })
    assert rsp.status_code == 302
    qs = parse_qs(urlparse(rsp.headers["Location"]).query)
    assert qs["state"] == ["client-state"]
    code = qs["code"][0]
    # exchange for a token
    rsp = client.post(
        f"{BASE}/v3/oauth2/tokens",
        headers={"Authorization": basic(CLIENT_ID, CLIENT_KEY)},
        data=json.dumps({"grant_type": "authorization_code", "code": code, "redirect_uri": CLIENT_REDIRECT}),
        content_type="application/json",
    )
    assert rsp.status_code == 200, rsp.data
    claims = validate_token(rsp.json["result"]["access_token"]["access_token"])
    assert claims["tapis/username"] == RAS_USERID
    assert claims["tapis/tenant_id"] == TENANT_ID
    assert claims["tapis/client_id"] == CLIENT_ID


def test_multi_idps_appends_idp_to_username(client, ras):
    _install_tenant(_multi_config(ras, append=True))
    with client.session_transaction() as sess:
        sess["idp_id"] = "ras"
    _, q = start_login(client)
    rsp = callback(client, code=RAS_CODE, state=q["state"][0])
    assert rsp.status_code == 302
    with client.session_transaction() as sess:
        assert sess["username"] == f"{RAS_USERID}@ras"


def test_multi_idps_without_append(client, ras):
    _install_tenant(_multi_config(ras, append=False))
    with client.session_transaction() as sess:
        sess["idp_id"] = "ras"
    _, q = start_login(client)
    assert callback(client, code=RAS_CODE, state=q["state"][0]).status_code == 302
    with client.session_transaction() as sess:
        assert sess["username"] == RAS_USERID


# ---- failure paths: none of these may leave a logged-in session


def _assert_not_logged_in(client, rsp):
    assert rsp.status_code >= 400 or rsp.status_code == 302 and urlparse(rsp.headers["Location"]).path != "/v3/oauth2/authorize"
    with client.session_transaction() as sess:
        assert not sess.get("username")


def test_callback_wrong_state(client, ras, ras_tenant):
    start_login(client)
    rsp = callback(client, code=RAS_CODE, state="forged")
    _assert_not_logged_in(client, rsp)
    assert ras.calls == []  # never even contacted RAS


def test_callback_missing_state(client, ras, ras_tenant):
    start_login(client)
    rsp = callback(client, code=RAS_CODE)
    _assert_not_logged_in(client, rsp)
    assert ras.calls == []


def test_callback_without_starting_login(client, ras, ras_tenant):
    rsp = callback(client, code=RAS_CODE, state="whatever")
    _assert_not_logged_in(client, rsp)
    assert ras.calls == []


def test_callback_access_denied(client, ras, ras_tenant):
    _, q = start_login(client)
    rsp = callback(client, error="access_denied", state=q["state"][0])
    _assert_not_logged_in(client, rsp)


def test_callback_missing_code(client, ras, ras_tenant):
    _, q = start_login(client)
    rsp = callback(client, state=q["state"][0])
    _assert_not_logged_in(client, rsp)


def test_callback_bad_code(client, ras, ras_tenant):
    _, q = start_login(client)
    rsp = callback(client, code="not-the-code", state=q["state"][0])
    _assert_not_logged_in(client, rsp)


def test_token_endpoint_500(client, ras, ras_tenant):
    ras.token_status = 500
    rsp = complete_login(client, ras)
    _assert_not_logged_in(client, rsp)


def test_userinfo_401(client, ras, ras_tenant):
    ras.userinfo_status = 401
    rsp = complete_login(client, ras)
    _assert_not_logged_in(client, rsp)


def test_userinfo_without_userid(client, ras, ras_tenant):
    ras.userinfo_body = {"email": "x@y.z"}
    rsp = complete_login(client, ras)
    _assert_not_logged_in(client, rsp)


def test_replayed_callback_rejected(client, ras, ras_tenant):
    """The state is single use, so replaying the same callback must fail even before RAS rejects the code."""
    _, q = start_login(client)
    state = q["state"][0]
    assert callback(client, code=RAS_CODE, state=state).status_code == 302
    with client.session_transaction() as sess:
        sess.pop("username", None)
    rsp = callback(client, code=RAS_CODE, state=state)
    _assert_not_logged_in(client, rsp)
    assert [c[0] for c in ras.calls] == ["token", "userinfo"]  # second attempt never reached RAS
