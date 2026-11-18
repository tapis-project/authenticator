"""
Live contract tests against the real NIH RAS test environment. No browser and no login are involved: the
interactive login (and therefore a valid authorization code) cannot be produced by a script, so these tests check
everything that CAN be verified non-interactively:

  * our client credentials and endpoint URLs are accepted by RAS (valid creds + bogus code -> invalid_grant,
    NOT invalid_client),
  * RAS rejects a wrong client secret and a bogus access token,
  * RAS's authorize endpoint accepts our registered redirect URI and does not bounce to an unregistered one,
  * OAuth2ProviderExtension handles REAL RAS error responses (not just our fake's) by raising ServiceConfigError.

The success path (valid code -> token -> userid) is covered with the fake RAS in test_oa2_nih_ras_flow.py.

Skipped unless all of these environment variables are set (never put the secret in the repo):
    RAS_CLIENT_ID, RAS_CLIENT_SECRET, RAS_AUTHORIZE_URL, RAS_TOKEN_URL, RAS_USERINFO_URL, RAS_REDIRECT_URI
RAS_REDIRECT_URI is the Tapis callback registered with RAS, e.g.
    https://<tenant>/v3/oauth2/extensions/oa2/callback
Optional: RAS_ISSUER (e.g. the RAS base URL) enables the discovery-document test.

Run with:
    docker compose run --rm -e RAS_CLIENT_ID -e RAS_CLIENT_SECRET -e RAS_AUTHORIZE_URL -e RAS_TOKEN_URL \
        -e RAS_USERINFO_URL -e RAS_REDIRECT_URI authenticator-tests service/tests/test_oa2_nih_ras_live.py -m live
"""
import os
from urllib.parse import urlparse

import pytest
import requests
from tapisservice import errors

from service import oauth2ext
from service.tests.test_oa2ext_nih_ras_unit import _patch_caches

_REQUIRED = ["RAS_CLIENT_ID", "RAS_CLIENT_SECRET", "RAS_AUTHORIZE_URL", "RAS_TOKEN_URL",
             "RAS_USERINFO_URL", "RAS_REDIRECT_URI"]
_MISSING = [v for v in _REQUIRED if not os.environ.get(v)]

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(bool(_MISSING), reason=f"live RAS env vars not set: {', '.join(_MISSING)}"),
]

TIMEOUT = 30


def env(name):
    return os.environ[name]


def _token_post(client_secret=None, code="bogus-code-for-contract-test", client_id=None):
    return requests.post(
        env("RAS_TOKEN_URL"),
        data={
            "client_id": client_id or env("RAS_CLIENT_ID"),
            "client_secret": client_secret if client_secret is not None else env("RAS_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": env("RAS_REDIRECT_URI"),
            "grant_type": "authorization_code",
        },
        headers={"Accept": "application/json"},
        timeout=TIMEOUT,
    )


def _error(rsp):
    try:
        return rsp.json().get("error")
    except Exception:
        return None


# ---------------------------------------------------------------- endpoint / credential checks


def test_token_endpoint_accepts_our_credentials(monkeypatch):
    """Valid client creds + bogus code: RAS must authenticate the client and reject only the code."""
    rsp = _token_post()
    assert rsp.status_code == 400, rsp.text
    assert _error(rsp) == "invalid_grant", rsp.text


def test_token_endpoint_rejects_wrong_client_secret():
    rsp = _token_post(client_secret="definitely-wrong-secret")
    assert rsp.status_code in (400, 401), rsp.text
    assert _error(rsp) == "invalid_client", rsp.text


def test_token_endpoint_rejects_unknown_client():
    rsp = _token_post(client_id="not-a-registered-client")
    assert rsp.status_code in (400, 401), rsp.text
    assert _error(rsp) == "invalid_client", rsp.text


def test_userinfo_rejects_bogus_token():
    rsp = requests.get(env("RAS_USERINFO_URL"), headers={"Authorization": "Bearer not-a-real-token"},
                       timeout=TIMEOUT)
    assert rsp.status_code in (400, 401), rsp.text


def test_authorize_accepts_registered_redirect_uri():
    """RAS shows its login page (or redirects to it) rather than an error for our client + redirect URI."""
    rsp = requests.get(
        env("RAS_AUTHORIZE_URL"),
        params={
            "response_type": "code",
            "client_id": env("RAS_CLIENT_ID"),
            "redirect_uri": env("RAS_REDIRECT_URI"),
            "scope": "openid email profile ga4gh_passport_v1 federated_identities",
            "state": "contract-test-state",
            "prompt": "login",
            "display": "page",
        },
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert rsp.status_code in (200, 302, 303), rsp.text[:500]
    if rsp.status_code in (302, 303):
        location = rsp.headers["Location"]
        # must be heading to RAS's own login, not straight back to us with an error
        assert not location.startswith(env("RAS_REDIRECT_URI")) or "error" not in location, location


def test_authorize_does_not_redirect_to_unregistered_uri():
    """RAS must never send the browser (and a code) to a redirect URI we did not register."""
    evil = "https://attacker.example/callback"
    rsp = requests.get(
        env("RAS_AUTHORIZE_URL"),
        params={"response_type": "code", "client_id": env("RAS_CLIENT_ID"), "redirect_uri": evil,
                "scope": "openid", "state": "x"},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert not rsp.headers.get("Location", "").startswith(evil)


@pytest.mark.skipif(not os.environ.get("RAS_ISSUER"), reason="RAS_ISSUER not set")
def test_discovery_document_matches_configured_endpoints():
    base = os.environ["RAS_ISSUER"].rstrip("/")
    rsp = requests.get(f"{base}/.well-known/openid-configuration", timeout=TIMEOUT)
    assert rsp.status_code == 200
    doc = rsp.json()
    assert doc["token_endpoint"] == env("RAS_TOKEN_URL")
    assert doc["authorization_endpoint"] == env("RAS_AUTHORIZE_URL")
    assert doc["userinfo_endpoint"] == env("RAS_USERINFO_URL")


# ---------------------------------------------------------------- our code against real RAS responses


@pytest.fixture
def ext(monkeypatch):
    _patch_caches(monkeypatch, {"nih_ras": {
        "client_id": env("RAS_CLIENT_ID"),
        "client_secret": env("RAS_CLIENT_SECRET"),
        "identity_redirect_url": env("RAS_AUTHORIZE_URL"),
        "oauth2_token_url": env("RAS_TOKEN_URL"),
        "user_info_url": env("RAS_USERINFO_URL"),
    }})
    e = oauth2ext.OAuth2ProviderExtension("dev")
    # RAS only accepts the redirect URI registered for the client
    e.callback_url = env("RAS_REDIRECT_URI")
    return e


def test_code_rejects_real_ras_invalid_grant(ext):
    ext.authorization_code = "bogus-code-for-contract-test"
    with pytest.raises(errors.ServiceConfigError):
        ext.get_token_using_auth_code()
    assert ext.access_token is None


def test_user_lookup_handles_real_ras_401(ext):
    ext.access_token = "not-a-real-token"
    with pytest.raises(errors.ServiceConfigError):
        ext.get_user_from_token()
    assert ext.username is None
