from flask import g, session, redirect, render_template, make_response, request, url_for
from service.models import db, AuthorizationCode, tenant_configs_cache
from service.session import clear_orig_client_data

from service import t
from service import errors
from tapisservice.logs import get_logger

logger = get_logger(__name__)


DEFAULT_DEVICE_CODE_TOKEN_TTL = 30


def oauth_redirect_url(endpoint, **values):
    """
    Build a redirect target for OAuth UI routes.

    Behind a TLS-terminating proxy, Flask may see an http:// request while clients
    use https://. Relative redirects then become http:// in the Location header.
    """
    if "localhost" in request.base_url:
        return url_for(endpoint, **values)
    return url_for(endpoint, _external=True, _scheme="https", **values)


def redirect_to_route(endpoint, status_code=302, headers=None, **values):
    location = oauth_redirect_url(endpoint, **values)
    if headers is not None:
        return redirect(location, status_code, headers)
    return redirect(location, status_code)


def generate_authorization_code(tenant_id, username, client_id, client, nonce=None):
    """
    Generates an authorization code and saves it to the database.
    """
    authz_code = AuthorizationCode(
        tenant_id=tenant_id,
        username=username,
        client_id=client_id,
        client_key=client.client_key,
        tapis_idp_id=session.get("idp_id"),
        redirect_url=client.callback_url,
        code=AuthorizationCode.generate_code(),
        expiry_time=AuthorizationCode.compute_expiry(),
        passthrough_nonce=nonce,
    )
    try:
        db.session.add(authz_code)
        db.session.commit()
    except Exception as e:
        logger.error(
            f"Got exception trying to add and commit the auth code. e: {e}; type(e): {type(e)}"
        )
        raise errors.ResourceError(
            "Internal error saving authorization code. Please try again later."
        )
    return authz_code


def handle_response_type(response_type, allowable_grant_types, tenant_id, username, client_id, client, state, nonce=None, **kwargs):
    if response_type == "token":
        if "implicit" not in allowable_grant_types:
            raise errors.ResourceError(
                f"The implicit grant type is not allowed for this "
                f"tenant. Allowable grant types: {allowable_grant_types}"
            )
        # url = f"{g.request_tenant_base_url}/v3/tokens"
        config = tenant_configs_cache.get_config(tenant_id)
        access_token_ttl = config.default_access_token_ttl

        content = {
            "token_tenant_id": f"{tenant_id}",
            "account_type": "user",
            "token_username": f"{username}",
            "claims": {
                "tapis/client_id": client_id,
                "tapis/grant_type": "implicit",
            },
            "access_token_ttl": access_token_ttl,
            "generate_refresh_token": False,
            "tapis/redirect_uri": client.callback_url,
        }

        if session.get("idp_id"):
            content["claims"]["tapis/idp_id"] = session.get("idp_id")
        try:
            logger.debug("Generating access token for implicit grant type.")
            tokens = t.tokens.create_token(
                **content,
                use_basic_auth=False,
            )
            access_token = tokens.access_token.access_token
            expires_in = tokens.access_token.expires_in
        except Exception as e:
            logger.error(f"Error generating access token: {e}")
            raise errors.ResourceError("Failed to generate access token.")

        # Redirect to the client's callback URL with the token
        redirect_url = f"{client.callback_url}?access_token={access_token}&state={state}&expires_in={expires_in}&token_type=Bearer"
        logger.debug(f"Redirecting to: {redirect_url}")
        if session.get("idp_id"):
            clear_orig_client_data()
        return redirect(redirect_url)

    elif response_type == "code":
        if "authorization_code" not in allowable_grant_types:
            raise errors.ResourceError(
                f"The authorization_code grant type is not allowed for this "
                f"tenant. Allowable grant types: {allowable_grant_types}"
            )

        # create the authorization code for the client and handle nonce if needed.
        if nonce:
            logger.debug(f"inside of handle response - nonce found: {nonce}")

        authz_code = generate_authorization_code(
            tenant_id, username, client_id, client, nonce=nonce
        )

        # Redirect to the client's callback URL with the authorization code
        redirect_url = f"{client.callback_url}?code={authz_code}&state={state}"
        logger.debug(f"Redirecting to: {redirect_url}")
        if session.get("idp_id"):
            clear_orig_client_data()
        return redirect(redirect_url)

    else:
        # Unsupported response type
        logger.error(f"Unsupported response type: {response_type}")
        raise errors.ResourceError(f"Unsupported response type: {response_type}")
