"""
This file contains the Resources responsible for handling the Token Webapp.

Resources:
- WebappTokenAndRedirect: Manages the primary `/oauth2/webapp` endpoint,
    displaying the token or initiating the OAuth2 flow.
- WebappTokenGen: Implements the OAuth2 callback for the authorization_code grant type,
    exchanging the code for a token.
- WebappLogout: Handles logout functionality specific to the Token Webapp.
- StaticFilesResource: Serves static files for the web application.
"""

import json
import secrets

import requests
from flask import (
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_restful import Resource
from tapisservice import errors
from tapisservice.logs import get_logger

from service.helpers.mfa import check_mfa_expired
from service.helpers.utils import get_tokenapp_client
from service.models import tenant_configs_cache

logger = get_logger(__name__)


class WebappTokenAndRedirect(Resource):
    """
    This resource implements the GET method for the primary /oauth2/webapp
    URL path of the Token Web app. This method does the following:
        1) If the user already has an active OAuth2 token in their session,
            it simply renders it in an HTML page.
        2) If not, start the OAuth2 flow by redirecting to the Authorization server's
            /oauth2/authorize URL.
    """

    def get(self):
        token = session.get("access_token")
        tenant_id = session.get("tenant_id")
        # if the authenticator is running locally,
        # redirect to the local instance of the Authorization server:
        if "localhost" in request.base_url:
            base_redirect_url = "http://localhost:5000"
        else:
            # otherwise, redirect based on the tenant in the request
            base_redirect_url = g.request_tenant_base_url
        if token:
            # tracks whether the user actually has a valid session;
            # even though they have a token, it could be expired.
            has_valid_session = True
            context = {"error": None, "token": token}
            # call the userinfo endpoint
            url = f"{base_redirect_url}/v3/oauth2/userinfo"
            headers = {"X-Tapis-Token": token}
            try:
                rsp = requests.get(url, headers=headers)
                rsp.raise_for_status()
            except Exception as e:
                # Note: it could be that the user is returning to the webpage after a
                # previous login attempt many hours later.
                # In this case, the token will exist in the session but be expired.
                # Therefore, if we cannot call the userinfo endpoint, we log the error,
                # log the user out and start the OAuth flow over again.
                msg = (
                    "Got exception trying to call userinfo endpoint. "
                    f"Will log out user. Details: {e}"
                )
                has_valid_session = False
                logout_from_webapp()
                logger.error(msg)
            if has_valid_session:
                try:
                    user_info = rsp.json().get("result")
                except Exception:
                    msg = (
                        "Could not get JSON result from userinfo endpoint. "
                        f"Will log out user. Details: rsp: {rsp}"
                    )
                    logger.error(msg)
                    has_valid_session = False
                    logout_from_webapp()
            if has_valid_session:
                try:
                    username = user_info["username"]
                except Exception as e:
                    logger.error(
                        "Got exception trying to get username out of userinfo endpoint "
                        "response object. This should never happen. Setting username "
                        f"to 'Not available'. Details: {e}; user_info: {user_info}"
                    )
                    username = "Not available"
                context["username"] = username
                context["tenant_id"] = tenant_id
                config = tenant_configs_cache.get_config(tenant_id)
                mfa_config = json.loads(config.mfa_config)
                if check_mfa_expired(mfa_config, session.get("mfa_timestamp", None)):
                    session["mfa_validated"] = False
                    tokenapp_client = get_tokenapp_client()
                    client_id = tokenapp_client["client_id"]
                    client_redirect_uri = tokenapp_client["callback_url"]
                    state = secrets.token_hex(24)
                    session["state"] = state
                    return redirect(
                        url_for(
                            "mfaresource",
                            client_id=client_id,
                            redirect_uri=client_redirect_uri,
                            state=state,
                            response_type="code",
                            source="webapp",
                        )
                    )
                return make_response(
                    render_template("token-display.html", **context), 200, headers
                )
        # otherwise, if there is no token in the session,
        # check the type of OAuth configured for this tenant;
        if not tenant_id:
            tenant_id = g.request_tenant_id
            session["tenant_id"] = tenant_id
        # start the standard Tapis OAuth2 flow with a redirect ---
        # redirect to login (oauth2/authorize)
        # maybe pass csrf token as well (state var)
        # get tenant_id based on url
        # http://localhost:5000/v3/oauth2/authorize?client_id=test_client&redirect_uri=http://localhost:5000/oauth2/webapp/callback&response_type=code
        # todo - in general, do not want to hard-code "dev.develop..."
        tokenapp_client = get_tokenapp_client()
        client_id = tokenapp_client["client_id"]
        client_redirect_uri = tokenapp_client["callback_url"]
        state = secrets.token_hex(24)
        session["state"] = state
        url = (
            f"{base_redirect_url}/v3/oauth2/authorize?client_id={client_id}&"
            f"redirect_uri={client_redirect_uri}&response_type=code&state={state}"
        )
        return redirect(url)


class WebappTokenGen(Resource):
    """
    Implements the OAuth2 callback URL for the Token Webapp for the
    authorization_code grant type.

    This resource only implements the GET method, as per the OAUth2 spec,
    to receive the callback from the Authorization server and then
    exchange the authorization code for a token.
    """

    def get(self):
        logger.debug("top of GET /v3/oauth2/webapp/callback")
        client_data = get_tokenapp_client()
        client_id = client_data["client_id"]
        client_key = client_data["client_key"]
        client_redirect_uri = client_data["callback_url"]
        # the user should already be authenticated and in the session --
        username = session.get("username")
        if not username:
            logger.error(
                "GET request to /v3/oauth2/webapp/callback made but WebappTokenGen "
                "could not find username in the session! "
            )
            raise errors.ResourceError(
                msg="The username could not be established from the session."
            )
        tenant_id = g.request_tenant_id
        logger.debug(f"client_id: {client_id}; tenant_id: {tenant_id}")
        # get additional query parameters from request ---
        state = request.args.get("state")
        session_state = session.get("state")
        if not state == session_state:
            logger.error(
                f"state received: ({state}) did not match "
                f"session state: ({session_state})"
            )
            raise errors.ResourceError(
                msg="Unauthorized access attempt: state mismatch."
            )
        code = request.args.get("code")

        #  POST to oauth2/tokens
        # (passing code, client id, client secret, and redirect uri)
        logger.debug(f"request.base_url: {request.base_url}")
        base_url = g.request_tenant_base_url
        # The common flaskbase code will compute request_tenant_base_url
        # based on the tenant of the request.
        # We will need to modify this for local development since the computed base url
        # will for example be the dev.tenants.develop.tapis.io for the dev tenant
        # in the develop instance.
        # If Token Webapp listening on localhost, base_url should be localhost

        # If the authenticator is running locally, use "localhost" for baseurl to
        # interact with OAuth server and we pass the tenant-id in as a special header:
        headers = {}
        if "localhost" in request.base_url:
            logger.debug("using localhost for base_url.")
            base_url = "http://localhost:5000"
            headers["X-Tapis-Local-Tenant"] = tenant_id
            logger.debug(f"setting X-Tapis-Local-Tenant header to: {tenant_id}")
        logger.debug(f"Final base_url: {base_url}")

        url = f"{base_url}/v3/oauth2/tokens"
        content = {
            "grant_type": "authorization_code",
            "redirect_uri": client_redirect_uri,
            "code": code,
        }
        try:
            logger.debug(f"making request to {url}")
            r = requests.post(
                url, json=content, auth=(client_id, client_key), headers=headers
            )
        except Exception as e:
            logger.error(
                "Got exception trying to POST to /v3/oauth2/tokens endpoint. "
                f"Exception: {e}"
            )
            raise errors.ResourceError(
                "Failure to generate an access token; please try again later."
            )
        logger.debug(f"made request; got response: {r}")
        try:
            json_resp = json.loads(r.text)
        except Exception as e:
            logger.error(
                "Got exception trying to parse JSON from POST to /v3/tokens endpoint. "
                f"Exception: {e}"
            )
            raise errors.ResourceError(
                "Failure to generate an access token; please try again later."
            )

        logger.debug(
            "Made request successfully and got JSON. "
            f"Now parsing JSON data: {json_resp}"
        )
        # Get token from POST response
        try:
            token = json_resp["result"]["access_token"]["access_token"]
        except TypeError as e:
            logger.error(
                f"Got TypeError trying to retrieve access_token from JSON response: {e}"
            )
            raise errors.ResourceError(
                "Failure to generate an access token; please try again later."
            )
        except Exception as e:
            logger.error(
                f"Got Exception trying to retrieve access token from JSON response: {e}"
            )
            raise errors.ResourceError(
                "Failure to generate an access token; please try again later."
            )
        session["access_token"] = token
        #  Redirect to oauth2/webapp/token-display
        return redirect(url_for("webapptokenandredirect"))


class WebappLogout(Resource):
    """
    Implements a logout function for just the Token Webapp; i.e., this endpoint removes
    only the webapp attributes from the user's session.
    """

    def get(self):
        logger.debug("top of GET /v3/oauth2/webapp/logout")
        logout_from_webapp()
        logger.debug(
            "User has been logged out of webapp; "
            f"remaining session keys: {session.keys()}"
        )


class StaticFilesResource(Resource):
    def get(self, path):
        return send_from_directory("templates", path)


def logout_from_webapp():
    """
    Helper function that just removes the Token Webapp's attributes from the session.
    """
    session.pop("access_token", None)
