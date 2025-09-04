"""
This file contains the Resources responsible for the authentication and
authorization of users.

Resources:
- LoginResource: Implements the login functionality for users.
- MFAResource: Handles Multi-Factor Authentication (MFA) for users.
- AuthorizeResource: Handles the activity of a user authorizing a client.
- LogoutResource: Implements the logout functionality for users.
"""

import json
import random
import time

from flask import g, make_response, redirect, render_template, request, session, url_for
from flask_restful import Resource
from tapisservice import errors
from tapisservice.logs import get_logger

from service import t
from service.errors import InvalidPasswordError
from service.helpers import (
    call_mfa,
    check_client,
    check_mfa_expired,
    check_sms,
    clear_orig_client_data,
    logout,
    needs_mfa,
    send_sms,
)
from service.ldap import check_username_password
from service.models import (
    AuthorizationCode,
    Client,
    DeviceCode,
    db,
    tenant_configs_cache,
)
from service.oauth2ext import OAuth2ProviderExtension

logger = get_logger(__name__)


DEFAULT_DEVICE_CODE_TOKEN_TTL = 30


class LoginResource(Resource):
    """
    Implements the URLs used by the Authorization server for
    logging a user into a specific tenant.
    """

    def get(self):
        logger.debug("Logging in")
        logger.debug(f"Session: {session}")
        client_id, client_redirect_uri, client_state, client, response_type = (
            check_client()
        )
        logger.debug(f"client_response_type: {response_type}")
        # selecting a tenant id is required before logging in -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect "
                "to SetTenantResource. session: {session}"
            )
            return redirect(
                url_for(
                    "settenantresource",
                    client_id=client_id,
                    redirect_uri=client_redirect_uri,
                    state=client_state,
                    response_type="code",
                )
            )
        headers = {"Content-Type": "text/html"}
        display_name = ""
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")
        context = {
            "error": "",
            "client_display_name": display_name,
            "client_id": client_id,
            "client_redirect_uri": client_redirect_uri,
            "client_state": client_state,
            "tenant_id": tenant_id,
            "client_response_type": response_type,
        }
        return make_response(render_template("login.html", **context), 200, headers)

    def post(self):
        # process the login form -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect "
                f"to SetTenantResource. session: {session}"
            )
            raise errors.ResourceError(
                "Invalid session; please return to the original application "
                "or logout of this session."
            )
        headers = {"Content-Type": "text/html"}
        client_id = request.form.get("client_id")
        client_redirect_uri = request.form.get("client_redirect_uri")
        client_state = request.form.get("client_state")
        client_display_name = request.form.get("client_display_name")
        context = {
            "error": "",
            "client_display_name": client_display_name,
            "client_id": client_id,
            "client_redirect_uri": client_redirect_uri,
            "client_state": client_state,
            "tenant_id": tenant_id,
        }
        username = request.form.get("username")
        if not username:
            context["error"] = "Username is required."
            return make_response(render_template("login.html", **context), 200, headers)
        password = request.form.get("password")
        if not password:
            context["error"] = "Password is required."
            return make_response(render_template("login.html", **context), 200, headers)
        try:
            check_username_password(
                tenant_id=tenant_id, username=username, password=password
            )
        except InvalidPasswordError:
            context["error"] = "Invalid username/password combination."
            return make_response(render_template("login.html", **context), 200, headers)
        # the username and password were accepted; set the session and
        # redirect to the authorization page.
        # first, check if this is a multi_idp situation
        idp_id = session.get("idp_id")
        if idp_id:
            is_local_development = "localhost" in request.base_url
            oa2ext = OAuth2ProviderExtension(
                tenant_id, is_local_development=is_local_development
            )
            # if we have set the idp_id in the session, we need to check if this idp_id
            # should be appended to the username
            append_idp_to_username = False
            # loop through all the idps for the one in the session, and check that one
            # for a flag, `append_idp_to_username`
            for idp in oa2ext.custom_idp_config_dict["multi_idps"]["idps"]:
                # we found the idp config
                if idp["idp_id"] == session.get("idp_id"):
                    # the append_idp_to_username attribute is optional
                    append_idp_to_username = idp.get("append_idp_to_username")
                    # either way, exit the loop because we've found the idp
                    break
            if append_idp_to_username:
                username = f"{username}@{idp_id}"

        # response_type = 'code'
        response_type = request.form.get("client_response_type")
        if not response_type:
            response_type = "code"
        session["username"] = username
        mfa_timestamp = session.get("mfa_timestamp", None)
        mfa_required = needs_mfa(tenant_id, mfa_timestamp)
        redirect_url = "authorizeresource"
        if mfa_required:
            redirect_url = "mfaresource"
            session["mfa_validated"] = False
            session["mfa_required"] = True
            sms_required = check_sms(tenant_id, username)
            if sms_required:
                logger.debug(f"SMS required for: {username}")
                sent = send_sms(tenant_id, username)
                logger.debug(f"SMS Sent: {sent}")
        if session.get("device_login"):
            response_type = "device_code"
            if not mfa_required:
                redirect_url = "deviceflowresource"
        return redirect(
            url_for(
                redirect_url,
                client_id=client_id,
                redirect_uri=client_redirect_uri,
                state=client_state,
                client_display_name=client_display_name,
                response_type=response_type,
            )
        )


class MFAResource(Resource):
    def get(self):
        # a tenant id is required
        logger.info("Top of GET MFA Resource")
        client_id, client_redirect_uri, client_state, client, response_type = (
            check_client()
        )
        tenant_id = g.request_tenant_id
        headers = {"Content-Type": "text/html"}
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect "
                f"to LoginResource. session: {session}"
            )
            return redirect(url_for("loginresource"), 200, headers)
        display_name = ""
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")

        logger.info(f"Source: {request.args.get('source', None)}")
        logger.info(f"User Code: {request.args.get('user_code', None)}")

        context = {
            "error": "",
            "client_display_name": display_name,
            "client_id": client_id,
            "client_redirect_uri": client_redirect_uri,
            "client_state": client_state,
            "tenant_id": tenant_id,
            "mfa_token_name": self.create_token(),
            "username": session.get("username"),
            "user_code": request.args.get("user_code", None),
            "source": request.args.get("source", None),
        }
        return make_response(render_template("mfa.html", **context), 200, headers)

    def post(self):
        logger.info("Top of POST MFA Resource")
        client_id, client_redirect_uri, client_state, client, response_type = (
            check_client()
        )
        tenant_id = g.request_tenant_id
        username = session.get("username")
        headers = {"Content-Type": "text/html"}
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect "
                f"to LoginResource. session: {session}"
            )
            return redirect(url_for("loginresource"), 200, headers)
        mfa_token_name = request.form.get("mfa_token_name")
        mfa_token = request.form.get(mfa_token_name)
        source = request.form.get("source", None)
        user_code = request.form.get("user_code", None)

        logger.info(f"Source: {source}")
        logger.info(f"User Code: {user_code}")

        response = "Incorrect MFA token"
        logger.debug("MFA CODE: %s" % mfa_token)
        validated = call_mfa(mfa_token, tenant_id, username)
        display_name = ""
        redirect_url = "authorizeresource"
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")
        if validated:
            # response_type = 'code'
            if "device_login" in session and source != "authorize":
                redirect_url = "deviceflowresource"
                response_type = "device_code"
            if source == "webapp":
                redirect_url = "webapptokenandredirect"
            session["mfa_validated"] = True
            session["mfa_timestamp"] = time.time()
            return redirect(
                url_for(
                    redirect_url,
                    client_id=client_id,
                    redirect_uri=client_redirect_uri,
                    state=client_state,
                    client_display_name=display_name,
                    response_type=response_type,
                    user_code=user_code,
                    source=source,
                )
            )
        else:
            context = {
                "error": response,
                "username": session.get("username"),
                "mfa_token_name": self.create_token(),
            }
            return make_response(render_template("mfa.html", **context), 200, headers)

    def create_token(self):
        """
        Create unique token field name (to prevet autofill of old tokens)
        """
        mfa_token_ident = str(random.random())[3:]

        return "mfa_token_" + mfa_token_ident


class AuthorizeResource(Resource):
    """
    This resource handles the activity of a user authorizing a client (web app)
    to get a token.
    It specifies the name of the client requesting authorization
    and asks the user to approve it.
    It also serves as a starting point for various OAuth2 flows,
    including authorization, implicit, and device code.
    """

    def get(self):
        logger.info("top of GET /v3/oauth2/authorize")
        is_device_flow = True if "device_login" in session else False
        # if we are using the multi_idp custom oa2 extension type it is possible
        # we are being redirected here, not by the original web client,
        # but by our select_idp page, in which case we need to get the client
        # out of the session.

        # Update: 10/23/2023 JFS: the idp_id could be in the session but the client_id
        # could not be. This would happen if the following steps were taken:
        #    1) user logs in with client 1. the idp_id gets set in the session here.
        #    2) user completes oauth flow with client 1; client 1 gets a token.
        #       at this point the orig_client is removed
        #       from the session (via clear_orig_client_data)
        #    3) user starts a new flow with client 2. at this point,
        #       the client_id is not in the session BUT
        #       the user's login info (including idp_id) IS still.
        if session.get("idp_id"):
            client_id, client_redirect_uri, client_state, client, response_type = (
                check_client(use_session=True)
            )
        else:
            client_id, client_redirect_uri, client_state, client, response_type = (
                check_client()
            )
        if is_device_flow:
            response_type = "device_code"
        tenant_id = session.get("tenant_id")
        if not tenant_id:
            tenant_id = g.request_tenant_id
            session["tenant_id"] = tenant_id
        # check if the grant type is supported by this tenant
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        mfa_config = json.loads(config.mfa_config)

        if mfa_config:
            if session.get("mfa_required") is True:
                if check_mfa_expired(mfa_config, session.get("mfa_timestamp", None)):
                    session["mfa_validated"] = False
                if session.get("mfa_validated") is False:
                    logger.debug("Authorize Resource: Redirecting to MFA")
                    return redirect(
                        url_for(
                            "mfaresource",
                            client_id=client_id,
                            redirect_uri=client_redirect_uri,
                            state=client_state,
                            response_type=response_type,
                            user_code=request.args.get("user_code", None),
                            source="authorize",
                        )
                    )

        if response_type == "token":
            if "implicit" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The implicit grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )
        if response_type == "code":
            if "authorization_code" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The authorization_code grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )
        if response_type == "device_code":
            logger.info("device_code response type")
            if "device_code" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The device_code grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )
        # if the user has not already authenticated, we need to issue a redirect
        # to the login screen; the login screen will depend
        # on the tenant's IdP configuration
        if "username" not in session:
            # Device login should already be in the session
            # User would have to navigate directly to authorize and put
            # device_code response type as parameter
            if response_type == "device_code":
                session["device_login"] = True
            # if the tenant is configured with a custom oa2 extension,
            # start the redirect for that --
            if tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id):
                logger.debug("username not in session and custom oa2 extension found.")
                is_local_development = "localhost" in request.base_url
                # we need to save the original client in the session in this case,
                # because there is no way to pass it through
                # the third party OAuth server
                session["orig_client_id"] = client_id
                session["orig_client_redirect_uri"] = client_redirect_uri
                session["orig_client_response_type"] = response_type
                session["orig_client_state"] = client_state
                oa2ext = OAuth2ProviderExtension(
                    tenant_id, is_local_development=is_local_development
                )
                # If the custom oa2 extension type is "multi_idps",
                # then the user must first select an idp from the available list.
                if oa2ext.ext_type == "multi_idps":
                    # Once selected, the choice goes into the session and the
                    # user is redirected back here;
                    # so first, check if the idp_id is in the session:
                    idp_id = session.get("idp_id")
                    if not idp_id:
                        # user has not selected an idp yet,
                        # so redirect them to the idp selection page:
                        return redirect(url_for("setidentityprovider"))
                    # User has selected an idp, so we need to construct
                    # a new oa2ext object that points to the selected idp extension.
                    oa2ext = OAuth2ProviderExtension(
                        tenant_id,
                        is_local_development=is_local_development,
                        idp_id_for_multi=idp_id,
                    )

                # cii has its own format of callback url;
                # there is no client id that is passed.
                if oa2ext.ext_type == "cii":
                    url = (
                        f"{oa2ext.identity_redirect_url}?redirect={oa2ext.callback_url}"
                    )
                # for globus, we set the scope parameter as well
                elif oa2ext.ext_type == "globus":
                    url = (
                        f"{oa2ext.identity_redirect_url}?"
                        f"client_id={oa2ext.client_id}&"
                        f"redirect_uri={oa2ext.callback_url}&"
                        "response_type=code&scope=openid profile"
                    )
                # when the extension type is ldap, we redirect to the login resource
                elif oa2ext.ext_type == "ldap":
                    pass
                # In all other cases, redirect to the oa2ext identity redirect url
                else:
                    url = (
                        f"{oa2ext.identity_redirect_url}?"
                        f"client_id={oa2ext.client_id}&"
                        f"redirect_uri={oa2ext.callback_url}&"
                        "response_type=code"
                    )
                if not oa2ext.ext_type == "ldap":
                    logger.debug(f"final redirect URL: {url}")
                    return redirect(url)
            logger.debug("username not in session; issuing redirect to login.")
            return redirect(
                url_for(
                    "loginresource",
                    client_id=client_id,
                    redirect_uri=client_redirect_uri,
                    state=client_state,
                    response_type=response_type,
                )
            )
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")

        headers = {"Content-Type": "text/html"}
        display_name = ""
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"No client available; e: {e}")
        context = {
            "error": "",
            "username": session["username"],
            "tenant_id": tenant_id,
            "client_display_name": display_name,
            "client_id": client_id,
            "client_redirect_uri": client_redirect_uri,
            "client_response_type": response_type,
            "client_state": client_state,
            "device_login": session.get("device_login", None),
            "user_code": request.args.get("user_code", None),
        }

        return make_response(render_template("authorize.html", **context), 200, headers)

    def post(self):
        logger.info("top of POST /v3/oauth2/authorize")
        # selecting a tenant id is required before logging in -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug("did not tenant_id on g or in session; raising error.")
            raise errors.ResourceError(
                "Tenant ID missing from session. Please logout and select a tenant."
            )
        client_display_name = request.form.get("client_display_name")
        try:
            username = session["username"]
        except KeyError:
            logger.debug(
                "did not find username in session; this is an error. "
                f"raising error. session: {session};"
            )
            raise errors.ResourceError(
                "username missing from session. Please login to continue."
            )
        approve = request.form.get("approve")
        if not approve:
            logger.debug("user did not approve.")
            headers = {"Content-Type": "text/html"}
            context = {
                "error": (
                    f"To proceed with authorization application: "
                    f"{client_display_name}, you must approve the request."
                )
            }
            return make_response(
                render_template("authorize.html", **context), 200, headers
            )

        state = request.form.get("client_state")
        client_response_type = request.form.get("client_response_type")
        client_id = request.form.get("client_id", None)
        if not client_id:
            logger.debug("client_id missing from form.")
            raise errors.ResourceError("client_id missing.")

        # retrieve client data from form and db -
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            logger.debug(f"client not found in db. client_id: {client_id}")
            raise errors.ResourceError(f"Invalid client: {client_id}")

        # check original response_type passed in by the client and
        # make sure grant type supported by the tenant --
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        mfa_config = json.loads(config.mfa_config)

        if mfa_config:
            if session.get("mfa_required") is True:
                if check_mfa_expired(mfa_config, session.get("mfa_timestamp", None)):
                    session["mfa_validated"] = False
                if session.get("mfa_validated") is False:
                    logger.debug("Authorize Resource: Redirecting to MFA")
                    client_redirect_uri = request.form.get("client_redirect_uri", None)
                    client_state = request.form.get("client_state", None)
                    # TODO: Define the client_state and client_redirect_uri
                    return redirect(
                        url_for(
                            "mfaresource",
                            client_id=client_id,
                            redirect_uri=client_redirect_uri,
                            state=client_state,
                            response_type=client_response_type,
                            user_code=request.args.get("user_code", None),
                            source="authorize",
                        )
                    )

        # implicit grant type -------------------------------------------------------
        if client_response_type == "token":
            if "implicit" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The implicit grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )
            # create the access token for the client -------
            # call /v3/tokens to generate access token
            url = f"{g.request_tenant_base_url}/v3/tokens"
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
            # if the idp_id is in the session, set it as an additional claim
            if session.get("idp_id"):
                content["claims"]["tapis/idp_id"] = session.get("idp_id")
            try:
                logger.debug(
                    "calling tokens API to create a token for implicit grant type;"
                    f"content: {content}"
                )
                tokens = t.tokens.create_token(**content, use_basic_auth=False)
                logger.debug(f"got tokens response: {tokens}")
            except Exception as e:
                logger.error(
                    "Got exception trying to POST to /v3/tokens endpoint. "
                    f"Exception: {e};"
                    f"content: {content}"
                )
                raise errors.ResourceError(
                    "Failure to generate an access token; please try again later."
                )
            try:
                access_token = tokens.access_token.access_token
                expires_in = tokens.access_token.expires_in
            except Exception as e:
                logger.error(
                    "Got exception trying to parse token in response from tokens API; "
                    f"e: {e}"
                )
                raise errors.ResourceError(
                    "Failure to generate an access token; please try again later."
                )
            url = (
                f"{client.callback_url}?"
                f"access_token={access_token}&"
                f"state={state}&"
                f"expires_in={expires_in}&"
                "token_type=Bearer"
            )
            logger.debug(f"issuing redirect to {client.callback_url}")
            if session.get("idp_id"):
                clear_orig_client_data()
            return redirect(url)

        # authorization_code grant type ---------------------------------------------
        elif client_response_type == "code":
            if "authorization_code" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The authorization_code grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )

            # create the authorization code for the client -
            authz_code = AuthorizationCode(
                tenant_id=tenant_id,
                username=username,
                client_id=client_id,
                client_key=client.client_key,
                tapis_idp_id=session.get("idp_id"),
                redirect_url=client.callback_url,
                code=AuthorizationCode.generate_code(),
                expiry_time=AuthorizationCode.compute_expiry(),
            )
            logger.debug("authorization code created.")
            try:
                db.session.add(authz_code)
                db.session.commit()
            except Exception as e:
                logger.error(
                    "Got exception trying to add and commit the auth code. "
                    f"e: {e}; type(e): {type(e)}"
                )
                raise errors.ResourceError(
                    "Internal error saving authorization code. Please try again later."
                )
            # issue redirect to client callback_url with authorization code:
            url = f"{client.callback_url}?code={authz_code}&state={state}"
            logger.debug(f"issuing redirect to {client.callback_url}")
            if session.get("idp_id"):
                clear_orig_client_data()
            return redirect(url)

        elif client_response_type == "device_code":
            if "device_code" not in allowable_grant_types:
                raise errors.ResourceError(
                    f"The authorization_code grant type is not allowed for this "
                    f"tenant. Allowable grant types: {allowable_grant_types}"
                )
            client_redirect_uri = request.form.get("client_redirect_uri")
            code = request.form.get("user_code")
            logger.info(f"User code passed in: {code}")

            # check that device code exists in the database
            try:
                device_code = DeviceCode.query.filter_by(
                    user_code=code, tenant_id=tenant_id, status="Entered"
                ).first()
                logger.info(f"User code entered for device code: {device_code}")
            except Exception as e:
                logger.debug(f"Error grabbing code: {code}; error: {e}")
                error = e
                client_state = request.form.get("client_state")
                context = {
                    "error": error,
                    "username": session["username"],
                    "tenant_id": tenant_id,
                    "client_display_name": client.display_name,
                    "client_id": client_id,
                    "client_redirect_uri": client_redirect_uri,
                    "client_response_type": "device_code",
                    "client_state": client_state,
                    "user_code": code,
                    "device_login": session.get("device_login", ""),
                }
                return make_response(
                    render_template("authorize.html", **context), 200, headers
                )

            headers = {"Content-Type": "text/html"}
            ttl = request.form.get("ttl", DEFAULT_DEVICE_CODE_TOKEN_TTL)
            if ttl == "" or ttl == " ":
                ttl = DEFAULT_DEVICE_CODE_TOKEN_TTL
            try:
                int(ttl)
            except ValueError:
                client_state = request.form.get("client_state")
                context = {
                    "error": "Please enter an integer",
                    "username": session["username"],
                    "tenant_id": tenant_id,
                    "client_display_name": client.display_name,
                    "client_id": client_id,
                    "client_redirect_uri": client_redirect_uri,
                    "client_response_type": "device_code",
                    "client_state": client_state,
                    "user_code": code,
                    "device_login": session.get("device_login", ""),
                }
                return make_response(
                    render_template("authorize.html", **context), 200, headers
                )
            if int(ttl) > 0:
                device_code.access_token_ttl = int(ttl) * 60 * 60 * 24
            if session.get("idp_id"):
                device_code.tapis_idp_id = session.get("idp_id")
            try:
                logger.info(f"Updating device code: {device_code}")
                db.session.commit()
            except Exception as e:
                logger.error(f"Error updating {device_code}; e: {e}")
                context = {
                    "error": e,
                    "username": session["username"],
                    "tenant_id": tenant_id,
                    "client_display_name": client.display_name,
                    "client_id": client_id,
                    "client_redirect_uri": client_redirect_uri,
                    "client_response_type": "device_code",
                    "client_state": client_state,
                    "user_code": code,
                    "device_login": session.get("device_login", ""),
                }
                return make_response(
                    render_template("authorize.html", **context), 200, headers
                )
            session.pop("device_login")
            if session.get("idp_id"):
                clear_orig_client_data()
            return make_response(render_template("success.html"), 200, headers)


class LogoutResource(Resource):
    def get(self):
        # selecting a tenant id is required before logging in -
        headers = {"Content-Type": "text/html"}
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect "
                f"to SetTenantResource. session: {session}"
            )
            # reset the session in case there is some weird cruft
            session.pop("username", None)
            session.pop("tenant_id", None)
            make_response(
                render_template(
                    "logout.html", logout_message="You have been logged out."
                ),
                200,
                headers,
            )
        return make_response(render_template("logout.html"), 200, headers)

    def post(self):
        headers = {"Content-Type": "text/html"}
        # process the logout form -
        if request.form.get("logout"):
            logout()
            make_response(
                render_template(
                    "logout.html", logout_message="You have been logged out."
                ),
                200,
                headers,
            )
        # if they submitted the logout form but did not check the box then
        # just return them to the logout form -
        return redirect(url_for("webapptokenandredirect"))
