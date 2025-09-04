from flask import g, request, session
from tapisservice import errors as common_errors
from tapisservice.config import conf

# get the logger instance -
from tapisservice.logs import get_logger

# from common import auth
from tapisservice.tapisflask import auth

from service import t
from service.ldap import check_username_password
from service.models import tenant_configs_cache

logger = get_logger(__name__)


def authn_and_authz():
    """
    Entry point for checking authentication and authorization
    for all requests to the authenticator.
    :return: None
    """
    # Setting session.permanent = True means that the session will survive
    # even after the user closes their browser.
    # session.permanent = True
    # session.permanent_session_lifetime = datetime.timedelta(seconds=15)
    # if we know the tenant_id based on the request base URL then do the following:
    #   1. look up the session expiry for the tenant based on the tenant config
    #      and set it on the session object
    #   2. expire the session (ie., logout()) if the session is older than the expiry
    #      * requires that we store the session creation time in the session object
    authentication()
    # when running locally, the g.request_tenant_id will always be 'dev',
    # so we use the session to allow for testing other tenants locally
    if "localhost" in request.base_url:
        logger.debug(
            "localhost was in request.base_url, "
            "so we are looking to override tenant_id based on session."
        )
        try:
            if "tenant_id" in session and session["tenant_id"]:
                logger.debug(
                    f"overriding tenant_id based on session to {session['tenant_id']}."
                )
                g.request_tenant_id = session["tenant_id"]
                logger.debug(f"tenant_id has been set to {g.request_tenant_id}.")
            else:
                logger.debug("did not override g.request_tenant_id")
        except Exception as e:
            # this code should only run in local development.
            logger.debug(
                f"Got exception trying to check tenant_id in session; exception: {e}"
            )
    authorization()


def authentication():
    """
    Entry point for checking authentication for all requests to the authenticator.
    :return:
    """
    # The authenticator uses different authentication methods for different endpoints.
    # For example, the service APIs such as clients and profiles
    # wuse pure JWT authentication, hile the OAuth endpoints use Basic Authentication
    # with OAuth client credentials.
    logger.debug(
        f"Top of authentication(). base_url: {request.base_url}; "
        f"url_rule: {request.url_rule}"
    )
    if (
        not hasattr(request, "url_rule")
        or not hasattr(request.url_rule, "rule")
        or not request.url_rule.rule
    ):
        raise common_errors.ResourceError(
            "The endpoint and HTTP method combination "
            "are not available from this service."
        )

    # the metadata endpoint is publicly available
    if "/v3/oauth2/.well-known/" in request.url_rule.rule:
        logger.debug(
            ".well-known endpoint; request is allowed to be made unauthenticated."
        )
        auth.resolve_tenant_id_for_request()
        return True

    if "/v3/oauth2/jwks" in request.url_rule.rule:
        logger.debug("jwks endpoint; request is allowed to be made unauthenticated.")
        auth.resolve_tenant_id_for_request()
        return True

    # only the authenticator's own service token and tenant admins for the tenant
    # can retrieve or modify the tenant config
    if "/v3/oauth2/admin" in request.url_rule.rule:
        logger.debug(
            "admin endpoint; checking for authenticator service token "
            "or tenant admin role..."
        )
        # admin endpoints always require tapis token auth
        auth.authentication()
        # we'll need to use the request's tenant_id, so make sure it is resolved now
        auth.resolve_tenant_id_for_request()
        # first, make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(
                f"The request is for a tenant ({g.request_tenant_id}) that is not "
                f"served by this authenticator."
            )
        # we only want to honor tokens from THIS authenticator;
        # i.e., not some other authenticator. therefore, we need
        # to check that the tenant_id associated with the token (g.tenant_id)
        # is the same as THIS authenticator's tenant id;
        if g.username == conf.service_name and g.tenant_id == conf.service_tenant_id:
            logger.info(
                f"allowing admin request because username was {conf.service_name} "
                f"and tenant was {conf.service_tenant_id}"
            )
            return True
        logger.debug(
            "request token does not represent THIS authenticator: "
            f"token username: {g.username}; "
            f" request tenant: {g.tenant_id}. Now checking for tenant admin..."
        )
        # all other service accounts are not allowed to update authenticator
        if g.account_type == "service":
            raise common_errors.PermissionsError(
                "Not authorized -- service accounts are not allowed to access the"
                "authenticator admin endpoints."
            )
        # sanity check - the request tenant id should be the same as the token tenant id
        # in the remaining cases because they are all user tokens
        if not g.request_tenant_id == g.tenant_id:
            logger.error(
                f"program error -- request_tenant_id: {g.request_tenant_id} not equal "
                f"to tenant_id: {g.tenant_id} even though account type was user!"
            )
            raise common_errors.ServiceConfigError(
                f"Unexpected program error checking permissions. The tenant id of"
                f"the request ({g.request_tenant_id}) did not match the tenant id "
                f"of the access token ({g.tenant_id}). Please contact server "
                f"administrators."
            )
        # check SK for tenant admin --
        try:
            rsp = t.sk.isAdmin(tenant=g.tenant_id, user=g.username)
        except Exception as e:
            logger.error(
                "Got exception trying to check tenant admin role for "
                f"tenant: {g.tenant_id} and user: {g.username}; "
                f"exception: {e}"
            )
            raise common_errors.PermissionsError(
                "Could not check tenant admin role with SK; this role is required for "
                "accessing the authenticator admin endpoints."
            )
        try:
            if rsp.isAuthorized:
                logger.info(
                    f"user: {g.username} had tenant admin role for "
                    f"tenant {g.tenant_id}; allowing request."
                )
                return True
            else:
                logger.info(
                    f"user: {g.username} DID NOT have tenant admin role for "
                    f"tenant {g.tenant_id}; NOT allowing request."
                )
                raise common_errors.PermissionsError(
                    "Permission denied -- Tenant admin role required for accessing "
                    "the authenticator admin endpoints."
                )
        except Exception as e:
            logger.error(
                "got exception trying to check isAuthorized property "
                "from isAdmin() call to SK. "
                f"username: {g.username}; tenant: {g.tenant_id}; rsp: {rsp}; e: {e}"
            )
            logger.info(
                f"user: {g.username} DID NOT have tenant admin role for "
                f"tenant {g.tenant_id}; NOT allowing request."
            )
            raise common_errors.PermissionsError(
                "Permission denied -- Tenant admin role required for accessing the "
                "authenticator admin endpoints."
            )

    # no credentials required on the authorize, login and oa2 extension pages
    if (
        "/v3/oauth2/authorize" in request.url_rule.rule
        or "/v3/oauth2/login" in request.url_rule.rule
        or "/oauth2/extensions" in request.url_rule.rule
        or "v3/oauth2/mfa" in request.url_rule.rule
        or "/v3/oauth2/device" in request.url_rule.rule
    ):
        # always resolve the request tenant id based on the URL:
        logger.debug("authorize, login or oa2 extension page. Resolving tenant_id")
        auth.resolve_tenant_id_for_request()
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError(
                "Unable to resolve tenant_id for request."
            )
        # make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(
                f"The request is for a tenant ({g.request_tenant_id}) that is not "
                f"served by this authenticator."
            )
        return True

    # token should come from `Authorization: Bearer $token` header
    # rather than x-tapis-token. this endpoint takes both and
    # converts Authorization to x-tapis-token for simplicity
    if "/v3/oauth2/userinfo/oidc" in request.url_rule.rule:
        logger.debug(
            f"top of /v3/oauth2/userinfo/oidc auth: request.headers: {request.headers}"
        )

        auth_token = request.headers.get("Authorization")
        if (
            auth_token
            and auth_token.startswith("Bearer ")
            and not request.headers.get("X-Tapis-Token")
        ):
            try:
                # overwrite the headers via wsgi environ.
                # request.headers itself is read-only
                tapis_token = auth_token.replace("Bearer ", "")
                logger.debug(
                    f"found auth header; setting environ X-Tapis-Token to {tapis_token}"
                )
                # modify the WSGI environment directly
                # wsgi requires headers be uppercase, no dashes,
                # and prefixed with 'HTTP_'
                request.environ["HTTP_X_TAPIS_TOKEN"] = tapis_token
            except Exception as e:
                logger.error(
                    f"found auth header, but failed to parse it; exception: {e}"
                )

        # debug logs
        try:
            headers = request.headers
            logger.debug(
                f"before auth.authentication(). request.headers: {headers.keys()}"
            )
        except Exception:
            pass

        # tokens might have aud, if jwt.decode in tapisservice doesn't specify
        # expected aud you'll get invalid aud.
        # Either we can somehow pop aud or specify to
        #   jwt.decode(
        #       options={'verify_aud': False}
        #   )
        # Instead of verify = false we can also specify a list of valid auds.
        # Pop aud would require re-encoding+signing key.
        # We don't have private tenant key in auth though.
        # Ignoring for now, only bookstack looks for this when running their auth.
        # resolve_tenant_id_for_request decode needs aud to expect
        # https://github.com/jpadilla/pyjwt/blob/master/docs/usage.rst#audience-claim-aud
        # Edit, expected_aud now exists. Bookstack asks for aud == client_id.
        # For now we'll just allow any aud, especially as this is one endpoint.

        auth.authentication(expected_aud=["*"])
        # always resolve the request tenant id based on the URL:
        auth.resolve_tenant_id_for_request()
        # make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(
                f"The request is for a tenant ({g.request_tenant_id}) that is not "
                f"served by this authenticator."
            )
        logger.debug(
            "End of v3/oauth2/userinfo/oidc auth: "
            f"final request_tenant_id: {g.request_tenant_id}"
        )
        return True

    # the profiles endpoints always use standard Tapis Token auth -
    if (
        "/v3/oauth2/profiles" in request.url_rule.rule
        or "/v3/oauth2/userinfo" in request.url_rule.rule
    ):
        auth.authentication()
        # always resolve the request tenant id based on the URL:
        auth.resolve_tenant_id_for_request()
        # make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(
                f"The request is for a tenant ({g.request_tenant_id}) that is not "
                f"served by this authenticator."
            )
        return True

    # the clients endpoints need to accept both standard Tapis Token auth and basic auth
    if "/v3/oauth2/clients" in request.url_rule.rule:
        # first check for basic auth header:
        parts = get_basic_auth_parts()
        if parts:
            logger.debug("oauth2 clients page, with basic auth header.")
            # do basic auth against the ldap
            # always resolve the request tenant id based on the URL:
            auth.resolve_tenant_id_for_request()
            # make sure this request is for a tenant served by this authenticator
            if g.request_tenant_id not in conf.tenants:
                raise common_errors.PermissionsError(
                    f"The request is for a tenant ({g.request_tenant_id}) that is not "
                    f"served by this authenticator."
                )
            try:
                logger.debug(f"request_tenant_id: {g.request_tenant_id}")
            except AttributeError:
                raise common_errors.BaseTapisError(
                    "Unable to resolve tenant_id for request."
                )
            check_username_password(
                parts["tenant_id"], parts["username"], parts["password"]
            )
            return True
        else:

            logger.debug("oauth2 clients page, no basic auth header.")
            # check for a Tapis token
            auth.authentication()

            # g.username is JWT claim username g.request_username,
            # defaults to g.username unless service specifies _x_tapis_user
            # We require that request_username must be JWT username or
            # _tapis_{JWT username}.
            if (
                g.username != g.request_username
                and g.request_username != f"_tapis_{g.username}"
            ):
                raise common_errors.AuthenticationError(
                    f"Client requests requires jwt username (g.username: {g.username}) "
                    f"match request username (g.request_username: {g.request_username})"
                    f" or request username to match _tapis_{{jwt username}}."
                )

            # always resolve the request tenant id based on the URL:
            auth.resolve_tenant_id_for_request()
            try:
                logger.debug(f"request_tenant_id: {g.request_tenant_id}")
            except AttributeError:
                raise common_errors.BaseTapisError(
                    "Unable to resolve tenant_id for request."
                )
            return True

    # Token Revocation Endpoint -----
    if "/v3/oauth2/tokens/revoke" in request.url_rule.rule:
        # anyone with a token is currently allowed to revoke it.
        # the only issue is whether this tokens API should revoke it.
        try:
            # TODO - This never verifies the token. Do we need to?
            # It just checks that the request contains a JSON body.
            if request.get_json().get("token"):
                pass
            # token_str = request.get_json().get("token")
        except Exception as e:
            logger.info(
                "Got exception trying to parse JSON from request; "
                f"e: {e}; type(e):{type(e)}"
            )
            raise common_errors.AuthenticationError(
                "Unable to parse message payload; is it JSON?"
            )
        # for now, we allow any site to revoke any token.
        # we can revisit this in the future
        return True

    # Token Creation Endpoints -----
    # we've already checked the revoke endpoint specifically, so if we're here,
    # the request is to a token creation endpoint
    if "/v3/oauth2/tokens" in request.url_rule.rule:
        logger.debug("oauth2 tokens URL")
        # the tokens endpoint uses basic auth with the client;
        # logic handled in the controller
        # however, it does require the request tenant id:

        # First, check if an X-Tapis-Token header appears in the request.
        # We do not honor JWT authentication for generating new tokens,
        # but we also don't want to fail for an expired token.
        # So, we remove the token header if it is present
        if "X-Tapis-Token" in request.headers:
            logger.debug("Got an X-Tapis-Token header.")
            try:
                auth.add_headers()
                auth.validate_request_token()
            except Exception:
                # we need to set the token claims because
                # the resolve_tenant_id_for_request method depends on it:
                g.token_claims = {}
        # now, resolve the tenant_id
        try:
            auth.resolve_tenant_id_for_request()
        except Exception:
            # we need to catch and swallow permissions errors
            # having to do with an invalid JWT;
            # if the JWT is invalid, its claims (including its tenant claim)
            # will be ignored, but then resolve_tenant_id_for_request() will
            # throw an error because the None tenant_id claim
            # will not match the tenant_id of the URL.
            pass
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError(
                "Unable to resolve tenant_id for request."
            )
        # make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(
                f"The request is for a tenant ({g.request_tenant_id}) that is "
                "not served by this authenticator."
            )
        return True

    # Special v3->v2 token generation endpoint.
    if "/v3/oauth2/v2/token" in request.url_rule.rule:
        logger.debug("v2 token URL")
        # the v2/token endpoint takes a v3 token generated for a user
        # and returns a v2 token for that user

        if "X-Tapis-Token" in request.headers:
            logger.debug(
                f"Got an X-Tapis-Token header; {request.headers['X-Tapis-Token']}"
            )
            try:
                auth.authentication()
                auth.resolve_tenant_id_for_request()
            except Exception as e:
                g.token_claims = {}
                raise common_errors.BaseTapisError(
                    f"Unable to process access token; error: {e}"
                )
        else:
            logger.debug("did not receive an X-Tapis-Token header.")
            raise common_errors.BaseTapisError("Endpoint requires X-Tapis-Token.")

        return True

    # Various endpoints for the example webapp
    if (
        "/v3/oauth2/logout" in request.url_rule.rule
        or "/v3/oauth2/login" in request.url_rule.rule
        or "/v3/oauth2/tenant" in request.url_rule.rule
        or "/v3/oauth2/idp" in request.url_rule.rule
        or "/v3/oauth2/webapp" in request.url_rule.rule
        or "/v3/oauth2/portal-login" in request.url_rule.rule
    ):
        # or '/v3/oauth2/webapp/callback' in request.url_rule.rule \
        # or '/v3/oauth2/webapp/token-display' in request.url_rule.rule \
        logger.debug("call is for some token webapp page.")
        auth.resolve_tenant_id_for_request()
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError(
                "Unable to resolve tenant_id for request."
            )
        #  make sure this tenant allows the token web app
        config = tenant_configs_cache.get_config(g.request_tenant_id)
        logger.debug(f"got tenant config: {config.serialize}")
        if not config.use_token_webapp:
            logger.info(
                f"tenant {g.request_tenant_id} not configured for the token webapp. "
                "Raising error"
            )
            raise common_errors.PermissionsError(
                "This tenant is not configured to use the Token Webapp."
            )

        return True


def get_basic_auth_parts():
    """
    Checks if the request contains the necessary headers for basic authentication,
    and if so, returns a dictionary containing: tenant_id, username, and password.
    Otherwise, returns None.
    NOTE: This method DOES NOT actually validate the password.
    That is the role of the caller.
    :return: (dict or None) - Either a python dictionary with the following keys:
        * tenant_id: The tenant_id to use to check this basic auth.
        * username: the "username" field of the Basic Auth header (decoded).
        * password: the "password" field of the Basic Auth header (decoded).
    """
    if "X-Tapis-Tenant" and "Authorization" in request.headers:
        auth = request.authorization
        return {
            "tenant_id": request.headers.get("X-Tapis-Tenant-Id"),
            "username": auth.username,
            "password": auth.password,
        }
    return None


def authorization():
    """
    Entry point for checking authorization for all requests to the authenticator.
    :return:
    """
    # TODO - it is currently an open question where authorization data
    # should live for authenticator requests.
    return True
