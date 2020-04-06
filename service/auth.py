from flask import request, g, session

from common import auth
from common import errors as common_errors

from service.ldap import check_username_password

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)



def authn_and_authz():
    """
    Entry point for checking authentication and authorization for all requests to the authenticator.
    :return:
    """
    authentication()
    # when running locally, the g.request_tenant_id will always be 'dev', so we use the session to allow for testing
    # other tenants locally
    if 'localhost' in request.base_url:
        logger.debug("localhost was in request.base_url, so we are looking to override tenant_id based on session.")
        try:
            if 'tenant_id' in session and session['tenant_id']:
                logger.debug(f"overriding tenant_id based on session to {session['tenant_id']}.")
                g.request_tenant_id = session['tenant_id']
                logger.debug(f"tenant_id has been set to {g.request_tenant_id}.")
            else:
                logger.debug("did not override g.request_tenant_id")
        except Exception as e:
            # we swallow any exception because this code should only run in local development.
            logger.debug(f"Got exception trying to check tenant_id in session; exception: {e}")
    authorization()


def authentication():
    """
    Entry point for checking authentication for all requests to the authenticator.
    :return:
    """
    # The authenticator uses different authentication methods for different endpoints. For example, the service
    # APIs such as clients and profiles use pure JWT authentication, while the OAuth endpoints use Basic Authentication
    # with OAuth client credentials.
    logger.debug(f"base_url: {request.base_url}; url_rule: {request.url_rule}")
    if not hasattr(request, 'url_rule') or not hasattr(request.url_rule, 'rule') or not request.url_rule.rule:
        raise common_errors.ResourceError("The endpoint and HTTP method combination "
                                          "are not available from this service.")

    # no credentials required on the authorize and login pages
    if '/v3/oauth2/authorize' in request.url_rule.rule or '/v3/oauth2/login' in request.url_rule.rule:
        # always resolve the request tenant id based on the URL:
        logger.debug("authorize or login page. Resolving tenant_id")
        auth.resolve_tenant_id_for_request()
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
        return True

    # the profiles endpoints always use standard Tapis Token auth -
    if '/v3/oauth2/profiles' in request.url_rule.rule:
        auth.authentication()
        # always resolve the request tenant id based on the URL:
        auth.resolve_tenant_id_for_request()
        return True

    # the clients endpoints need to accept both standard Tapis Token auth and basic auth,
    if '/v3/oauth2/clients' in request.url_rule.rule:
        # first check for basic auth header:
        parts = get_basic_auth_parts()
        if parts:
            logger.debug("oauth2 clients page, with basic auth header.")
            # do basic auth against the ldap
            # always resolve the request tenant id based on the URL:
            auth.resolve_tenant_id_for_request()
            try:
                logger.debug(f"request_tenant_id: {g.request_tenant_id}")
            except AttributeError:
                raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
            check_username_password(parts['tenant_id'], parts['username'], parts['password'])
            return True
        else:
            logger.debug("oauth2 clients page, no basic auth header.")
            # check for a Tapis token
            auth.authentication()
            # always resolve the request tenant id based on the URL:
            auth.resolve_tenant_id_for_request()
            try:
                logger.debug(f"request_tenant_id: {g.request_tenant_id}")
            except AttributeError:
                raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
            return True

    if '/v3/oauth2/tokens' in request.url_rule.rule:
        logger.debug("oauth2 tokens URL")
        # the tokens endpoint uses basic auth with the client; logic handled in the controller. # however, it does
        # require the request tenant id:

        # first, check if an X-Tapis-Token header appears in the request. We do not honor JWT authentication for
        # generating new tokens, but we also don't want to fail for an expired token. So, we remove the token header
        # if it
        if 'X-Tapis-Token' in request.headers:
            logger.debug("Got an X-Tapis-Token header.")
            try:
                auth.add_headers()
                auth.validate_request_token()
            except:
                # we need to set the token claims because the resolve_tenant_id_for_request method depends on it:
                g.token_claims = {}
        # now, resolve the tenant_id
        try:
            auth.resolve_tenant_id_for_request()
        except:
            # we need to catch and swallow permissions errors having to do with an invalid JWT; if the JWT is invalid,
            # its claims (including its tenant claim) will be ignored, but then resolve_tenant_id_for_request() will
            # throw an error because the None tenant_id claim will not match the tenant_id of the URL.
            pass
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
        return True

    if '/v3/oauth2/logout' in request.url_rule.rule \
        or '/v3/oauth2/login' in request.url_rule.rule \
        or '/v3/oauth2/tenant' in request.url_rule.rule \
        or '/v3/oauth2/webapp' in request.url_rule.rule \
        or '/v3/oauth2/portal-login' in request.url_rule.rule:
        # or '/v3/oauth2/webapp/callback' in request.url_rule.rule \
        # or '/v3/oauth2/webapp/token-display' in request.url_rule.rule \
        logger.debug("call for some other token webapp page.")
        auth.resolve_tenant_id_for_request()
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
        return True


def get_basic_auth_parts():
    """
    Checks if the request contains the necessary headers for basic authentication, and if so, returns a dictionary
    containing the tenant_id, username, and password. Otherwise, returns None.
    NOTE: This method DOES NOT actually validate the password. That is the role of the caller.
    :return: (dict or None) - Either a python dictionary with the following keys:
        * tenant_id: The tenant_id to use to check this basic auth.
        * username: the "username" field of the Basic Auth header (decoded).
        * password: the "password" field of the Basic Auth header (decoded).
    """
    if 'X-Tapis-Tenant' and 'Authorization' in request.headers:
        auth = request.authorization
        return {'tenant_id': request.headers.get('X-Tapis-Tenant-Id'),
                'username': auth.username,
                'password': auth.password}
    return None


def authorization():
    """
    Entry point for checking authorization for all requests to the authenticator.
    :return:
    """
    # todo - it is currently an open question where authorization data should live for authenticator requests.
    #
    return True
