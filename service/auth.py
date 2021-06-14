from flask import request, g, session

from common import auth
from common.config import conf
from common import errors as common_errors

from service import t
from service.models import tenant_configs_cache
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

    # only the authenticator's own service token and tenant admins for the tenant can retrieve or modify the tenant
    # config
    if '/v3/oauth2/admin' in request.url_rule.rule:
        logger.debug("admin endpoint; checking for authentictor service token or tenant admin role...")
        # admin endpoints always require tapis token auth
        auth.authentication()
        # we'll need to use the request's tenant_id, so make sure it is resolved now
        auth.resolve_tenant_id_for_request()
        # first, make sure this request is for a tenant served by this authenticator
        if g.request_tenant_id not in conf.tenants:
            raise common_errors.PermissionsError(f"The request is for a tenant ({g.request_tenant_id}) that is not "
                                                 f"served by this authenticator.")
        # we only want to honor tokens from THIS authenticator; i.e., not some other authenticator. therefore, we need
        # to check that the tenant_id associated with the token (g.tenant_id) is the same as THIS authenticator's tenant
        # id;
        if g.username == conf.service_name and g.tenant_id == conf.service_tenant_id:
            logger.info(f"allowing admin request because username was {conf.service_name} "
                        f"and tenant was {conf.service_tenant_id}")
            return True
        logger.debug(f"request token does not represent THIS authenticator: token username: {g.username};"
                     f" request tenant: {g.tenant_id}. Now checking for tenant admin...")
        # all other service accounts are not allowed to update authenticator
        if g.account_type == 'service':
            raise common_errors.PermissionsError("Not authorized -- service accounts are not allowed to access the"
                                                 "authenticator admin endpoints.")
        # sanity check -- the request tenant id should be the same as the token tenant id in the remaining cases because
        # they are all user tokens
        if not g.request_tenant_id == g.tenant_id:
            logger.error(f"program error -- g.request_tenant_id: {g.request_tenant_id} not equal to "
                         f"g.tenant_id: {g.tenant_id} even though account type was user!")
            raise common_errors.ServiceConfigError(f"Unexpected program error checking permissions. The tenant id of"
                                                   f"the request ({g.request_tenant_id})  did not match the tenant id "
                                                   f"of the access token ({g.tenant_id}). Please contact server "
                                                   f"administrators.")
        # check SK for tenant admin --
        try:
            rsp = t.sk.isAdmin(tenant=g.tenant_id, user=g.username)
        except Exception as e:
            logger.error(f"Got exception trying to check tenant admin role for tenant: {g.tenant_id} "
                         f"and user: {g.username}; exception: {e}")
            raise common_errors.PermissionsError("Could not check tenant admin role with SK; this role is required for "
                                                 "accessing the authenticator admin endpoints.")
        try:
            if rsp.isAuthorized:
                logger.info(f"user {g.username} had tenant admin role for tenant {g.tenant_id}; allowing request.")
                return True
            else:
                logger.info(f"user {g.username} DID NOT have tenant admin role for tenant {g.tenant_id}; "
                            f"NOT allowing request.")
                raise common_errors.PermissionsError("Permission denied -- Tenant admin role required for accessing "
                                                     "the authenticator admin endpoints.")
        except Exception as e:
            logger.error(f"got exception trying to check isAuthorized property from isAdmin() call to SK."
                         f"username: {g.username}; tenant: {g.tenant_id}; rsp: {rsp}; e: {e}")
            logger.info(f"user {g.username} DID NOT have tenant admin role for tenant {g.tenant_id}; "
                        f"NOT allowing request.")
            raise common_errors.PermissionsError("Permission denied -- Tenant admin role required for accessing the "
                                                 "authenticator admin endpoints.")

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
        logger.debug("call is for some token webapp page.")
        auth.resolve_tenant_id_for_request()
        try:
            logger.debug(f"request_tenant_id: {g.request_tenant_id}")
        except AttributeError:
            raise common_errors.BaseTapisError("Unable to resolve tenant_id for request.")
        #  make sure this tenant allows the token web app
        config = tenant_configs_cache.get_config(g.request_tenant_id)
        logger.debug(f"got tenant config: {config.serialize}")
        if not config.use_token_webapp:
            logger.info(f"tenant {g.request_tenant_id} not configured for the token webapp. Raising error")
            raise common_errors.PermissionsError("This tenant is not configured to use the Token Webapp.")

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
