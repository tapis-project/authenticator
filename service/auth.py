from flask import request

from common import auth
from common import errors as common_errors
from tapy.dyna import DynaTapy

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
    authorization()


def authentication():
    """
    Entry point for checking authentication for all requests to the authenticator.
    :return:
    """
    # The authenticator uses different authentication methods for different endpoints. For example, the service
    # APIs such as clients and profiles use pure JWT authentication, while the OAuth endpoints use Basic Authentication
    # with OAuth client credentials.
    logger.debug(f"URL RULE: {request.url_rule}")
    if not hasattr(request, 'url_rule') or not hasattr(request.url_rule, 'rule') or not request.url_rule.rule:
        raise common_errors.ResourceError("The endpoint and HTTP method combination "
                                          "are not available from this service.")

    # no credentials required on the login page
    if '/v3/oauth2/authorize' in request.url_rule.rule:
        return True

    # the profiles endpoints always use standard Tapis Token auth -
    if '/v3/oauth2/profiles' in request.url_rule.rule:
        auth.authentication()
        return True

    # the clients endpoints need to accept both standard Tapis Token auth and basic auth,
    if '/v3/oauth2/clients' in request.url_rule.rule:
        # first check for basic auth header:
        parts = get_basic_auth_parts()
        if parts:
            # do basic auth against the ldap
            check_username_password(parts['tenant_id'], parts['username'], parts['password'])
            return True
        else:
            # check for a Tapis token
            auth.authentication()
            return True

    if '/v3/oauth2/tokens' in request.url_rule.rule:
        # todo - any any custom logic for the tokens API
        pass


def get_basic_auth_parts():
    """
    Checks if the request contains the neceassary headers for basic authentication, and if so, returns a dictionary
    containing the tenant_id, username, and passwrod. Otherwise, returns None.
    NOTE: This method DOES NOT actually validate the password. That is the role of the caller.
    :return: (dict or None) - Either a python dictionary with the following keys:
        * tenant_id: The tenant_id to use to check this basic auth.
        * username: the "username" field of the Basic Auth header (decoded).
        * password: the "password" field of the Basic Auth header (decoded).
    """
    if 'X-Tapis-Tenant-Id' and 'Authorization' in request.headers:
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