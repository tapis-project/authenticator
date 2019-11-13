from flask import request

from common import auth

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
    # with OAuth client credentials
    if '/clients' in request.url_rule.rule \
        or '/profiles' in request.url_rule.rule:
        # use the standard Tapis request token to
        auth.authentication()


def authorization():
    """
    Entry point for checking authorization for all requests to the authenticator.
    :return:
    """
    # todo - it is currently an open question where authorization data should live for authenticator requests.
    #
    return True