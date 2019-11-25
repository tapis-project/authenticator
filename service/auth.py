from flask import request

from common import auth

from common import errors as common_errors
from tapy.dyna import DynaTapy

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
    # with OAuth client credentials
    logger.warning(f"URL RULE: {request.url_rule}")
    if '/v3/clients' in request.url_rule.rule \
        or '/v3/profiles' in request.url_rule.rule \
            or '/v3/oauth2' in request.url_rule.rule:
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