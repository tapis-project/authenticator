from flask import g, request, session
from tapisservice import errors
from tapisservice.config import conf
from tapisservice.logs import get_logger

from service.models import Client, token_webapp_clients

logger = get_logger(__name__)


def check_client(use_session=False):
    """
    Utility function used by several controller classes.
    Checks the request for associated client query parameters,
    validates them against the client registered in the DB
    and returns the associated objects.

    If use_session is True, this function will check for the
    client credentials out of the session. This is
    used when the tenant is configured with a 3rd-party OAuth2 server
    that does not pass back the original client credentials.
    """
    # tenant_id should be determined by the request URL -
    tenant_id = session.get("tenant_id")
    if not tenant_id:
        tenant_id = g.request_tenant_id
    if not tenant_id:
        logout()
        raise errors.ResourceError("tenant_id missing.")
    if tenant_id not in conf.tenants:
        logout()
        raise errors.ResourceError(
            "This application is not configured to "
            f"serve the requested tenant {tenant_id}."
        )
    if use_session:
        # note: it is possible that the use_session is true
        #       (because this is a third-party OAuth situation,
        #       but the client is NOT in the session
        logger.debug("Inside check_client, using session")
        client_id = session.get("orig_client_id")
        client_redirect_uri = session.get("orig_client_redirect_uri")
        response_type = session.get("orig_client_response_type")
        client_state = session.get("orig_client_state")
        if not client_id:
            logger.debug(
                "The use_session was true, but we didn't find a client "
                "in the session so we are looking in query parameters."
            )
            # We didn't find the client_id in the session
            # it better have been passed in the query parameters
            # In this case, we expect to find everything in the query params;
            # no mix and match!
            client_id = request.args.get("client_id")
            client_redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            # state is optional -
            client_state = request.args.get("state")

    else:
        logger.debug(
            "Inside check_client, NOT using session; expecting args in client."
        )
        # required query parameters:
        client_id = request.args.get("client_id")
        client_redirect_uri = request.args.get("redirect_uri")
        response_type = request.args.get("response_type")
        # state is optional -
        client_state = request.args.get("state")
    if not client_id:
        logger.debug(f"No client_id found; use_session: {use_session}")
        logout()
        raise errors.ResourceError("Required query parameter client_id missing.")
    # make sure the client exists and the redirect_uri matches
    client = Client.query.filter_by(tenant_id=tenant_id, client_id=client_id).first()
    if not client:
        logout()
        raise errors.ResourceError("Invalid client.")

    # Device Code logins do not require the client to have even registered
    # a redirect uri and the flow does not set a response_type
    if "device_login" in session:
        return client_id, None, client_state, client, response_type
    if (
        not response_type == "code"
        and not response_type == "token"
        and not response_type == "device_code"
    ):
        logout()
        raise errors.ResourceError(
            "Required query parameter response_type missing or not supported."
        )
    if not client_redirect_uri:
        logout()
        raise errors.ResourceError("Required query parameter redirect_uri missing.")
    if not client.callback_url == client_redirect_uri:
        logout()
        # cgarcia - I'm not sure if the uris should be exact or
        # if only domain should match. But I'll leave this as is.
        logger.debug(
            "redirect_uri query parameter does not match registered "
            "callback_url for the client. "
            f"redirect_uri: {client_redirect_uri} "
            f"callback_url: {client.callback_url}"
        )
        raise errors.ResourceError(
            "redirect_uri query parameter does not match the "
            "registered callback_url for the client."
        )
    return client_id, client_redirect_uri, client_state, client, response_type


def get_tokenapp_client(tenant_id=None):
    """
    Looks up the client information associated with the Token Webapp
    for a specific tenant. If no tenant is specified,
    this function will attempt to get the tenant from the
    request context and then the session.
    :param tenant_id: The tenant id for the client of interest.
    :return:
    """
    if not tenant_id:
        tenant_id = session.get("tenant_id")
    if not tenant_id:
        try:
            tenant_id = g.tenant_id
        except AttributeError:
            pass
    if not tenant_id:
        try:
            tenant_id = g.request_tenant_id
        except AttributeError:
            pass

    if not tenant_id:
        logger.error("get_tokenapp_client could not determine the tenant_id.")
        raise errors.ResourceError(
            msg="The tenant could not be established from the session."
        )
    # look up the client data by tenant id:
    client_data = token_webapp_clients[tenant_id]
    # if the authenticator is running locally, get the "local" client data:
    if "localhost" in request.base_url:
        client_data = token_webapp_clients[f"local.{tenant_id}"]
    return client_data


def logout():
    """
    Helper function to reset the session whenever a logout needs to occur.
    """
    session.pop("username", None)
    session.pop("tenant_id", None)
    session.pop("access_token", None)
    session.pop("device_login", None)
    session.pop("mfa_required", None)
    session.pop("mfa_validated", None)
    session.pop("state", None)
    session.pop("idp_id", None)
    session.pop("orig_client_id", None)
    session.pop("orig_client_redirect_uri", None)
    session.pop("orig_client_response_type", None)
    session.pop("orig_client_state", None)


def get_user_data_rights(username):
    # Implement logic to retrieve the list of data releases the user has access to
    # This function should return a list of strings representing data releases
    return [
        "release1",
        "release2",
        "lsst-sqre",
        "admin:jupyterlab",
        "admin",
        "jupyterlab",
        "square",
        "tacc-spherex",
    ]


def clear_orig_client_data():
    session.pop("orig_client_id", None)
    session.pop("orig_client_redirect_uri", None)
    session.pop("orig_client_response_type", None)
    session.pop("orig_client_state", None)
