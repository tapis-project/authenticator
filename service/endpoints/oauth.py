"""
This file contains the Resources responsible for handling metadata and callback functionality. # noqa

Resources:
- OAuthMetadataResource: Provides the `.well-known` endpoint for OAuth2 server metadata.
- OAuth2ProviderExtCallback: Handles callbacks from third-party OAuth2 providers,
    including token exchange and deriving the user's identity.
"""

import json

from flask import g, redirect, request, session, url_for
from flask_restful import Resource
from tapisservice import errors
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service import t
from service.helpers import check_client
from service.models import tenant_configs_cache
from service.oauth2ext import OAuth2ProviderExtension

logger = get_logger(__name__)


class OAuthMetadataResource(Resource):
    """
    Provides the .well-known endpoint.
    See https://datatracker.ietf.org/doc/html/rfc8414
    """

    def get(self):
        logger.info("top of GET /v3/oauth2/.well-known/oauth-authorization-server")
        tenant_id = g.request_tenant_id
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        tenant = t.tenant_cache.get_tenant_config(tenant_id=tenant_id)
        base_url = tenant.base_url
        metadata = {
            "issuer": f"{base_url}/v3/oauth2",
            "authorization_endpoint": f"{base_url}/v3/oauth2/authorize",
            "token_endpoint": f"{base_url}/v3/oauth2/token",
            "jwks_uri": f"{base_url}/v3/tenants/{tenant_id}",
            "registration_endpoint": f"{base_url}/v3/oauth2/clients",
            "grant_types_supported": allowable_grant_types,
        }
        return utils.ok(
            result=metadata, msg="OAuth server metadata retrieved successfully."
        )


class OAuth2ProviderExtCallback(Resource):
    """
    This controller is used for IdPs based on OAuth2 provider servers.
    It is the target of the Tapis callback URL registered
    with the 3rd party OAuth2 provider.
    It implements the following endpoint:
        GET /v3/oauth2/extensions/oa2/callback --
            receive the authorization code and exchange it for a token.
    """

    def get(self):
        logger.info("top of GET /v3/oauth2/extensions/oa2/callback")
        # use tenant id to create the tenant oa2 extension config
        tenant_id = g.request_tenant_id
        session["tenant_id"] = tenant_id
        logger.debug(f"request for tenant {tenant_id}")
        is_local_development = "localhost" in request.base_url
        oa2ext = OAuth2ProviderExtension(
            tenant_id, is_local_development=is_local_development
        )
        append_idp_to_username = False
        # for multi_idps, the idp_id should already be set in the session here
        if oa2ext.ext_type == "multi_idps":
            idp_id = session.get("idp_id")
            if not idp_id:
                raise errors.ResourceError(
                    "Unable to process callback from Identity provider. "
                    "Details: idp_id missing from session."
                )
            # Check if we need to append the idp_id to the username for this idp id
            # loop through all the idps for the one in the session,
            # and check that one for the flag, `append_idp_to_username`
            for idp in oa2ext.custom_idp_config_dict["multi_idps"]["idps"]:
                # we found the idp config
                if idp["idp_id"] == session.get("idp_id"):
                    # the append_idp_to_username attribute is optional
                    append_idp_to_username = idp.get("append_idp_to_username")
                    # either way, exit the loop because we've found the idp
                    break
            # recompute the oa2ext object based on the idp_id
            oa2ext = OAuth2ProviderExtension(
                tenant_id,
                is_local_development=is_local_development,
                idp_id_for_multi=idp_id,
            )
        # the CII OAuth2 provider does not send an authorization code,
        # it sends the token directly, so
        if oa2ext.ext_type == "cii":
            oa2ext.get_token_from_callback(request)
        else:
            # get the authorization code and validate the state variable.
            oa2ext.get_auth_code_from_callback(request)
            # exchange the authorization code for a token
            oa2ext.get_token_using_auth_code()
        # derive the user's identity from the token
        if append_idp_to_username:
            session["username"] = oa2ext.get_user_from_token(
                idp_id=session.get("idp_id")
            )
        else:
            session["username"] = oa2ext.get_user_from_token()
        # Get the origin client out of the session and then
        # redirect to authorization page
        client_id, client_redirect_uri, client_state, client, response_type = (
            check_client(use_session=True)
        )
        return redirect(
            url_for(
                "authorizeresource",
                client_id=client_id,
                redirect_uri=client_redirect_uri,
                state=client_state,
                client_display_name=client.display_name,
                response_type="code",
            )
        )
