"""
This file contains the Resources responsible for handling OpenID Connect (OIDC).

Resources:
- OIDCjwksResource: Provides the `/jwks` endpoint, returning OIDC metadata.
- OIDCTokensResource: Handles token requests for OIDC.
- OIDCUserInfoResource: Handles user info request for OIDC.
"""

from flask import g, jsonify, request
from flask_restful import Resource
from jwcrypto import jwk
from tapisservice.logs import get_logger

from service import t
from service.helpers import _handle_tokens_request, _handle_userinfo_request

logger = get_logger(__name__)


class OIDCjwksResource(Resource):
    """
    Provides the OIDC jwks endpoint.
    """

    def get(self):
        logger.info("top of GET /v3/oauth2/jwks")
        tenant_id = g.request_tenant_id
        # config = tenant_configs_cache.get_config(tenant_id)
        # allowable_grant_types = json.loads(config.allowable_grant_types)
        tenant = t.tenant_cache.get_tenant_config(tenant_id=tenant_id)

        # unpack jwks info from tenant public key
        pem_key = tenant.public_key
        key = jwk.JWK.from_pem(pem_key.encode("utf-8"))
        jwk_json = key.export(as_dict=True)
        # check for required values:
        if "alg" not in jwk_json.keys():
            jwk_json["alg"] = "RS256"
        if "typ" not in jwk_json.keys():
            jwk_json["typ"] = "JWT"
        # NOTE 2025.3.28 kprice -- these values can be hard coded
        # since they are also hard coded in tokens.
        # If these values ever change in tokens
        # we'll need to update this block.

        json_response = {"keys": [jwk_json]}
        return jsonify(json_response)
        # utils.ok(result=metadata,
        # msg='OAuth OIDC metadata retrieved successfully.')


class OIDCTokensResource(Resource):
    def post(self):
        return _handle_tokens_request(request, oidc=True)


class OIDCUserInfoResource(Resource):
    def get(self):
        return _handle_userinfo_request(request, oidc=True)
