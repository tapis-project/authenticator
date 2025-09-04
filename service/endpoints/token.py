from datetime import datetime

import requests
from flask import g, request
from flask_restful import Resource
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
from requests.auth import HTTPBasicAuth
from tapisservice import errors
from tapisservice.auth import insecure_decode_jwt_to_claims, validate_token
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service import t
from service.helpers import _handle_tokens_request
from service.models import AccessTokens, RefreshTokens, db, tenant_configs_cache

logger = get_logger(__name__)


class TokensResource(Resource):
    def post(self):
        return _handle_tokens_request(request, oidc=False)


class V2TokenResource(Resource):
    def post(self):
        logger.debug("Top of v2 Token Resource")

        token = request.headers["X-Tapis-Token"]

        claims = validate_token(token)
        username = claims.get("tapis/username")

        tenant_id = g.request_tenant_id
        config = tenant_configs_cache.get_config(tenant_id)

        logger.debug(config.serialize)

        # set url and oauth client/password in tenant config
        try:
            token_url = config.token_url
            impers_oauth_client_id = config.impers_oauth_client_id
            impers_oauth_client_secret = config.impers_oauth_client_secret
            impersadmin_uesrname = config.impersadmin_username
            impersadmin_password = config.impersadmin_password
        except Exception as e:
            logger.debug(f"Error getting configs from tenant; error: {e}")
            raise errors.ResourceError("Failure to load impersonation configs.")

        # mapping of v3 tenant id to v2 wso2 user store id. for background on this see
        # this writeup https://confluence.tacc.utexas.edu/display/CIC/Impersonation
        WSO2_USER_STORE_ID = {
            "tacc": "TACC",
            "designsafe": "TACC",
            "vdj": "VDJ",
            "iplantc": "IPLANTC",
            "jupyter-tacc-dev": "TACC",
        }
        wso2_user_store_id = WSO2_USER_STORE_ID.get(tenant_id)
        data = {
            "grant_type": "admin_password",
            "username": impersadmin_uesrname,
            "password": impersadmin_password,
            "token_username": f"{wso2_user_store_id}/{username}",
            "scope": "PRODUCTION",
        }

        try:
            logger.debug(
                f"Sending post request to v2 token endpoint for user: {username}"
            )
            response = requests.post(
                token_url,
                data=data,
                auth=HTTPBasicAuth(impers_oauth_client_id, impers_oauth_client_secret),
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Error getting v2 token; error: {e}")
            raise errors.ResourceError(
                "Failure calling v2 token endpoint; please try again later."
            )
        return response.json()


class RevokeTokensResource(Resource):
    """
    Revoke a Tapis JWT.
    """

    def post(self):
        logger.debug("top of POST /v3/oauth2/tokens/revoke")
        validated = openapi_request_validator.validate(
            utils.spec, FlaskOpenAPIRequest(request)
        )
        if validated.errors:
            raise errors.ResourceError(msg=f"Invalid POST data: {validated.errors}.")
        # validated_body = validated.body
        token_str = validated.body.token
        try:
            token_data = validate_token(token_str)
        except errors.AuthenticationError as e:
            raise errors.ResourceError(
                msg=f"Invalid POST data; could not validate the token: debug data: {e}."
            )
        # call the tokens api to actually revoke the token
        try:
            t.tokens.revoke_token(
                token=token_str, _tapis_set_x_headers_from_service=True
            )
        except Exception as e:
            logger.error(
                "Got exception trying to call the tokens api to revoke a token; "
                f"details: {e}"
            )
            raise errors.ResourceError(
                msg=f"Unexpected error trying to revoke the token: debug data: {e}."
            )
        logger.info(
            "Token has been revoked with the Tokens API, will now update our table."
        )
        # update the token to "revoked" on the correct table
        try:
            revoked_token_claims = insecure_decode_jwt_to_claims(token_str)
        except Exception as e:
            logger.error(
                "could not get claims from revoked token and therefore could not update"
                f" the token table; details: {e}"
            )
            # swallow the exception for now, nothing the user can do
            revoked_token_claims = None
        if revoked_token_claims:
            # get the token type and jti
            try:
                token_type = revoked_token_claims["tapis/token_type"]
                jti = revoked_token_claims["jti"]
            except Exception as e:
                logger.error(
                    "could not get token_typ and jti claims from revoked token and "
                    f"therefore could not update the token table; details: {e}"
                )
                token_type = None
                jti = None
            if token_type and jti:
                if token_type == "access":
                    access_token = AccessTokens.query.filter_by(jti=jti).first()
                    if not access_token:
                        logger.error(
                            f"revoked access token with jti {jti} not found on table."
                        )
                    else:
                        access_token.token_revoked = True
                        access_token.token_revoked_time = datetime.now()
                        access_token.last_update_time = datetime.now()
                        try:
                            db.session.commit()
                            logger.info(
                                f"access token with jit {jti} revoked, "
                                "and revoked status added to table."
                            )
                        except Exception as e:
                            logger.error(
                                "could not commit update to revoked access token; "
                                f"e: {e}"
                            )
                else:
                    refresh_token = RefreshTokens.query.filter_by(jti=jti).first()
                    if not refresh_token:
                        logger.error(
                            f"revoked refresh token with jti {jti} not found on table."
                        )
                    else:
                        refresh_token.token_revoked = True
                        refresh_token.token_revoked_time = datetime.now()
                        refresh_token.last_update_time = datetime.now()
                        try:
                            db.session.commit()
                            logger.info(
                                f"refresh token with jit {jti} revoked, "
                                "and revoked status added to table."
                            )
                        except Exception as e:
                            logger.error(
                                "could not commit update to revoked refresh token; "
                                f"e: {e}"
                            )
        else:
            logger.error(
                "insecure_decode_jwt_to_claims did not return claims "
                f"for the token: {token_str}"
            )
        return utils.ok(result="", msg=f"Token {token_data['jti']} has been revoked.")
