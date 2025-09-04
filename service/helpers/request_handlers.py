import json
import time
from datetime import datetime

import jwt
import sqlalchemy
from flask import g, jsonify, session
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
from tapisservice import errors
from tapisservice.auth import insecure_decode_jwt_to_claims, validate_token
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service import t
from service.errors import InvalidPasswordError
from service.helpers import get_user_data_rights
from service.ldap import check_username_password, get_tenant_user
from service.models import (
    AccessTokens,
    AuthorizationCode,
    Client,
    DeviceCode,
    RefreshTokens,
    Token,
    TokenRequestBody,
    db,
    tenant_configs_cache,
)

logger = get_logger(__name__)


def _handle_tokens_request(request, oidc=False):
    """
    Implements the oauth2/tokens endpoint for generating tokens
    for the following grant types:
      * password
      * authorization_code
      * refresh_token
      * device_code
    """
    if oidc or not oidc:
        logger.info("top of POST /v3/oauth2/tokens")
        # support content-type www-form by setting the body on the request
        # equal to the JSON
        if request.content_type.startswith("application/x-www-form-urlencoded"):
            logger.debug("handling x-www-form data")
            validated_body = TokenRequestBody(form=request.form)
        else:
            result = openapi_request_validator.validate(
                utils.spec, FlaskOpenAPIRequest(request)
            )
            if result.errors:
                raise errors.ResourceError(msg=f"Invalid POST data: {result.errors}.")
            validated_body = result.body
        data = Token.get_derived_values(validated_body)

        grant_type = data.get("grant_type")
        if not grant_type:
            raise errors.ResourceError(msg="Missing the required grant_type parameter.")
        logger.debug(f"processing grant_type: {grant_type}")
        tenant_id = g.request_tenant_id
        # when running locally (ONLY), we will check for a special header,
        # X-Tapis-Local-Tenant, to allow the sample webapp (also running on localhost)
        # to set a tenant other than dev.
        if "localhost" in request.base_url:
            logger.debug(
                "localhost was in the request.base_url so we are looking for "
                "X-Tapis-Local-Tenant header.."
            )
            if request.headers.get("X-Tapis-Local-Tenant"):
                tenant_id = request.headers.get("X-Tapis-Local-Tenant")
                logger.debug(
                    f"found X-Tapis-Local-Tenant; override tenant to: {tenant_id}"
                )
            else:
                logger.debug("did not find X-Tapis-Local-Tenant header.")
        else:
            logger.debug(f"localhost was NOT in request.base_urL: {request.base_url}")
        logger.debug(f"tenant_id: {tenant_id}")
        config = tenant_configs_cache.get_config(tenant_id)
        logger.debug(f"tenant config: {config}")
        # check if grant type is even allowed for this tenant --
        allowable_grant_types = json.loads(config.allowable_grant_types)
        if grant_type not in allowable_grant_types:
            raise errors.ResourceError(
                f"Invalid grant_type ({grant_type}); this grant type is not allowed "
                f"for this tenant. Allowable grant types: {allowable_grant_types}"
            )
        # get headers
        auth = request.authorization
        # client id and client key are optional on the password grant type to allow
        # new users to generate tokens right away before they create a client
        if not auth:
            # kprice 1/27/2025 optionally can include client credentials in post body
            client_id = data.get("client_id")
            client_key = data.get("client_key")
        else:
            try:
                client_id = auth.username
                client_key = auth.password
            except Exception:
                raise errors.ResourceError(
                    msg="Invalid headers. Basic authentication with client id and key "
                    "required but missing."
                )
        if grant_type == "device_code":
            client_id = data.get("client_id")
            if not client_id:
                logger.debug("No client id passed in the request")
                raise errors.ResourceError(msg="Required client_id parameter missing.")

            code = data.get("device_code")
            if not code:
                logger.debug("no device code found in the request")
                raise errors.ResourceError(
                    msg="Required device_code parameter missing."
                )

            logger.debug(f"consuming device code: {code}")
            db_code = DeviceCode.validate_code(code)
            if not db_code:
                raise errors.ResourceError(msg=f"No db_code found for {code}")

            if client_id != db_code.client_id:
                msg = "Device code client id and passed in client id do not match"
                logger.debug(msg)
                raise errors.ResourceError(msg=msg)

            client_key = db_code.client_key

            DeviceCode.consume_code(code)

        if not client_id and not client_key and grant_type == "password":
            logger.debug(
                "Allowing the password grant request even though auth header missing."
            )
        # check that client is in db
        else:
            logger.debug("Checking that client exists.")
            client = Client.query.filter_by(
                tenant_id=tenant_id, client_id=client_id, client_key=client_key
            ).first()
            if not client:
                # todo -- remove session
                logger.debug(
                    f"Client with id {client_id} and key {client_key} "
                    f"not found on tenant {tenant_id}."
                )
                raise errors.ResourceError(
                    msg=f"Invalid client credentials: {client_id}, {client_key}. "
                    f"session: {session}"
                )

        # the idp_id is only set for some tenant config; we fill it in later
        idp_id = None

        # checks by grant type:
        if grant_type == "password":
            # validate user/pass against ldap
            username = data.get("username")
            password = data.get("password")
            if not username or not password:
                raise errors.ResourceError(
                    "Missing required payload data; username and password are required "
                    "for the password grant type."
                )
            try:
                check_username_password(tenant_id, username, password)
            except InvalidPasswordError:
                msg = "Invalid username/password combination."
                logger.debug(msg)
                raise errors.ResourceError(msg)
        elif grant_type == "authorization_code":
            # check the redirect uri -
            redirect_uri = data.get("redirect_uri")
            if not redirect_uri:
                raise errors.ResourceError("Required redirect_uri parameter missing.")
            if not redirect_uri == client.callback_url:
                raise errors.ResourceError(
                    "Invalid redirect_uri parameter: does not match "
                    "callback URL registered with client."
                )
            # validate the authorization code
            code = data.get("code")
            if not code:
                raise errors.ResourceError(
                    "Required authorization_code parameter missing."
                )
            # this server MUST expire the authorization code after a single use;
            # multiple uses of the same authorization code are NOT permitted
            # by the OAuth2 spec: https://tools.ietf.org/html/rfc6749#section-4.1.2
            db_code = AuthorizationCode.validate_and_consume_code(
                tenant_id=tenant_id,
                code=code,
                client_id=client_id,
                client_key=client_key,
            )
            username = db_code.username
            idp_id = db_code.tapis_idp_id
        elif grant_type == "device_code":
            username = db_code.username
            ttl = db_code.access_token_ttl
            idp_id = db_code.tapis_idp_id

            logger.debug(
                f"USERNAME: {username}; TTL: {ttl}; idp_id: {db_code.tapis_idp_id}"
            )

        elif grant_type == "refresh_token":
            logger.debug("performing refresh token checks.")
            refresh_token = data.get("refresh_token")
            if not refresh_token:
                logger.debug("no refresh_token found in the request.")
                raise errors.ResourceError("Required refresh_token parameter missing.")
            # validate the refresh token
            try:
                claims = validate_token(refresh_token)
            except Exception as e:
                logger.debug(
                    f"unable to validate the refresh_token found in the request. e: {e}"
                )
                raise errors.ResourceError("Invalid refresh_token.")
            # make sure they actually passed a refresh token:
            token_type = claims.get("tapis/token_type")
            if not token_type == "refresh":
                logger.debug(f"Did not pass a refresh_token. claims where: {claims}")
                raise errors.ResourceError(
                    "Invalid token type. The refresh_token grant type required a token "
                    f"of type refresh. Instead a token of type {token_type} was passed."
                )
            # get the access token claims associated with this refresh token:
            access_token_claims = claims.get("tapis/access_token")
            if not access_token_claims:
                msg = "Refresh token did NOT have an access_token claim."
                logger.error(msg + f" claims: {claims}")
                raise errors.ResourceError(msg=msg)
            # make sure the client_id matches the client passed in the auth header
            client_id_claim = access_token_claims.get("tapis/client_id")
            if not client_id == client_id_claim:
                msg = (
                    f"client_id from header ({client_id}) does not match the client_id "
                    f"in the token claim ({client_id_claim})."
                )
                logger.debug(msg)
                raise errors.ResourceError(msg)
            username = access_token_claims.get("tapis/username")
        else:
            logger.debug(f"Invalid grant_type: {grant_type}")
            raise errors.ResourceError("Invalid grant_type")

        # call /v3/tokens to generate access token for the user --------
        # commenting this out, not used
        # url = f"{g.request_tenant_base_url}/v3/tokens"
        # override this
        access_token_ttl = config.default_access_token_ttl

        if grant_type == "device_code":
            access_token_ttl = ttl

        content = {
            "token_tenant_id": f"{tenant_id}",
            "account_type": "user",
            "token_username": f"{username}",
            "claims": {
                "tapis/client_id": client_id,
                "tapis/grant_type": grant_type,
            },
            "access_token_ttl": access_token_ttl,
            "generate_refresh_token": False,
        }
        if idp_id:
            content["claims"]["tapis/idp_id"] = idp_id
        if oidc:
            if client_id:
                # bookstack for example requires aud to match client id
                content["claims"]["aud"] = client_id
            content["claims"]["iat"] = int(time.time())
            content["claims"]["extravar"] = username
            content["claims"]["email"] = username

        # only generate a refresh token when OAuth client is passed
        if client_id and client_key:
            content["generate_refresh_token"] = True
            refresh_token_ttl = config.default_refresh_token_ttl
            content["refresh_token_ttl"] = refresh_token_ttl

        # set the redirect_uri claim when using a web-based flow or when refreshing
        # a token that was generated using a web-based flow:
        if grant_type == "authorization_code" or (
            grant_type == "refresh_token"
            and access_token_claims.get("tapis/redirect_uri")
        ):
            content["claims"]["tapis/redirect_uri"] = client.callback_url
        # if generating a refresh token, add a claim to count the total refreshes:
        if content["generate_refresh_token"]:
            # if the grant_type is refresh_token, there should already be a claim:
            if grant_type == "refresh_token":
                refresh_count = access_token_claims.get("tapis/refresh_count") + 1
            else:
                refresh_count = 0
            content["claims"]["tapis/refresh_count"] = refresh_count
        try:
            logger.debug(f"calling tokens API to create a token; content: {content}")
            tokens = t.tokens.create_token(**content, use_basic_auth=False)
            logger.debug(f"got tokens response: {tokens}")
        except Exception as e:
            logger.error(
                f"Got exception trying to POST to /v3/tokens endpoint. Exception: {e};"
                f"content: {content}"
            )
            try:
                logger.error(f"Headers from the request: {e.request.headers}")
            except Exception as e:
                logger.error(
                    f"Couldn't get the headers from the request; exception: {e}"
                )
            raise errors.ResourceError(
                "Failure to generate an access token; please try again later."
            )
        try:
            result = {
                "access_token": {
                    "access_token": tokens.access_token.access_token,
                    "id_token": tokens.access_token.access_token,
                    "expires_at": tokens.access_token.expires_at,
                    "expires_in": tokens.access_token.expires_in,
                    "jti": tokens.access_token.jti,
                },
            }
            if content.get("generate_refresh_token"):
                result["refresh_token"] = {
                    "refresh_token": tokens.refresh_token.refresh_token,
                    "expires_at": tokens.refresh_token.expires_at,
                    "expires_in": tokens.refresh_token.expires_in,
                    "jti": tokens.refresh_token.jti,
                }
        except AttributeError as e:
            logger.error(
                "Got an unexpected AttributeError trying to parse tokens response; "
                f"e: {e}"
            )
            raise errors.ResourceError(
                "Failure to parse access token response; please try again later."
            )

        # get the claims associated with the token we just generated;
        # we don't want to bother checking the signature, etc., here
        # because we know the token was just generated by Tokens API
        # and we just want to record the claims in our db.
        new_access_token_claims = insecure_decode_jwt_to_claims(
            tokens.access_token.access_token
        )

        # add the tokens to the AccessTokens and RefreshTokens tables -------
        access_token = AccessTokens(
            jti=tokens.access_token.jti,
            subject=new_access_token_claims["sub"],
            tenant_id=tenant_id,
            username=username,
            grant_type=grant_type,
            token_ttl=access_token_ttl,
            with_refresh=content["generate_refresh_token"],
            # token_create_time has the correct default of now.
            token_expiry_time=datetime.fromisoformat(tokens.access_token.expires_at),
            token_revoked=False,
        )
        # client_id could be none, for instance, in case of password grant type.
        if client_id:
            access_token.client_id = client_id
        if content["generate_refresh_token"]:
            refresh_token = RefreshTokens(
                jti=tokens.refresh_token.jti,
                subject=new_access_token_claims["sub"],
                tenant_id=tenant_id,
                username=username,
                grant_type=grant_type,
                token_ttl=refresh_token_ttl,
                # token_create_time has the correct default of now.
                token_expiry_time=datetime.fromisoformat(
                    tokens.access_token.expires_at
                ),
                token_revoked=False,
            )
            # a client_id is always required for a refresh token
            refresh_token.client_id = client_id
        # commit tokens to the db
        try:
            db.session.add(access_token)
            if content["generate_refresh_token"]:
                db.session.add(refresh_token)
            db.session.commit()
            if content["generate_refresh_token"]:
                logger.debug("access token and refresh added to table")
            else:
                logger.debug("access token added to table")
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(
                "got exception trying to commit access_token object to db. "
                f"Exception: {e}"
            )
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        except Exception as e:
            msg = (
                f"Got unexpected exception trying to add access_token to database. "
                f"Contact system administrator. (Debug data: {e})"
            )
            logger.error(msg)
            raise errors.ResourceError(f"{msg}")

        if oidc:
            logger.info("Token endpoint with OIDC flag set.")
            response_json = {
                "access_token": result["access_token"]["access_token"],
                "expires_in": result["access_token"]["expires_in"],
                "token_type": "Bearer",
                "id_token": result["access_token"]["id_token"],
            }
            logger.info(f"OIDC response: {response_json}")
            # oidc endpoints aren't expecting our tapis 5 stanza response.
            return jsonify(response_json)

        return utils.ok(result=result, msg="Token created successfully.")


def _handle_userinfo_request(request, oidc=False):
    tenant_id = g.request_tenant_id
    if oidc:
        logger.debug(f"top of GET /v3/oauth2/userinfo/oidc - tenant_id: {tenant_id}")
    else:
        logger.debug(f"top of GET /v3/oauth2/userinfo - tenant_id: {tenant_id}")
    # note that the user info endpoint is more limited for custom oauth idp extensions
    # in general because the custom OAuth server may not provide a profile endpoint.
    custom_oa2_extension_type = tenant_configs_cache.get_custom_oa2_extension_type(
        tenant_id=tenant_id
    )
    # token should maybe already have:
    # jti iss sub exp tapis/tenant_id tapis/token_type
    # tapis/delegation tapis/delegation_sub tapis/username
    # tapis/account_type tapis/client_id tapis/grant_type

    if custom_oa2_extension_type and not custom_oa2_extension_type == "ldap":
        logger.debug(
            "Using custom auth for userinfo; "
            f"custom_oa2_extension_type: {custom_oa2_extension_type}"
        )
        logger.debug(f"g.token_claims - {g.token_claims}")
        result = {"username": g.username}
        return utils.ok(
            result=result,
            msg="User profile retrieved successfully - custom auth extension provider",
        )

    userinfo = get_tenant_user(tenant_id=tenant_id, username=g.username)

    # Rubin Science place needs
    # rubin scope with info via data_rights
    # adding data rights for specific users for rubin - test
    logger.debug(f"userinfo: {userinfo.serialize}")
    try:
        username = userinfo.get("username")
    except Exception:
        username = "TALKTODEV"
    if oidc:
        logger.debug(f"inside of oidc userinfo; username: {username}")
        # This code still doesn't matter, was attempting some debugging for rubin place
        # Kevin got Gafaelfawr to look in the "correct field" to map groups
        if username and username in ["cgarcia", "mpackard", "kprice", "jstubbs"]:
            data_rights = get_user_data_rights(username)
            if data_rights:
                userinfo["data_rights"] = " ".join(data_rights)

        # return token + userinfo as return for bookstack OIDC userinfo call.
        # bookstack at leasts needs sub claim.
        try:
            token_dict = jwt.decode(
                g.x_tapis_token, options={"verify_signature": False}
            )
            newinfo = userinfo.serialize
            newinfo.update(token_dict)
        except Exception as e:
            logger.debug(
                f"Error creating userinfo+token object: {e}, token: {g.x_tapis_token}"
            )
            raise errors.ResourceError("Error with token and userinfo objects.")
        return jsonify(newinfo)

    return utils.ok(
        result=userinfo.serialize, msg="User profile retrieved successfully."
    )
