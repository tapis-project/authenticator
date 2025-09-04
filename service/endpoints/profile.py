"""
This file contains the Resources responsible for handling user profiles and
user information in the TACC Authenticator service.

Resources:
- ProfileResource: Handles operations on a single user profile, including
  retrieval by username.
- ProfilesResource: Handles operations on multiple user profiles, including
  listing all profiles for a tenant.
- UserInfoResource: Implements the `/userinfo` endpoint, providing user
  information based on the OAuth2 standard.
"""

from flask import g, request
from flask_restful import Resource
from tapisservice import errors
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service.helpers import _handle_userinfo_request
from service.ldap import get_tenant_user, list_tenant_users
from service.models import tenant_configs_cache

logger = get_logger(__name__)


class ProfileResource(Resource):
    def get(self, username):
        logger.debug(f"top of GET /v3/profiles/{username}")
        tenant_id = g.request_tenant_id
        # note that the user info endpoint is more limited for custom
        # OAuth idp extensions in general because the custom
        # OAuth server may not provider a profile endpoint.
        custom_oa2_extension_type = tenant_configs_cache.get_custom_oa2_extension_type(
            tenant_id=tenant_id
        )
        if custom_oa2_extension_type and custom_oa2_extension_type != "ldap":
            result = {"username": g.username}
            return utils.ok(result=result, msg="User profile retrieved successfully.")
        user = get_tenant_user(tenant_id=tenant_id, username=username)
        return utils.ok(
            result=user.serialize, msg="User profile retrieved successfully."
        )


class ProfilesResource(Resource):
    """
    Work with profiles.
    """

    def get(self):
        logger.debug("top of GET /profiles")
        # get the tenant id - we use the x_tapis_tenant if that is set
        # (from some service account); otherwise, we use the tenant_id
        # associated with the JWT.
        tenant_id = getattr(g, "x_tapis_tenant", None)
        if not tenant_id:
            logger.debug("didn't find x_tapis_tenant; using tenant id in token")
            tenant_id = g.tenant_id
        logger.debug(f"using tenant_id {tenant_id}")
        # note that the profiles API is not supported for custom oauth idp
        # extensions in general because the custom OAuth server
        # may not provider a profiles listing endpoint
        if tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id):
            raise errors.ResourceError(
                f"This endpoint is not available in the {tenant_id} tenant. "
                "The profiles  endpoints are generally not available for "
                "tenants with custom OAuth IdP extensions."
            )
        try:
            limit = int(request.args.get("limit"))
        except Exception:
            limit = None
        offset = 0
        try:
            offset = int(request.args.get("offset"))
        except Exception as e:
            logger.debug(
                f"get exception parsing offset; exception: {e}; "
                "setting offset to none."
            )
        users, offset = list_tenant_users(
            tenant_id=tenant_id, limit=limit, offset=offset
        )
        msg = "Profiles retrieved successfully."
        resp = utils.ok(result=[u.serialize for u in users], msg=msg)
        resp.headers["X-Tapis-Offset"] = offset
        return resp


class UserInfoResource(Resource):
    def get(self):
        return _handle_userinfo_request(request, oidc=False)
