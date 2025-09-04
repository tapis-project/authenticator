import json

import sqlalchemy
from flask import g, make_response, redirect, render_template, request, session, url_for
from flask_restful import Resource
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
from tapisservice import errors
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service.models import TenantConfig, db, tenant_configs_cache
from service.oauth2ext import OAuth2ProviderExtension

logger = get_logger(__name__)


class TenantConfigResource(Resource):
    """
    Implements the /v3/oauth2/admin/config endpoints.
    """

    def get(self):
        logger.debug("top of GET /v3/oauth2/admin/config")
        # we always use the request tenant id because this should either be
        # the same as g.tenant_id (in the case of a user account) or
        # the token was the authenticator's OWN service token,
        # in which case we use the x-tapis-tenant header set
        # in the request (authenticator itself can update all tenants).
        tenant_id = g.request_tenant_id
        config = TenantConfig.query.filter_by(tenant_id=tenant_id).first()
        return utils.ok(
            result=config.serialize, msg="Tenant config object retrieved successfully."
        )

    def put(self):
        logger.debug("top of PUT /v3/oauth2/admin/config")
        tenant_id = g.request_tenant_id
        config = TenantConfig.query.filter_by(tenant_id=tenant_id).first()
        if not config:
            raise errors.ResourceError(
                f"Config for tenant {tenant_id} does not exist. "
                "Contact system administrators."
            )
        logger.debug(
            f"update request for tenant {tenant_id}; config: {config.serialize}"
        )
        result = openapi_request_validator.validate(
            utils.spec, FlaskOpenAPIRequest(request)
        )
        if result.errors:
            logger.debug(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f"Invalid PUT data: {result.errors}.")
        validated_body = result.body
        logger.debug("got past validator checks")
        # check for unsupported fields --
        logger.debug("got past additional checks for unsupported fields.")
        new_allowable_grant_types = getattr(
            validated_body, "allowable_grant_types", None
        )
        logger.debug(f"got new_allowable_grant_types: {new_allowable_grant_types}")
        # deal with the JSON columns first --
        if new_allowable_grant_types:
            try:
                new_allowable_grant_types_str = json.dumps(new_allowable_grant_types)
            except Exception as e:
                logger.debug(
                    f"got exception trying to parse allowable_grant_types; e: {e} "
                )
                raise errors.ResourceError(
                    f"Invalid allowable_grant_type ({new_allowable_grant_types}) -- "
                    f"must be JSON serializable"
                )
            # TEST THIS
            if new_allowable_grant_types is not list:
                raise errors.ResourceError(
                    f"Invalid allowable_grant_type ({new_allowable_grant_types}) "
                    "-- must be list"
                )
        # since custom_idp_configuration is of type object, the validate() method
        # returns an openapi_core.extensions.models.factories.Model object,
        # which cannot be serialized, so we go directly to the
        # flask request json object
        new_custom_idp_configuration = request.json.get("custom_idp_configuration")
        if new_custom_idp_configuration:
            try:
                new_custom_idp_configuration_str = json.dumps(
                    new_custom_idp_configuration
                )
            except Exception as e:
                logger.debug(
                    "got exception trying to parse new_custom_idp_configuration; "
                    f"e: {e}"
                )
                raise errors.ResourceError(
                    "Invalid new_custom_idp_configuration "
                    f"({new_custom_idp_configuration}) --  must be JSON serializable"
                )
            if type(new_custom_idp_configuration) is not dict:
                raise errors.ResourceError(
                    "Invalid new_custom_idp_configuration "
                    f"({new_custom_idp_configuration}) -- must be an object mapping "
                    "(i.e., dictionary)."
                )
            # TODO -- update once additional custom configuration types are supported;
            # should use the jsonschema to validate.
            if "ldap" not in new_custom_idp_configuration.keys():
                raise errors.ResourceError(
                    "Invalid new_custom_idp_configuration "
                    f"({new_custom_idp_configuration}) -- 'ldap' key required."
                )
        new_mfa_config = request.json.get("mfa_config")
        if new_mfa_config:
            try:
                new_mfa_config_str = json.dumps(new_mfa_config)
            except Exception as e:
                logger.debug(
                    f"got exception trying to parse new_mfa_configuration; e: {e}"
                )
                raise errors.ResourceError(
                    f"Invalid new_mfa_configuration ({new_mfa_config}) -- "
                    f"must be JSON serializable"
                )
            if type(new_mfa_config) is not dict:
                raise errors.ResourceError(
                    f"Invalid new_mfa_configuration ({new_mfa_config}) -- "
                    f"must be an object mapping (i.e., dictionary)."
                )
        # non-JSON columns ---
        new_use_ldap = getattr(validated_body, "use_ldap", config.use_ldap)
        new_use_token_webapp = getattr(
            validated_body, "use_token_webapp", config.use_token_webapp
        )
        new_default_access_token_ttl = getattr(
            validated_body, "default_access_token_ttl", config.default_access_token_ttl
        )
        new_default_refresh_token_ttl = getattr(
            validated_body,
            "default_refresh_token_ttl",
            config.default_refresh_token_ttl,
        )
        new_max_access_token_ttl = getattr(
            validated_body, "max_access_token_ttl", config.max_access_token_ttl
        )
        new_max_refresh_token_ttl = getattr(
            validated_body, "max_refresh_token_ttl", config.max_refresh_token_ttl
        )
        new_token_url = getattr(validated_body, "token_url", config.token_url)
        new_impers_oauth_client_id = getattr(
            validated_body, "impers_oauth_client_id", config.impers_oauth_client_id
        )
        new_impers_oauth_client_secret = getattr(
            validated_body,
            "impers_oauth_client_secret",
            config.impers_oauth_client_secret,
        )
        new_impersadmin_username = getattr(
            validated_body, "impersadmin_username", config.impersadmin_username
        )
        new_impersadmin_password = getattr(
            validated_body, "impersadmin_password", config.impersadmin_password
        )

        logger.debug("updating config object with new attributes...")
        # update the model and commit --
        if new_allowable_grant_types:
            logger.debug(
                f"new_allowable_grant_types_str: {new_allowable_grant_types_str}"
            )
            config.allowable_grant_types = new_allowable_grant_types_str
        if new_custom_idp_configuration:
            config.custom_idp_configuration = new_custom_idp_configuration_str
        if new_mfa_config:
            config.mfa_config = new_mfa_config_str
        config.use_ldap = new_use_ldap
        config.use_token_webapp = new_use_token_webapp
        config.default_access_token_ttl = new_default_access_token_ttl
        config.default_refresh_token_ttl = new_default_refresh_token_ttl
        config.max_access_token_ttl = new_max_access_token_ttl
        config.max_refresh_token_ttl = new_max_refresh_token_ttl
        config.token_url = new_token_url
        config.impers_oauth_client_id = new_impers_oauth_client_id
        config.impers_oauth_client_secret = new_impers_oauth_client_secret
        config.impersadmin_username = new_impersadmin_username
        config.impersadmin_password = new_impersadmin_password

        try:
            db.session.commit()
            logger.info(
                f"update to tenant config committed to db. config object: {config}"
            )
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(
                "got exception trying to commit updated tenant config object to db. "
                f"Exception: {e}"
            )
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid PUT data; {msg}")
        logger.debug("returning serialized tenant object.")
        # reload the config cache upon update --
        tenant_configs_cache.load_tenant_config_cache()
        return utils.ok(
            result=config.serialize, msg="Tenant config object updated successfully."
        )


class SetTenantResource(Resource):
    """
    Allows users to set the tenant they wish to authenticate with.
    Technically, these resources are not needed if
    each tenant simply uses its own base URL for the authorization server.
    This resource would be called before the Login resource is run.
    """

    def get(self):
        headers = {"Content-Type": "text/html"}

        context = {
            "error": "",
            "client_display_name": "",
            "client_id": "",
            "client_redirect_uri": "",
            "client_state": "",
        }
        return make_response(render_template("tenant.html", **context), 200, headers)

    def post(self):
        tenant_id = request.form.get("tenant")
        logger.debug(f"setting session tenant_id to: {tenant_id}")
        # client_state = request.form.get("client_state")
        session["tenant_id"] = tenant_id
        # tokenapp_client = get_tokenapp_client()
        return redirect(url_for("webapptokenandredirect"))
        # return redirect(url_for('loginresource',
        #                         client_id=tokenapp_client['client_id'],
        #                         redirect_uri=tokenapp_client['callback_url'],
        #                         state=client_state,
        #                         client_display_name=tokenapp_client['display_name'],
        #                         response_type='code'))


class SetIdentityProvider(Resource):
    """
    For tenants configured to support multiple identity providers,
    these URLs/pages allow users to select the identity provider
    they wish to authenticate with.
    """

    def get(self):
        headers = {"Content-Type": "text/html"}
        # selecting a tenant id is required before selecting an idp
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; "
                f"issuing redirect to SetTenantResource. session: {session}"
            )
            return redirect(url_for("settenantresource"))
        is_local_development = "localhost" in request.base_url
        # look up the oa2ext configuration for the tenant
        oa2ext = OAuth2ProviderExtension(
            tenant_id, is_local_development=is_local_development
        )
        context = {
            "tenant_id": tenant_id,
            "error": "",
            # allowable idps -- each must have a idp_name and a idp_id field.
            "idps": oa2ext.custom_idp_config_dict["multi_idps"]["idps"],
        }
        return make_response(
            render_template("select_idp.html", **context), 200, headers
        )

    def post(self):
        idp_id = request.form.get("idp_id")
        logger.debug(f"setting session idp_id to: {idp_id}")
        session["idp_id"] = idp_id
        return redirect(url_for("authorizeresource"))
