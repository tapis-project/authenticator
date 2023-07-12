from datetime import date, datetime
from os import access
from pydoc import cli
import requests
from requests.auth import HTTPBasicAuth
import json
import time
from flask import g, request, Response, render_template, redirect, make_response, send_from_directory, session, url_for
from flask_restful import Resource
# TODO: tapipy-1.4.0
# from openapi_core.shortcuts import RequestValidator
# from openapi_core.wrappers.flask import FlaskOpenAPIRequest
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
import sqlalchemy
import secrets

from tapisservice import errors
from tapisservice.tapisflask import utils
from tapisservice.config import conf
from tapisservice.auth import validate_token, insecure_decode_jwt_to_claims

from service import t
from service.errors import InvalidPasswordError
from service.models import db, TenantConfig, AccessTokens, RefreshTokens, Client, TokenRequestBody, Token, AuthorizationCode, DeviceCode, token_webapp_clients, tenant_configs_cache
from service.ldap import list_tenant_users, get_tenant_user, check_username_password
from service.oauth2ext import OAuth2ProviderExtension
from service.mfa import needs_mfa, call_mfa, check_mfa_expired


# get the logger instance -
from tapisservice.logs import get_logger

logger = get_logger(__name__)


DEFAULT_DEVICE_CODE_TOKEN_TTL = 30

# ------------------------------
# REST API Endpoint controllers
# ------------------------------

class OAuthMetadataResource(Resource):
    """
    Provides the .well-known endpoint.
    See https://datatracker.ietf.org/doc/html/rfc8414
    """
    def get(self):
        tenant_id = g.request_tenant_id
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        tenant = t.tenant_cache.get_tenant_config(tenant_id=tenant_id)
        base_url = tenant.base_url
        metadata = {
            'issuer': f'{base_url}/v3/oauth2',
            'authorization_endpoint': f'{base_url}/v3/oauth2/authorize',
            'token_endpoint': f'{base_url}/v3/oauth2/token',
            'jwks_uri': f'{base_url}/v3/tenants/{tenant_id}',
            'registration_endpoint': f'{base_url}/v3/oauth2/clients',
            'grant_types_supported': allowable_grant_types,
        }
        return utils.ok(result=metadata, msg='OAuth server metadata retrieved successfully.')


class ClientsResource(Resource):
    """
    Work with OAuth client objects
    """

    def get(self):
        show_inactive = request.args.get('show_inactive', False)
        if show_inactive:
            clients = Client.query.filter_by(tenant_id=g.tenant_id, username=g.username)
        else: 
            clients = Client.query.filter_by(tenant_id=g.tenant_id, username=g.username, active=True)
        return utils.ok(result=[cl.serialize for cl in clients], msg="Clients retrieved successfully.")

    def post(self):
        # TODO: tapipy-1.4.0
        # validator = RequestValidator(utils.spec)
        # result = validator.validate(FlaskOpenAPIRequest(request))
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        data = Client.get_derived_values(validated_body)
        client = Client(**data)
        logger.debug(f"creating new client; data: {data}; "
                     f"client: {client}")
        try:
            db.session.add(client)
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit client object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        except Exception as e:
            msg = f"Got unexpected exception trying to add client to database. " \
                  f"Contact system administrator. (Debug data: {e})"
            logger.error(msg)
            raise errors.ResourceError(f"{msg}")
        return utils.ok(result=client.serialize, msg="Client created successfully.")


class ClientResource(Resource):
    """
    Work with a single OAuth client objects
    """

    def get(self, client_id):
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        return utils.ok(result=client.serialize, msg='Client object retrieved successfully.')

    def put(self, client_id):
        logger.debug("top of PUT /clients/{client_id}")
        if 'client_id' in request.json:
            raise errors.ResourceError("Changing client_id not currently supported.")
        if 'client_key' in request.json:
            raise errors.ResourceError("Changing client_key not currently supported.")
        if 'description' in request.json:
            raise errors.ResourceError("Changing description not currently supported.")
        logger.debug("got past checks for unsupported fields.")
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        # TODO: for tapipy-1.4.0
        # validator = RequestValidator(utils.spec)
        # result = validator.validate(FlaskOpenAPIRequest(request))
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            print(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid PUT data: {result.errors}')
        validated_body = result.body
        new_callback_url = getattr(validated_body, 'callback_url', client.callback_url)
        new_display_name = getattr(validated_body, 'display_name', client.display_name)        
        client.callback_url = new_callback_url
        client.display_name = new_display_name
        db.session.commit()
        return utils.ok(result=client.serialize, msg="Client updated successfully")

    def delete(self, client_id):
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        client.active = False
        db.session.commit()
        return utils.ok(result=client.serialize, msg="Client status updated to inactive successfully")


class ProfilesResource(Resource):
    """
    Work with profiles.
    """

    def get(self):
        logger.debug('top of GET /profiles')
        # get the tenant id - we use the x_tapis_tenant if that is set (from some service account); otherwise, we use
        # the tenant_id associated with the JWT.
        tenant_id = getattr(g, 'x_tapis_tenant', None)
        if not tenant_id:
            logger.debug("didn't find x_tapis_tenant; using tenant id in token.")
            tenant_id = g.tenant_id
        logger.debug(f"using tenant_id {tenant_id}")
        # note that the profiles API is not supported for custom oauth idp extensions in general because the
        # custom OAuth server may not provider a profiles listing endpoint
        if tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id):
            raise errors.ResourceError(f"This endpoint is not available in the {tenant_id} tenant. The profiles "
                                       f"endpoints are generally not available for tenants with custom OAuth IdP"
                                       f"extensions.")
        try:
            limit = int(request.args.get('limit'))
        except:
            limit = None
        offset = 0
        try:
            offset = int(request.args.get('offset'))
        except Exception as e:
            logger.debug(f'get exception parsing offset; exception: {e}; setting offset to none.')
        users, offset = list_tenant_users(tenant_id=tenant_id, limit=limit, offset=offset)
        resp = utils.ok(result=[u.serialize for u in users], msg="Profiles retrieved successfully.")
        resp.headers['X-Tapis-Offset'] = offset
        return resp


class UserInfoResource(Resource):
    def get(self):
        logger.debug(f'top of GET /userinfo')
        tenant_id = g.request_tenant_id
        # note that the user info endpoint is more limited for custom oauth idp extensions in general because the
        # custom OAuth server may not provider a profile endpoint.
        custom_oa2_extension_type = tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id)
        if custom_oa2_extension_type and not custom_oa2_extension_type == 'ldap':
            result = {"username": g.username}
            return utils.ok(result=result, msg="User profile retrieved successfully.")

        user = get_tenant_user(tenant_id=tenant_id, username=g.username)
        return utils.ok(result=user.serialize, msg="User profile retrieved successfully.")


class ProfileResource(Resource):
    def get(self, username):
        logger.debug(f'top of GET /profiles/{username}')
        tenant_id = g.request_tenant_id
        # note that the user info endpoint is more limited for custom oauth idp extensions in general because the
        # custom OAuth server may not provider a profile endpoint.
        custom_oa2_extension_type = tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id)
        if custom_oa2_extension_type and not custom_oa2_extension_type == 'ldap':
            result = {"username": g.username}
            return utils.ok(result=result, msg="User profile retrieved successfully.")
        user = get_tenant_user(tenant_id=tenant_id, username=username)
        return utils.ok(result=user.serialize, msg="User profile retrieved successfully.")


class TenantConfigResource(Resource):
    """
    Implements the /v3/oauth2/admin/config endpoints.
    """

    def get(self):
        logger.debug('top of GET /v3/oauth2/admin/config')
        # we always use the request tenant id because this should either be the same as g.tenant_id (in the case of a
        # user account) or the token was the authenticator's OWN service token, in whcih case we use the x-tapis-tenant
        # header set in the reqest (authenticator itself can update all tenants).
        tenant_id = g.request_tenant_id
        config = TenantConfig.query.filter_by(tenant_id=tenant_id).first()
        return utils.ok(result=config.serialize, msg="Tenant config object retrieved successfully.")

    def put(self):
        logger.debug('top of PUT /v3/oauth2/admin/config')
        tenant_id = g.request_tenant_id
        config = TenantConfig.query.filter_by(tenant_id=tenant_id).first()
        if not config:
            raise errors.ResourceError(f"Config for tenant {tenant_id} does not exist. Contact system administrators.")
        logger.debug(f"update request for tenant {tenant_id}; config: {config.serialize}")
        # TODO: for tapipy-1.4.0
        # validator = RequestValidator(utils.spec)
        # result = validator.validate(FlaskOpenAPIRequest(request))
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            logger.debug(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid PUT data: {result.errors}.')
        validated_body = result.body
        logger.debug("got past validator checks")
        # check for unsupported fields --
        logger.debug("got past additional checks for unsupported fields.")
        new_allowable_grant_types = getattr(validated_body, 'allowable_grant_types', None)
        logger.debug(f"got new_allowable_grant_types: {new_allowable_grant_types}")
        # deal with the JSON columns first --
        if new_allowable_grant_types:
            try:
                new_allowable_grant_types_str = json.dumps(new_allowable_grant_types)
            except Exception as e:
                logger.debug(f"got exception trying to parse allowable_grant_types; e: {e} ")
                raise errors.ResourceError(f"Invalid allowable_grant_type ({new_allowable_grant_types}) -- must be "
                                           f"JSON serializable")
            if not type(new_allowable_grant_types) == list:
                raise errors.ResourceError(f"Invalid allowable_grant_type ({new_allowable_grant_types}) -- must be "
                                           f"list.")
        # since custom_idp_configuration is of type object, the validate() method returns an
        # openapi_core.extensions.models.factories.Model object, which cannot be serialized, so we go directly to the
        # flask request json object
        new_custom_idp_configuration = request.json.get('custom_idp_configuration')
        if new_custom_idp_configuration:
            try:
                new_custom_idp_configuration_str = json.dumps(new_custom_idp_configuration)
            except Exception as e:
                logger.debug(f"got exception trying to parse new_custom_idp_configuration; e: {e}")
                raise errors.ResourceError(f"Invalid new_custom_idp_configuration ({new_custom_idp_configuration}) -- "
                                           f"must be JSON serializable")
            if not type(new_custom_idp_configuration) == dict:
                raise errors.ResourceError(f"Invalid new_custom_idp_configuration ({new_custom_idp_configuration}) -- "
                                           f"must be an object mapping (i.e., dictionary).")
            # todo -- update once additional custom configuration types are supported; should use the jsonschema to
            # validate.
            if 'ldap' not in new_custom_idp_configuration.keys():
                raise errors.ResourceError(f"Invalid new_custom_idp_configuration ({new_custom_idp_configuration}) -- "
                                           f"'ldap' key required.")
        new_mfa_config = request.json.get('mfa_config')
        if new_mfa_config:
            try:
                new_mfa_config_str = json.dumps(new_mfa_config)
            except Exception as e:
                logger.debug(f"got exception trying to parse new_mfa_configuration; e: {e}")
                raise errors.ResourceError(f"Invalid new_mfa_configuration ({new_mfa_config}) -- "
                                           f"must be JSON serializable")
            if not type(new_mfa_config) == dict:
                raise errors.ResourceError(f"Invalid new_mfa_configuration ({new_mfa_config}) -- "
                                           f"must be an object mapping (i.e., dictionary).")
        # non-JSON columns ---
        new_use_ldap = getattr(validated_body, 'use_ldap', config.use_ldap)
        new_use_token_webapp = getattr(validated_body, 'use_token_webapp', config.use_token_webapp)
        new_default_access_token_ttl = getattr(validated_body, 'default_access_token_ttl',
                                               config.default_access_token_ttl)
        new_default_refresh_token_ttl = getattr(validated_body, 'default_refresh_token_ttl',
                                                config.default_refresh_token_ttl)
        new_max_access_token_ttl = getattr(validated_body, 'max_access_token_ttl', config.max_access_token_ttl)
        new_max_refresh_token_ttl = getattr(validated_body, 'max_refresh_token_ttl', config.max_refresh_token_ttl)
        new_token_url = getattr(validated_body, 'token_url', config.token_url)
        new_impers_oauth_client_id = getattr(validated_body, 'impers_oauth_client_id', config.impers_oauth_client_id)
        new_impers_oauth_client_secret = getattr(validated_body, 'impers_oauth_client_secret', config.impers_oauth_client_secret)
        new_impersadmin_username = getattr(validated_body, 'impersadmin_username', config.impersadmin_username)
        new_impersadmin_password = getattr(validated_body, 'impersadmin_password', config.impersadmin_password)

        logger.debug("updating config object with new attributes...")
        # update the model and commit --
        if new_allowable_grant_types:
            logger.debug(f"new_allowable_grant_types_str: {new_allowable_grant_types_str}")
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
            logger.info(f"update to tenant config committed to db. config object: {config}")
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit updated tenant config object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid PUT data; {msg}")
        logger.debug("returning serialized tenant object.")
        # reload the config cache upon update --
        tenant_configs_cache.load_tenant_config_cache()
        return utils.ok(result=config.serialize, msg="Tenant config object updated successfully.")


# ---------------------------------
# Authorization Server controllers
# ---------------------------------

def check_client(use_session=False):
    """
    Utility function used by several controller classes.
    Checks the request for associated client query parameters, validates them against the client registered in the DB
    and returns the associated objects.

    If use_session is True, this function will check for the client credentials out of the session. This is
    used when the tenant is configured with a 3rd-party OAuth2 sever that does not pass back the original
    client credentials.
    """
    # tenant_id should be determined by the request URL -
    tenant_id = session.get('tenant_id')
    if not tenant_id:
        tenant_id = g.request_tenant_id
    if not tenant_id:
        raise errors.ResourceError("tenant_id missing.")
    if not tenant_id in conf.tenants:
        raise errors.ResourceError(f"This application is not configured to serve the requested tenant {tenant_id}.")
    if use_session:
        client_id = session.get('orig_client_id')
        client_redirect_uri = session.get('orig_client_redirect_uri')
        response_type = session.get('orig_client_response_type')
        client_state = session.get('orig_client_state')
    else:
        # required query parameters:
        client_id = request.args.get('client_id')
        client_redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        # state is optional -
        client_state = request.args.get('state')
    if not client_id:
        raise errors.ResourceError("Required query parameter client_id missing.")
    # make sure the client exists and the redirect_uri matches
    logger.debug(f"checking for client with id: {client_id} in tenant {tenant_id}")
    client = Client.query.filter_by(tenant_id=tenant_id, client_id=client_id).first()
    if not client:
        raise errors.ResourceError("Invalid client.")
    if 'device_login' in session:
        return client_id, None, None, None, None
    if not client_redirect_uri:
        raise errors.ResourceError("Required query parameter redirect_uri missing.")
    if not response_type == 'code' and not response_type == 'token' and not response_type == 'device_code':
        raise errors.ResourceError("Required query parameter response_type missing or not supported.")
    if not client.callback_url == client_redirect_uri:
        raise errors.ResourceError(
            "redirect_uri query parameter does not match the registered callback_url for the client.")
    return client_id, client_redirect_uri, client_state, client, response_type


class SetTenantResource(Resource):
    """
    Allows users to set the tenant they wish to authenticate with. Technically, these resources are not needed if
    each tenant simply uses its own base URL for the authorization server. This resource would be called before
    the Login resource is run.
    """

    def get(self):
        headers = {'Content-Type': 'text/html'}

        context = {'error': '',
                   'client_display_name': '',
                   'client_id': '',
                   'client_redirect_uri': '',
                   'client_state': ''}
        return make_response(render_template('tenant.html', **context), 200, headers)

    def post(self):
        tenant_id = request.form.get("tenant")
        logger.debug(f"setting session tenant_id to: {tenant_id}")
        client_state = request.form.get('client_state')
        session['tenant_id'] = tenant_id
        tokenapp_client = get_tokenapp_client()
        return redirect(url_for('webapptokenandredirect'))
        # return redirect(url_for('loginresource',
        #                         client_id=tokenapp_client['client_id'],
        #                         redirect_uri=tokenapp_client['callback_url'],
        #                         state=client_state,
        #                         client_display_name=tokenapp_client['display_name'],
        #                         response_type='code'))



class SetIdentityProvider(Resource):
    """
    For tenants configured to support multiple identity providers, these URLs/pages allow users to 
    select the identity provider they wish to authenticate with. 
    """

    def get(self):
        headers = {'Content-Type': 'text/html'}
        # selecting a tenant id is required before selecting an idp
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            return redirect(url_for('settenantresource'))
        is_local_development = 'localhost' in request.base_url
        # look up the oa2ext configuration for the tenant
        oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development)
        context = {
            'tenant_id': tenant_id,
            'error': '',
             # allowable idps -- each must have a idp_name and a idp_id field.
            'idps': oa2ext.custom_idp_config_dict['multi_idps']['idps']
        }
        return make_response(render_template('select_idp.html', **context), 200, headers)

    def post(self):
        idp_id = request.form.get("idp_id")
        logger.debug(f"setting session idp_id to: {idp_id}")
        session['idp_id'] = idp_id
        return redirect(url_for('authorizeresource'))



class LoginResource(Resource):
    """
    Implements the URLs used by the Authorization server for logging a user into a specific tenant.
    """

    def get(self):
        logger.debug("Logging in")
        logger.debug(f"Session: {session}")
        client_id, client_redirect_uri, client_state, client, response_type = check_client()
        # selecting a tenant id is required before logging in -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            return redirect(url_for('settenantresource',
                                    client_id=client_id,
                                    redirect_uri=client_redirect_uri,
                                    state=client_state,
                                    response_type='code'))
        headers = {'Content-Type': 'text/html'}
        display_name = ''
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")
        context = {'error': '',
                   'client_display_name': display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_state': client_state,
                   'tenant_id': tenant_id}
        return make_response(render_template('login.html', **context), 200, headers)

    def post(self):
        # process the login form -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            raise errors.ResourceError(
                "Invalid session; please return to the original application or logout of this session.")
        headers = {'Content-Type': 'text/html'}
        client_id = request.form.get('client_id')
        client_redirect_uri = request.form.get('client_redirect_uri')
        client_state = request.form.get('client_state')
        client_display_name = request.form.get('client_display_name')
        context = {'error': '',
                   'client_display_name': client_display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_state': client_state,
                   'tenant_id': tenant_id}
        username = request.form.get("username")
        if not username:
            context['error'] = 'Username is required.'
            return make_response(render_template('login.html', **context), 200, headers)
        password = request.form.get("password")
        if not password:
            context['error'] = 'Password is required.'
            return make_response(render_template('login.html', **context), 200, headers)
        try:
            check_username_password(tenant_id=tenant_id, username=username, password=password)
        except InvalidPasswordError:
            context['error'] = 'Invalid username/password combination.'
            return make_response(render_template('login.html', **context), 200, headers)
        # the username and password were accepted; set the session and redirect to the authorization page.
        # first, check if this is a multi_idp situation
        idp_id = session.get('idp_id')
        if idp_id:
            is_local_development = 'localhost' in request.base_url
            oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development)    
            # if we have set the idp_id in the session, we need to check if this idp_id should be
            # appended to the username
            append_idp_to_username = False
            # loop through all the idps for the one in the session, and check that one for a 
            # flag, `append_idp_to_username`
            for idp in oa2ext.custom_idp_config_dict["multi_idps"]['idps']:
                # we found the idp config
                if idp['idp_id'] == session.get('idp_id'):
                    # the append_idp_to_username attribute is optional
                    append_idp_to_username = idp.get('append_idp_to_username')
                    # either way, exit the loop because we've found the idp
                    break
            if append_idp_to_username:
                username = f"{username}@{idp_id}"

        session['username'] = username
        #mfa_timestamp = session.get('mfa_timestamp', None)
        mfa_required = needs_mfa(tenant_id)
        redirect_url = 'authorizeresource'
        if mfa_required:
            redirect_url = 'mfaresource'
            session['mfa_validated'] = False
            session['mfa_required'] = True
        if session.get('device_login'):
            redirect_url = 'deviceflowresource'
        return redirect(url_for(redirect_url,
                                client_id=client_id,
                                redirect_uri=client_redirect_uri,
                                state=client_state,
                                client_display_name=client_display_name,
                                response_type='code'))

class MFAResource(Resource):
    def get(self):
        # a tenant id is required
        client_id, client_redirect_uri, client_state, client, response_type = check_client()
        tenant_id = g.request_tenant_id
        headers = {'Content-Type': 'text/html'}
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to LoginResource. session: {session}")
            return redirect(url_for('loginresource'), 200, headers)
        display_name = ''
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")
        context = {'error': '',
                   'client_display_name': display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_state': client_state,
                   'tenant_id': tenant_id,
                   'username': session.get('username')}
        return make_response(render_template('mfa.html', **context), 200, headers)

    def post(self):
        client_id, client_redirect_uri, client_state, client, response_type = check_client()
        tenant_id = g.request_tenant_id
        username = session.get('username')
        headers = {'Content-Type': 'text/html'}
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to LoginResource. session: {session}")
            return redirect(url_for('loginresource'), 200, headers)
        mfa_token = request.form.get('mfa_token')
        response = "Incorrect MFA token"
        logger.debug("MFA CODE: %s" % mfa_token)
        validated = call_mfa(mfa_token, tenant_id, username)
        display_name = ''
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"Error getting client display name. e: {e}")
        if validated:
            response_type = 'code'
            if 'device_login' in session:
                response_type = 'device_code'
            session['mfa_validated'] = True
            session['mfa_timestamp'] = time.time()
            return redirect(url_for('authorizeresource',
                                    client_id=client_id,
                                    redirect_uri=client_redirect_uri,
                                    state=client_state,
                                    client_display_name=display_name,
                                    response_type=response_type))
        else:
            context = {'error': response,
                   'username': session.get('username')}
            return make_response(render_template('mfa.html', **context), 200, headers)


class DeviceFlowResource(Resource):
    """
    Web page responsible for authentication using user code
    """
    def get(self):
        """
        Displays page with box to enter user code
        """
        logger.info("GET - Device Flow")
        tenant_id = g.request_tenant_id
        headers = {'Content-Type': 'text/html'}
        client_id = request.args.get("client_id")
        if not client_id:
            context = {'error': 'Invalid URL: client_id must be passed.'}
            return make_response(render_template('device-code.html', **context), 200, headers)
        logger.debug(f"Got client id: {client_id}")
        session['device_login'] = True
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to AuthorizeResource. session: {session}")
            return redirect(url_for('authorizeresource', client_id=client_id))
        if 'username' not in session:
            logger.debug(f"username not found in session: {session}; issuing redirect to authorize")
            return redirect(url_for('authorizeresource', client_id=client_id))
        context = {'error': '',
                   'tenant_id': tenant_id,
                   'username': session.get('username')}
        return make_response(render_template('device-code.html', **context), 200, headers)

    def post(self):
        logger.info("POST - Device Flow")
        tenant_id = g.request_tenant_id
        headers = {'Content-Type': 'text/html'}
        session['device_login'] = True
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to LoginResource. session: {session}")
            return redirect(url_for('loginresource'), 302, headers)
        if 'username' not in session:
            logger.debug(
                f"did not find username in session; issuing redirect to LoginResource. session: {session}")
            return redirect(url_for('loginresource'), 302, headers)

        user_code = request.form.get('user_code')
        device_code = DeviceCode.query.filter_by(tenant_id=tenant_id,
                                                    user_code=user_code).first()
        if not device_code:
            raise errors.ResourceError("Invalid code.")
        logger.info(f"Got device code: {device_code}")
        # ask about this
        try:
            client = Client.query.filter_by(client_id=device_code.client_id).first()
        except Exception as e:
            logger.debug(f"Unable to retrieve client: {device_code.client_id}; error: {e}")
            raise errors.ResourceError("Unable to retrieve client, cannot continue device flow")
        if device_code:  
            status = device_code.status
            if status == "Created":
                status = "Entered"
                try:
                    device_code.status = status
                    device_code.username = session.get('username')
                    db.session.commit()
                except Exception as e:
                    logger.error("Error trying to update device code entry; error: {e}")
                    raise errors.ResourceError("Unable to update device, cannot continue device flow")
                return redirect(url_for('authorizeresource',
                                        client_id=client.client_id,
                                        redirect_uri=None,
                                        state=None,
                                        client_display_name=client.display_name,
                                        response_type='device_code',
                                        user_code=user_code,
                                        device_code=device_code))
            else:
                response = "Code not eligible to be entered"
                context = {'error': response,
                        'username': session.get('username')}
                return make_response(render_template('device-code.html', **context), 200, headers)
        else:
            response = "No device code found"
            context = {'error': response,
                   'username': session.get('username')}
            return make_response(render_template('device-code.html', **context), 200, headers)
        
class DeviceCodeResource(Resource):
    """
    POST request for creating a device code
    input:
    * client_id: created by user
    optional:
    * ttl: time to live for token
    """
    def post(self):
        logger.debug("In device code resource")
        # support content-type www-form by setting the body on the request eqaul to the JSON

        # TODO: tapipy-1.4.0        
        # validator = RequestValidator(utils.spec)        
        # result = validator.validate(FlaskOpenAPIRequest(request))
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        logger.debug(f"validate_body: {validated_body}")
        client_id = validated_body.client_id
        logger.debug("Checked client_id: %s", client_id)
        tenant_id = g.request_tenant_id
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            logger.debug(f"client not found in db. client_id: {client_id}")
            raise errors.ResourceError(f'Invalid client: {client_id}')
        # we just need the part of the URL up to the "/v3/oauth2" (i.e., the base URL) so we 
        # split on that:
        device_code_base_url = request.base_url.split("/v3/oauth2")[0]
        device_code = DeviceCode(tenant_id=tenant_id,
                                 username=None,
                                 client_id=client_id,
                                 client_key=client.client_key,
                                 code=DeviceCode.generate_code(),
                                 user_code=DeviceCode.generate_user_code(),
                                 status="Created",
                                 verification_uri=DeviceCode.generate_verification_uri(tenant_id, client_id, BASE_URL=device_code_base_url),
                                 expiry_time=DeviceCode.compute_expiry(),
                                 access_token_ttl=DeviceCode.set_ttl())
        try:
            db.session.add(device_code)
            db.session.commit()
        except Exception as e:
                logger.error(f"Got exception trying to add and commit the device code. e: {e}; type(e): {type(e)}")
                raise errors.ResourceError("Internal error saving device code. Please try again later.")
        result = {}
        result['client_id'] = client_id
        result['user_code'] = device_code.user_code
        result['device_code'] = device_code.code
        result['verification_uri'] = device_code.verification_uri
        result['expires_in'] = device_code.expiry_time

        return utils.ok(result=result, msg="Token created successfully.")


class AuthorizeResource(Resource):
    """
    This resource handles the activity of a user authorizing a client (web app) to get a token. It specifies the
    name of the client requesting authorization and asks the user to approve it.
    It also serves as a starting point for various OAuth2 flows, including authorization, implicit, and
    device code. 
    """

    def get(self):
        logger.info("top of GET /oauth2/authorize")
        is_device_flow = True if 'device_login' in session else False
        logger.debug("Authorize Resource: Checking Client")
        # if we are using the multi_idp custom oa2 extension type it is possible we are being redirected here, not by the 
        # original web client, but by our select_idp page, in which case we need to get the client out of the session.
        if session.get('idp_id'):
            client_id, client_redirect_uri, client_state, client, response_type = check_client(use_session=True)
        else:    
            client_id, client_redirect_uri, client_state, client, response_type = check_client()
        if is_device_flow:
            response_type ='device_code'
        tenant_id = session.get('tenant_id')
        if not tenant_id:
            tenant_id = g.request_tenant_id
            session['tenant_id'] = tenant_id
        # check if the grant type is supported by this tenant
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        mfa_config = json.loads(config.mfa_config)

        if response_type == 'token':
            if 'implicit' not in allowable_grant_types:
                raise errors.ResourceError(f"The implicit grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")
        if response_type == 'code':
            if 'authorization_code' not in allowable_grant_types:
                raise errors.ResourceError(f"The authorization_code grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")
        if response_type == 'device_code':
            if 'device_code' not in allowable_grant_types:
                raise errors.ResourceError(f"The device_code grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")
        # if the user has not already authenticated, we need to issue a redirect to the login screen;
        # the login screen will depend on the tenant's IdP configuration
        if 'username' not in session:
            # Device login should already be in the session
            # User would have to navigate directly to authorize and put device_code response type as parameter
            if response_type == 'device_code':
                session['device_login'] = True
            # if the tenant is configured with a custom oa2 extension, start the redirect for that --
            if tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id):
                logger.debug(f"username not in session and custom oa2 extension found.")
                is_local_development = 'localhost' in request.base_url
                # we need to save the original client in the session in this case, because there is no
                # way to pass it through the third party OAuth server
                session['orig_client_id'] = client_id
                session['orig_client_redirect_uri'] = client_redirect_uri
                session['orig_client_response_type'] = response_type
                session['orig_client_state'] = client_state
                oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development)
                # If the custom oa2 extension type is "multi_idps", then the user must first select 
                # an idp from the available list. 
                if oa2ext.ext_type == 'multi_idps':
                    # Once selected, the choice goes into the session and the
                    # user is redirected back here; so first, check if the idp_id is in the session:
                    idp_id = session.get('idp_id')
                    if not idp_id:
                        # user has not selected an idp yet, so redirect them to the idp selection page:
                        return redirect(url_for('setidentityprovider'))
                    # User has selected an idp, so we need to construct a new oa2ext object that points to
                    # the selected idp extension. 
                    oa2ext = OAuth2ProviderExtension(tenant_id, 
                                                     is_local_development=is_local_development, 
                                                     idp_id_for_multi=idp_id
                                                     )

                # cii has its own format of callback url; there is no client id that is passed.
                if oa2ext.ext_type == 'cii':
                    url = f'{oa2ext.identity_redirect_url}?redirect={oa2ext.callback_url}'
                # for globus, we set the scope parameter as well
                elif oa2ext.ext_type == 'globus':
                    url = f'{oa2ext.identity_redirect_url}?client_id={oa2ext.client_id}&redirect_uri={oa2ext.callback_url}&response_type=code&scope=openid profile'
                # when the extension type is ldap, we redirect to the login resource
                elif oa2ext.ext_type == 'ldap':
                    pass
                # In all other cases, redirect to the oa2ext identity redirect url
                else:
                    url = f'{oa2ext.identity_redirect_url}?client_id={oa2ext.client_id}&redirect_uri={oa2ext.callback_url}&response_type=code'
                if not oa2ext.ext_type == 'ldap':
                    logger.debug(f"final redirect URL: {url}")
                    return redirect(url)
            logger.debug("username not in session; issuing redirect to login.")
            return redirect(url_for('loginresource',
                                    client_id=client_id,
                                    redirect_uri=client_redirect_uri,
                                    state=client_state,
                                    response_type=response_type))
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')

        logger.info(f"session in authorize: {session}")

        if session.get('mfa_required') == True:
            if check_mfa_expired(mfa_config, session.get('mfa_timestamp', None)):
                logger.info("MFA Expired")
                session['mfa_validated'] = False
            if session.get('mfa_validated') == False:
                logger.info("Authorize Resource: Redirecting to MFA")
                return redirect(url_for('mfaresource',
                                        client_id=client_id,
                                        redirect_uri=client_redirect_uri,
                                        state=client_state,
                                        response_type=response_type))

        headers = {'Content-Type': 'text/html'}
        logger.info(f"Request args: {request.args}")
        display_name = ''
        try:
            display_name = client.display_name
        except Exception as e:
            logger.debug(f"No client available; e: {e}")
        context = {'error': '',
                   'username': session['username'],
                   'tenant_id': tenant_id,
                   'client_display_name': display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_response_type': response_type,
                   'client_state': client_state,
                   'device_login': session.get('device_login', None),
                   'device_code': request.args.get('device_code', None),
                   'user_code': request.args.get('user_code', None)}

        return make_response(render_template('authorize.html', **context), 200, headers)

    def post(self):
        logger.info("top of POST /oauth2/authorize")
        # selecting a tenant id is required before logging in -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug("did not tenant_id on g or in session; raising error.")
            raise errors.ResourceError('Tenant ID missing from session. Please logout and select a tenant.')
        client_display_name = request.form.get('client_display_name')
        try:
            username = session['username']
        except KeyError:
            logger.debug(f"did not find username in session; this is an error. raising error. session: {session};")
            raise errors.ResourceError('username missing from session. Please login to continue.')
        approve = request.form.get("approve")
        if not approve:
            logger.debug("user did not approve.")
            headers = {'Content-Type': 'text/html'}
            context = {'error': f'To proceed with authorization application {client_display_name}, you '
                                f'must approve the request.'}
            return make_response(render_template('authorize.html', **context), 200, headers)

        logger.info(f"request.form: {request.form}")
        state = request.form.get("client_state")
        client_response_type = request.form.get('client_response_type')
        client_id = request.form.get('client_id', None)
        if not client_id:
                logger.debug("client_id missing from form.")
                raise errors.ResourceError("client_id missing.")

        # retrieve client data from form and db -
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            logger.debug(f"client not found in db. client_id: {client_id}")
            raise errors.ResourceError(f'Invalid client: {client_id}')

        # check original response_type passed in by the client and make sure grant type supported by the tenant --
        config = tenant_configs_cache.get_config(tenant_id)
        allowable_grant_types = json.loads(config.allowable_grant_types)
        mfa_config = json.loads(config.mfa_config)

        if mfa_config:
            if session.get('mfa_required') == True:
                if check_mfa_expired(mfa_config, session.get('mfa_timestamp', None)):
                    session['mfa_validated'] = False
                    logger.info("Authorize Resource: MFA expired, redirecting to MFA resource")
                    return redirect(url_for('mfaresource',
                                            client_id=client_id,
                                            redirect_uri=client_redirect_uri,
                                            state=client_state,
                                            response_type=client_response_type))
        
        # implicit grant type -------------------------------------------------------
        if client_response_type == 'token':
            if 'implicit' not in allowable_grant_types:
                raise errors.ResourceError(f"The implicit grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")
            # create the access token for the client -------
            # call /v3/tokens to generate access token
            url = f'{g.request_tenant_base_url}/v3/tokens'
            access_token_ttl = config.default_access_token_ttl
            content = {
                "token_tenant_id": f"{tenant_id}",
                "account_type": "user",
                "token_username": f"{username}",
                "claims": {
                    "tapis/client_id": client_id,
                    "tapis/grant_type": 'implicit',
                },
                "access_token_ttl": access_token_ttl,
                "generate_refresh_token": False,
                "tapis/redirect_uri": client.callback_url
            }
            # if the idp_id is in the session, set it as an additional claim
            if session.get('idp_id'):
                content['claims']['tapis/idp_id'] = session.get('idp_id')
            try:
                logger.debug(f"calling tokens API to create a token for implicit grant type; content: {content}")
                tokens = t.tokens.create_token(**content, use_basic_auth=False)
                logger.debug(f"got tokens response: {tokens}")
            except Exception as e:
                logger.error(f"Got exception trying to POST to /v3/tokens endpoint. Exception: {e};"
                             f"content: {content}")
                raise errors.ResourceError("Failure to generate an access token; please try again later.")
            try:
                access_token = tokens.access_token.access_token
                expires_in = tokens.access_token.expires_in
            except Exception as e:
                logger.error(f"Got exception trying to parse token from response from tokens API; e: {e}")
                raise errors.ResourceError("Failure to generate an access token; please try again later.")
            url = f'{client.callback_url}?access_token={access_token}&state={state}&expires_in={expires_in}&token_type=Bearer'
            logger.debug(f"issuing redirect to {client.callback_url}")
            return redirect(url)

        # authorization_code grant type ---------------------------------------------
        elif client_response_type == 'code':
            if 'authorization_code' not in allowable_grant_types:
                raise errors.ResourceError(f"The authorization_code grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")

            # create the authorization code for the client -
            authz_code = AuthorizationCode(tenant_id=tenant_id,
                                           username=username,
                                           client_id=client_id,
                                           client_key=client.client_key,
                                           tapis_idp_id=session.get('idp_id'),
                                           redirect_url=client.callback_url,
                                           code=AuthorizationCode.generate_code(),
                                           expiry_time=AuthorizationCode.compute_expiry())
            logger.debug("authorization code created.")
            try:
                db.session.add(authz_code)
                db.session.commit()
            except Exception as e:
                logger.error(f"Got exception trying to add and commit the auth code. e: {e}; type(e): {type(e)}")
                raise errors.ResourceError("Internal error saving authorization code. Please try again later.")
            # issue redirect to client callback_url with authorization code:
            url = f'{client.callback_url}?code={authz_code}&state={state}'
            logger.debug(f"issuing redirect to {client.callback_url}")
            return redirect(url)

        elif client_response_type == 'device_code':
            if 'device_code' not in allowable_grant_types:
                raise errors.ResourceError(f"The authorization_code grant type is not allowed for this "
                                           f"tenant. Allowable grant types: {allowable_grant_types}")
            code = request.form.get('user_code')
            logger.info(f"User code passed in: {code}")
            # check that device code exists in the database
            try:
                device_code = DeviceCode.query.filter_by(user_code=code,
                                                        tenant_id=tenant_id,
                                                        status="Entered").first()
                logger.info(f"User code entered for device code: {device_code}")
            except Exception as e:
                logger.debug(f"Error grabbing code: {code}; error: {e}")
                error = e
                client_redirect_uri = request.form.get('client_redirect_uri')
                client_state = request.form.get('client_state')
                context = {'error': error,
                   'username': session['username'],
                   'tenant_id': tenant_id,
                   'client_display_name': client.display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_response_type': 'device_code',
                   'client_state': client_state,
                   'device_code': code,
                   'device_login': session.get('device_login', '')}
                return make_response(render_template("authorize.html", **context), 200, headers)
            logger.info("Past exception")
            logger.info(f"Default TTL: {DEFAULT_DEVICE_CODE_TOKEN_TTL}")
            headers = {'Content-Type': 'text/html'}
            ttl = request.form.get("ttl", DEFAULT_DEVICE_CODE_TOKEN_TTL)
            if ttl == "" or ttl == " ":
                ttl = DEFAULT_DEVICE_CODE_TOKEN_TTL
            try:
                int(ttl)
            except ValueError:
                client_redirect_uri = request.form.get('client_redirect_uri')
                client_state = request.form.get('client_state')
                context = {'error': 'Please enter an integer',
                   'username': session['username'],
                   'tenant_id': tenant_id,
                   'client_display_name': client.display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_response_type': 'device_code',
                   'client_state': client_state,
                   'device_code': code,
                   'device_login': session.get('device_login', '')}
                print(f"User entered: {ttl} which is not an int")
                return make_response(render_template("authorize.html", **context), 200, headers)
            if int(ttl) > 0:
                logger.info("ttl > 0")
                device_code.access_token_ttl = int(ttl) * 60 * 60 * 24
                logger.info("set new access_token_ttl")
            if session.get('idp_id'):
                device_code.tapis_idp_id = session.get('idp_id')
            try:
                logger.info(f"Updating device code: {device_code}")
                db.session.commit()
            except Exception as e:
                logger.error(f"Error updating {device_code}; e: {e}")
                context = {'error': e,
                   'username': session['username'],
                   'tenant_id': tenant_id,
                   'client_display_name': client.display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_response_type': 'device_code',
                   'client_state': client_state,
                   'device_code': code,
                   'device_login': session.get('device_login', '')}
                return make_response(render_template("authorize.html", **context), 200, headers)
            session.pop('device_login')
            return make_response(render_template("success.html"), 200, headers)


class OAuth2ProviderExtCallback(Resource):
    """
    This controller is used for IdPs based on OAuth2 provider servers. It is the target of the Tapis callback
    URL registered with the 3rd party OAuth2 provider.
    It implements the following endpoint:
      GET /v3/oauth2/extensions/oa2/callback -- receive the authorization code and exchange it for a token.
    """
    def get(self):
        logger.debug("top of GET /oauth2/extensions/oa2/callback")
        # use tenant id to create the tenant oa2 extension config
        tenant_id = g.request_tenant_id
        session['tenant_id'] = tenant_id
        logger.debug(f"request for tenant {tenant_id}")
        is_local_development = 'localhost' in request.base_url
        oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development)
        append_idp_to_username = False
        # for multi_idps, the idp_id should already be set in the session here
        if oa2ext.ext_type == 'multi_idps':
            idp_id = session.get('idp_id')
            if not idp_id:
                raise errors.ResourceError(f"Unable to process callback from Identity provider. Details: idp_id missing from session.")
            # First, check if we need to append the idp_id to the username for this idp id
            # loop through all the idps for the one in the session, and check that one for a 
            # flag, `append_idp_to_username`
            for idp in oa2ext.custom_idp_config_dict["multi_idps"]['idps']:
                # we found the idp config
                if idp['idp_id'] == session.get('idp_id'):
                    # the append_idp_to_username attribute is optional
                    append_idp_to_username = idp.get('append_idp_to_username')
                    # either way, exit the loop because we've found the idp
                    break
            # recompute the oa2ext object based on the idp_id
            oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development, idp_id_for_multi=idp_id)
        # the CII OAuth2 provider does not send an authorization code, it sends the token directly, so
        #
        if oa2ext.ext_type == 'cii':
            oa2ext.get_token_from_callback(request)
        else:
            # get the authorization code and validate the state variable.
            oa2ext.get_auth_code_from_callback(request)
            # exchange the authorization code for a token
            oa2ext.get_token_using_auth_code()
        # derive the user's identity from the token
        if append_idp_to_username:
            session['username'] = oa2ext.get_user_from_token(idp_id=session.get('idp_id'))
        else:    
            session['username'] = oa2ext.get_user_from_token()
        #  Get the origin client out of the session and then redirect to authorization page
        client_id, client_redirect_uri, client_state, client, response_type = check_client(use_session=True)
        return redirect(url_for('authorizeresource',
                                client_id=client_id,
                                redirect_uri=client_redirect_uri,
                                state=client_state,
                                client_display_name=client.display_name,
                                response_type='code'))


class TokensResource(Resource):
    """
    Implements the oauth2/tokens endpoint for generating tokens for the following grant types:
      * password
      * authorization_code
      * refresh_token
      * device_code
    """

    def post(self):
        logger.debug("top of POST /oauth2/tokens")
        # support content-type www-form by setting the body on the request equal to the JSON        
        if request.content_type.startswith('application/x-www-form-urlencoded'):
            logger.debug(f"handling x-www-form data")
            validated_body = TokenRequestBody(form=request.form)
        else:
            # TODO: tapipy-1.4.0
            # validator = RequestValidator(utils.spec)        
            # result = validator.validate(FlaskOpenAPIRequest(request))
            result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
            if result.errors:
                raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
            validated_body = result.body
        data = Token.get_derived_values(validated_body)

        grant_type = data.get('grant_type')
        if not grant_type:
            raise errors.ResourceError(msg=f'Missing the required grant_type parameter.')
        logger.debug(f"processing grant_type: {grant_type}")
        tenant_id = g.request_tenant_id
        # when running locally (ONLY), we will check for a special header, X-Tapis-Local-Tenant, to allow
        # the sample webapp (also running on localhost) to set a tenant other than dev.
        if 'localhost' in request.base_url:
            logger.debug("localhost was in the request.base_url so we are looking for X-Tapis-Local-Tenant header..")
            if request.headers.get('X-Tapis-Local-Tenant'):
                tenant_id = request.headers.get('X-Tapis-Local-Tenant')
                logger.debug(f"found X-Tapis-Local-Tenant; override tenant to: {tenant_id}")
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
            raise errors.ResourceError(f"Invalid grant_type ({grant_type}); this grant type is not allowed for this "
                                       f"tenant. Allowable grant types: {allowable_grant_types}")
        # get headers
        auth = request.authorization
        # client id and client key are optional on the password grant type to allow new users to generate tokens
        # right away before they create a client
        if not auth:
            client_id = None
            client_key = None
        else:
            try:
                client_id = auth.username
                client_key = auth.password
            except Exception as e:
                raise errors.ResourceError(msg='Invalid headers. Basic authentication with client id and key '
                                               'required but missing.')
        if grant_type == 'device_code':
            client_id = data.get('client_id')
            if not client_id:
                logger.debug("No client id passed in the request")
                raise errors.ResourceError(msg="Required client_id parameter missing.")

            code = data.get('device_code')
            if not code:
                logger.debug("no device code found in the request")
                raise errors.ResourceError(msg="Required device_code parameter missing.")
            
            logger.info(f"consuming device code: {code}")
            db_code = DeviceCode.validate_and_consume_code(code)
            logger.info(f"db_code: {db_code}")
            if not db_code:
                logger.info("No db_code found")
                raise errors.ResourceError(msg=f"No db_code found for {code}")

            if client_id != db_code.client_id:
                logger.debug("Passed in client_id and client_id of code are not equal")
                raise errors.ResourceError(msg="Client IDs do not match between device code and passed in client_id")

            client_key = db_code.client_key
        
        if not client_id and not client_key and grant_type == 'password':
            logger.debug("Allowing the password grant request even though the auth header missing.")
        # check that client is in db
        else:
            logger.debug("Checking that client exists.")
            client = Client.query.filter_by(tenant_id=tenant_id, client_id=client_id, client_key=client_key).first()
            if not client:
                # todo -- remove session
                raise errors.ResourceError(msg=f'Invalid client credentials: {client_id}, {client_key}. '
                                               f'session: {session}')

        # the idp_id is only set for some tenant config; we fill it in later
        idp_id = None

        # checks by grant type:
        if grant_type == 'password':
            # validate user/pass against ldap
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                raise errors.ResourceError("Missing required payload data; username and password are required for "
                                           "the password grant type.")
            try:
                check_username_password(tenant_id, username, password)
            except InvalidPasswordError:
                msg = 'Invalid username/password combination.'
                logger.debug(msg)
                raise errors.ResourceError(msg)
        elif grant_type == 'authorization_code':
            # check the redirect uri -
            redirect_uri = data.get('redirect_uri')
            if not redirect_uri:
                raise errors.ResourceError("Required redirect_uri parameter missing.")
            if not redirect_uri == client.callback_url:
                raise errors.ResourceError("Invalid redirect_uri parameter: does not match "
                                           "callback URL registered with client.")
            # validate the authorization code
            code = data.get('code')
            if not code:
                raise errors.ResourceError("Required authorization_code parameter missing.")
            # this server MUST expire the authorization code after a single use; multiple uses of the same
            # authorization code are NOT permitted by the OAuth2 spec: https://tools.ietf.org/html/rfc6749#section-4.1.2
            db_code = AuthorizationCode.validate_and_consume_code(tenant_id=tenant_id,
                                                                  code=code,
                                                                  client_id=client_id,
                                                                  client_key=client_key)
            username = db_code.username
            idp_id = db_code.tapis_idp_id
        elif grant_type == 'device_code':
            username = db_code.username 
            ttl = db_code.access_token_ttl
            idp_id = db_code.tapis_idp_id

            logger.debug(f"USERNAME: {username}; TTL: {ttl}; idp_id: {db_code.tapis_idp_id}")

        elif grant_type == 'refresh_token':
            logger.debug("performing refresh token checks.")
            refresh_token = data.get('refresh_token')
            if not refresh_token:
                logger.debug("no refresh_token found in the request.")
                raise errors.ResourceError("Required refresh_token parameter missing.")
            # validate the refresh token
            try:
                claims = validate_token(refresh_token)
            except Exception as e:
                logger.debug(f"unable to validate the refresh_token found in the request. e: {e}")
                raise errors.ResourceError("Invalid refresh_token.")
            # make sure they actually passed a refresh token:
            token_type = claims.get('tapis/token_type')
            if not token_type == 'refresh':
                logger.debug(f"Did not pass a refresh_token. claims where: {claims}")
                raise errors.ResourceError(f"Invalid token type. The refresh_token grant type required a token of type "
                                           f"refresh. Instead a token of type {token_type} was passed.")
            # get the access token claims associated with this refresh token:
            access_token_claims = claims.get('tapis/access_token')
            if not access_token_claims:
                logger.error(f"Got a refresh token that did NOT have an access_token claim. claims: {claims}")
                raise errors.ResourceError("Invalid refresh_token format; this token was missing the access_token "
                                           "claim.")
            # make sure the client_id matches the client passed in the auth header
            client_id_claim = access_token_claims.get('tapis/client_id')
            if not client_id == client_id_claim:
                msg = f"client_id from header ({client_id}) does not match the client_id in the token claim " \
                      f"({client_id_claim})."
                logger.debug(msg)
                raise errors.ResourceError(msg)
            username = access_token_claims.get('tapis/username')
        else:
            logger.debug(f"Invalid grant_type: {grant_type}")
            raise errors.ResourceError("Invalid grant_type")

        # call /v3/tokens to generate access token for the user --------
        url = f'{g.request_tenant_base_url}/v3/tokens'
        #override this
        access_token_ttl = config.default_access_token_ttl

        if grant_type == 'device_code':
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
            "generate_refresh_token": False
        }
        if idp_id:
            content['claims']['tapis/idp_id'] = idp_id

        # only generate a refresh token when OAuth client is passed
        if client_id and client_key:
            content["generate_refresh_token"] = True
            refresh_token_ttl = config.default_refresh_token_ttl
            content["refresh_token_ttl"] = refresh_token_ttl

        # set the redirect_uri claim when using a web-based flow or when refreshing a token that was
        # generated using a web-based flow:
        if grant_type == 'authorization_code' or (grant_type == 'refresh_token'
                                                  and access_token_claims.get('tapis/redirect_uri')):
            content['claims']["tapis/redirect_uri"] = client.callback_url
        # if generating a refresh token, add a claim to count the total refreshes:
        if content["generate_refresh_token"]:
            # if the grant_type is refresh_token, there should already be a claim:
            if grant_type == 'refresh_token':
                refresh_count = access_token_claims.get('tapis/refresh_count') + 1
            else:
                refresh_count = 0
            content['claims']['tapis/refresh_count'] = refresh_count
        try:
            logger.debug(f"calling tokens API to create a token; content: {content}")
            tokens = t.tokens.create_token(**content, use_basic_auth=False)
            logger.debug(f"got tokens response: {tokens}")
        except Exception as e:
            logger.error(f"Got exception trying to POST to /v3/tokens endpoint. Exception: {e};"
                         f"content: {content}")
            try:
                logger.error(f"Headers from the request: {e.request.headers}")
            except Exception as e:
                logger.error(f"Couldn't get the headers from the request; exception: {e}")
            raise errors.ResourceError("Failure to generate an access token; please try again later.")
        try:
            result = {'access_token': {'access_token': tokens.access_token.access_token,
                                       'expires_at': tokens.access_token.expires_at,
                                       'expires_in': tokens.access_token.expires_in,
                                       'jti': tokens.access_token.jti
                                       },
                      }
            if content.get('generate_refresh_token'):
                result['refresh_token'] = {'refresh_token': tokens.refresh_token.refresh_token,
                                           'expires_at': tokens.refresh_token.expires_at,
                                           'expires_in': tokens.refresh_token.expires_in,
                                           'jti': tokens.refresh_token.jti,
                                           }
        except AttributeError as e:
            logger.error(f"Got an unexpected AttributeError trying to parse tokens response; e: {e}")
            raise errors.ResourceError("Failure to parse access token response; please try again later.")
        
        # get the claims associated with the token we just generated; we don't want to bother checking the 
        # signature, etc., here because we know the token was just generated by Tokens API and we just want
        # to record the claims in our db.
        new_access_token_claims = insecure_decode_jwt_to_claims(tokens.access_token.access_token)

        # add the tokens to the AccessTokens and RefreshTokens tables -------
        access_token = AccessTokens(
            jti=tokens.access_token.jti,
            subject=new_access_token_claims['sub'],
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
                subject=new_access_token_claims['sub'],
                tenant_id=tenant_id,
                username=username,
                grant_type=grant_type,
                token_ttl=refresh_token_ttl,
                # token_create_time has the correct default of now.
                token_expiry_time=datetime.fromisoformat(tokens.access_token.expires_at),
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
            logger.debug(f"got exception trying to commit access_token object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        except Exception as e:
            msg = f"Got unexpected exception trying to add access_token to database. " \
                  f"Contact system administrator. (Debug data: {e})"
            logger.error(msg)
            raise errors.ResourceError(f"{msg}")
        
        return utils.ok(result=result, msg="Token created successfully.")


class V2TokenResource(Resource):
    def post(self):
        logger.debug("Top of v2 Token Resource")

        token = request.headers['X-Tapis-Token']

        claims = validate_token(token)
        username = claims.get('tapis/username')

        tenant_id=g.request_tenant_id
        config = tenant_configs_cache.get_config(tenant_id)

        logger.debug(config.serialize)

        #set url and oauth client/password in tenant config
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
            "jupyter-tacc-dev": "TACC"
        }
        wso2_user_store_id = WSO2_USER_STORE_ID.get(tenant_id)
        data =  {
            "grant_type": "admin_password",
            "username": impersadmin_uesrname,
            "password": impersadmin_password,
            "token_username": f"{wso2_user_store_id}/{username}",
            "scope": "PRODUCTION"
        }

        try:
            logger.debug(f"Sending post request to v2 token endpoint for user: {username}")
            response = requests.post(token_url, data=data, auth=HTTPBasicAuth(impers_oauth_client_id, impers_oauth_client_secret))
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Error getting v2 token; error: {e}")
            raise errors.ResourceError("Failure calling v2 token endpoint; please try again later.")
        return response.json()


class RevokeTokensResource(Resource):
    """
    Revoke a Tapis JWT.
    """
    def post(self):
        logger.debug("top of POST /v3/oauth2/tokens/revoke")
        # TODO: tapipy-1.4.0
        # validator = RequestValidator(utils.spec)
        # validated = validator.validate(FlaskOpenAPIRequest(request))
        validated = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if validated.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {validated.errors}.')
        validated_body = validated.body
        token_str = validated.body.token
        try:
            token_data = validate_token(token_str)
        except errors.AuthenticationError as e:
            raise errors.ResourceError(msg=f'Invalid POST data; could not validate the token: debug data: {e}.')
        # call the tokens api to actually revoke the token
        try:
            t.tokens.revoke_token(token=token_str, _tapis_set_x_headers_from_service=True)
        except Exception as e:
            logger.error(f"Got exception trying to call the tokens api to revoke a token; details: {e}")
            raise errors.ResourceError(msg=f"Unexpected error trying to revoke the token: debug data: {e}.")
        logger.info(f"Token has been revoked with the Tokens API, will now update our table.")
        # update the token to "revoked" on the correct table
        try:
            revoked_token_claims = insecure_decode_jwt_to_claims(token_str)
        except Exception as e:
            logger.error(f"could not get claims from revoked token and therefore could not update the " + 
                          "token table; details: {e}")
            # swallow the exception for now, nothing the user can do
            revoked_token_claims = None
        if revoked_token_claims:
            # get the token type and jti
            try:
                token_type = revoked_token_claims['tapis/token_type']
                jti = revoked_token_claims['jti']
            except Exception as e:
                logger.error(f"could not get token_typ and jti claims from revoked token and therefore " + 
                            " could not update the token table; details: {e}")
                token_type = None
                jti = None
            if token_type and jti:
                if token_type == 'access':
                    access_token = AccessTokens.query.filter_by(jti=jti).first()
                    if not access_token:
                        logger.error(f"revoked access token with jti {jti} not found on table.")
                    else:
                        access_token.token_revoked = True
                        access_token.token_revoked_time = datetime.now()
                        access_token.last_update_time = datetime.now()
                        try:
                            db.session.commit()
                            logger.info(f"access token with jit {jti} revoked, and revoked status added to table.")
                        except Exception as e:
                            logger.error(f"could not commit update to revoked access token; e: {e}")
                else:
                    refresh_token = RefreshTokens.query.filter_by(jti=jti).first()
                    if not refresh_token:
                        logger.error(f"revoked refresh token with jti {jti} not found on table.")
                    else:
                        refresh_token.token_revoked = True
                        refresh_token.token_revoked_time = datetime.now()
                        refresh_token.last_update_time = datetime.now()
                        try:
                            db.session.commit()
                            logger.info(f"refresh token with jit {jti} revoked, and revoked status added to table.")
                        except Exception as e:
                            logger.error(f"could not commit update to revoked refresh token; e: {e}")                
        else:
            logger.error(f"insecure_decode_jwt_to_claims did not return claims for the token: {token_str}")
        return utils.ok(result='', msg=f"Token {token_data['jti']} has been revoked.")



# ---------------------------------
# Example Token Webapp controllers
# ---------------------------------

def get_tokenapp_client(tenant_id=None):
    """
    Looks up the client information associated with the Token Webapp for a specific tenant. If no tenant is specified,
    this function will attempt to get the tenant from the request context and then the session.
    :param tenant_id: The tenant id for the client of interest.
    :return:
    """
    if not tenant_id:
        tenant_id = session.get('tenant_id')
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
        raise errors.ResourceError(msg=f'The tenant could not be established from the session.')
    # look up the client data by tenant id:
    client_data = token_webapp_clients[tenant_id]
    # if the authenticator is running locally, get the "local" client data:
    if 'localhost' in request.base_url:
        client_data = token_webapp_clients[f'local.{tenant_id}']
    return client_data


def logout():
    """
    Helper function to reset the session whenever a logout needs to occur.
    """
    session.pop('username', None)
    session.pop('tenant_id', None)
    session.pop('access_token', None)
    session.pop('device_login', None)
    session.pop('mfa_required', None)
    session.pop('mfa_validated', None)
    session.pop('state', None)
    session.pop('idp_id', None)
    session.pop('orig_client_id', None)
    session.pop('orig_client_redirect_uri', None)
    session.pop('orig_client_response_type', None)
    session.pop('orig_client_state', None)


class WebappTokenAndRedirect(Resource):
    """
    This resource implements the GET method for the primary /oauth2/webapp URL path of the Token Web app. This method
    does the following:
      1) If the user already has an active OAuth2 token in their session, it simply renders it in an HTML page.
      2) If not, start the OAuth2 flow by redirecting to the Authorization server's /oauth2/authorize URL.
    """

    def get(self):
        token = session.get('access_token')
        tenant_id = session.get('tenant_id')
        # if the authenticator is running locally, redirect to the local instance of the Authorization server:
        if 'localhost' in request.base_url:
            base_redirect_url = 'http://localhost:5000'
        else:
            # otherwise, redirect based on the tenant in the request
            base_redirect_url = g.request_tenant_base_url
        if token:
            # tracks whether the user actually has a valid session; even though they have a token, it could
            # be expired.
            has_valid_session = True
            context = {'error': None,
                       'token': token}
            headers = {'Content-Type': 'text/html'}
            # call the userinfo endpoint
            url = f'{base_redirect_url}/v3/oauth2/userinfo'
            headers = {'X-Tapis-Token': token}
            try:
                rsp = requests.get(url, headers=headers)
                rsp.raise_for_status()
            except Exception as e:
                # Note: it could be that the user is returning to the webpage after a previous login attempt
                # many hours later. In this case, the token will exist in the session but be expired.
                # Therefore, if we cannot call the userinfo endpoint, we log the error, log the user out
                # and start the OAuth flow over again.
                msg = f'Got exception trying to call userinfo endpoint. Will log out user. Details: {e}'
                has_valid_session = False
                logout()
                logger.error(msg)
            if has_valid_session:
                try:
                    user_info = rsp.json().get('result')
                except Exception as e:
                    msg = f'Could not get JSON result from userinfo endpoint. Will log out user. Details: rsp: {rsp}'
                    logger.error(msg)
                    has_valid_session = False
                    logout()
            if has_valid_session:
                try:
                    username = user_info['username']
                except Exception as e:
                    logger.error(f"Got exception trying to get username out of userinfo endpoint response object. This should never happen. Setting username to 'Not available'. Details: {e}; user_info: {user_info}")
                    username = 'Not available'
                context['username'] = username
                context['tenant_id'] = tenant_id
                config = tenant_configs_cache.get_config(tenant_id)
                mfa_config = json.loads(config.mfa_config)
                logger.info(f"MFA CONFIG: {mfa_config}")
                if check_mfa_expired(mfa_config, session.get('mfa_timestamp', None)):
                    session["mfa_validated"] = False
                    tokenapp_client = get_tokenapp_client()
                    client_id = tokenapp_client['client_id']
                    client_redirect_uri = tokenapp_client['callback_url']
                    state = secrets.token_hex(24)
                    session['state'] = state
                    return redirect(url_for('mfaresource',
                                        client_id=client_id,
                                        redirect_uri=client_redirect_uri,
                                        state=state,
                                        response_type='code'))
                return make_response(render_template('token-display.html', **context), 200, headers)
        # otherwise, if there is no token in the session, check the type of OAuth configured for this tenant;
        if not tenant_id:
            tenant_id = g.request_tenant_id
            session['tenant_id'] = tenant_id
        # start the standard Tapis OAuth2 flow with a redirect ---
        # redirect to login (oauth2/authorize)
        # maybe pass csrf token as well (state var)
        # get tenant_id based on url
        # http://localhost:5000/v3/oauth2/authorize?client_id=test_client&redirect_uri=http://localhost:5000/oauth2/webapp/callback&response_type=code
        # todo - in general, do not want to hard-code "dev.develop..."
        tokenapp_client = get_tokenapp_client()
        client_id = tokenapp_client['client_id']
        client_redirect_uri = tokenapp_client['callback_url']
        state = secrets.token_hex(24)
        session['state'] = state
        url = f'{base_redirect_url}/v3/oauth2/authorize?client_id={client_id}&redirect_uri={client_redirect_uri}&response_type=code&state={state}'
        return redirect(url)


class WebappTokenGen(Resource):
    """
    Implements the OAuth2 callback URL for the Token Webapp for the authorization_code grant type. This resource only
    implements the GET method, as per the OAUth2 spec, to receive the callback from the Authorization server and then
    exchange the authorization code for a token.
    """

    def get(self):
        logger.debug("top of GET /v3/oauth2/webapp/callback")
        client_data = get_tokenapp_client()
        client_id = client_data['client_id']
        client_key = client_data['client_key']
        client_redirect_uri = client_data['callback_url']
        # the user should already be authenticated and in the session --
        username = session.get('username')
        if not username:
            logger.error("GET request to /v3/oauth2/webapp/callback made but WebappTokenGen could not "
                         "find username in the session! ")
            raise errors.ResourceError(msg=f'The username could not be established from the session.')
        tenant_id = g.request_tenant_id
        logger.debug(f"client_id: {client_id}; tenant_id: {tenant_id}")
        # get additional query parameters from request ---
        state = request.args.get('state')
        session_state = session.get('state')
        if not state == session_state:
            logger.error(f"state received ({state}) did not match session state ({session_state})")
            raise errors.ResourceError(msg=f'Unauthorized access attempt: state mismatch.')
        code = request.args.get('code')

        #  POST to oauth2/tokens (passing code, client id, client secret, and redirect uri)
        logger.debug(f"request.base_url: {request.base_url}")
        base_url = g.request_tenant_base_url
        # the common flaskbase code will compute request_tenant_base_url based on the tenant of the request.
        # we will need to modify this for local development since the computed base url will for example be the
        # dev.tenants.develop.tapis.io for the dev tenant in the develop instance.
        # if Token Webapp listening on localhost, base_url should be localhost

        # if the authenticator is running locally, use "localhost" for baseurl to interact with OAuth server
        # and we pass the tenant-id in as a special header:
        headers = {}
        if 'localhost' in request.base_url:
            logger.debug("using localhost for base_url.")
            base_url = 'http://localhost:5000'
            headers['X-Tapis-Local-Tenant'] = tenant_id
            logger.debug(f"setting X-Tapis-Local-Tenant header to: {tenant_id}")
        logger.debug(f"Final base_url: {base_url}")

        url = f'{base_url}/v3/oauth2/tokens'
        content = {
            "grant_type": "authorization_code",
            "redirect_uri": client_redirect_uri,
            "code": code
        }
        try:
            logger.debug(f"making request to {url}")
            r = requests.post(url, json=content, auth=(client_id, client_key), headers=headers)
        except Exception as e:
            logger.error(f"Got exception trying to POST to /v3/oauth2/tokens endpoint. Exception: {e}")
            raise errors.ResourceError("Failure to generate an access token; please try again later.")
        logger.debug(f"made request; got response: {r}")
        try:
            json_resp = json.loads(r.text)
        except Exception as e:
            logger.error(f"Got exception trying to parse JSON from POST to /v3/tokens endpoint. Exception: {e}")
            raise errors.ResourceError("Failure to generate an access token; please try again later.")

        logger.debug(f"Made request successfully and got JSON. Now parsing JSON data: {json_resp}")
        # Get token from POST response
        try:
            token = json_resp['result']['access_token']['access_token']
        except TypeError as e:
            logger.error(f"Got TypeError trying to retrieve access_token from JSON response: {e}")
            raise errors.ResourceError("Failure to generate an access token; please try again later.")
        except Exception as e:
            logger.error(f"Got Exception trying to retrieve access token from JSON response: {e}")
            raise errors.ResourceError("Failure to generate an access token; please try again later.")
        session['access_token'] = token
        #  Redirect to oauth2/webapp/token-display
        return redirect(url_for('webapptokenandredirect'))


class LogoutResource(Resource):

    def get(self):
        # selecting a tenant id is required before logging in -
        headers = {'Content-Type': 'text/html'}
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            logger.debug(
                f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            # reset the session in case there is some weird cruft
            session.pop('username', None)
            session.pop('tenant_id', None)
            make_response(render_template('logout.html', logout_message='You have been logged out.'), 200, headers)
        return make_response(render_template('logout.html'), 200, headers)

    def post(self):
        headers = {'Content-Type': 'text/html'}
        # process the logout form -
        if request.form.get("logout"):
            logout()
            make_response(render_template('logout.html', logout_message='You have been logged out.'), 200, headers)
        # if they submitted the logout form but did not check the box then just return them to the logout form -
        return redirect(url_for('webapptokenandredirect'))


class StaticFilesResource(Resource):
    def get(self, path):
        return send_from_directory('templates', path)
