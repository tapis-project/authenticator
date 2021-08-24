import requests
import json
from flask import g, request, Response, render_template, redirect, make_response, send_from_directory, session, url_for
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest
import sqlalchemy

from common import utils, errors
from common.config import conf
from common.auth import validate_token

from service import t
from service.errors import InvalidPasswordError
from service.models import db, TenantConfig, Client, Token, AuthorizationCode, token_webapp_clients, tenant_configs_cache
from service.ldap import list_tenant_users, get_tenant_user, check_username_password
from service.oauth2ext import OAuth2ProviderExtension


# get the logger instance -
from common.logs import get_logger

logger = get_logger(__name__)


# ------------------------------
# REST API Endpoint controllers
# ------------------------------

class ClientsResource(Resource):
    """
    Work with OAuth client objects
    """

    def get(self):
        clients = Client.query.filter_by(tenant_id=g.tenant_id, username=g.username)
        return utils.ok(result=[cl.serialize for cl in clients], msg="Clients retrieved successfully.")

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        data = Client.get_derived_values(validated_body)
        client = Client(**data)
        db.session.add(client)
        db.session.commit()
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

    def delete(self, client_id):
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        db.session.delete(client)
        db.session.commit()


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
        user = get_tenant_user(tenant_id=tenant_id, username=g.username)
        return utils.ok(result=user.serialize, msg="User profile retrieved successfully.")


class ProfileResource(Resource):
    def get(self, username):
        logger.debug(f'top of GET /profiles/{username}')
        tenant_id = g.request_tenant_id
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
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            logger.debug(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid PUT data: {result.errors}.')
        validated_body = result.body
        logger.debug("got past validator checks")
        # check for unsupported fields --
        if hasattr(validated_body, 'mfa_config'):
            raise errors.ResourceError("Setting mfa_config not currently supported.")
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
        # non-JSON columns ---
        new_use_ldap = getattr(validated_body, 'use_ldap', config.use_ldap)
        new_use_token_webapp = getattr(validated_body, 'use_token_webapp', config.use_token_webapp)
        new_default_access_token_ttl = getattr(validated_body, 'default_access_token_ttl',
                                               config.default_access_token_ttl)
        new_default_refresh_token_ttl = getattr(validated_body, 'default_refresh_token_ttl',
                                                config.default_refresh_token_ttl)
        new_max_access_token_ttl = getattr(validated_body, 'max_access_token_ttl', config.max_access_token_ttl)
        new_max_refresh_token_ttl = getattr(validated_body, 'max_refresh_token_ttl', config.max_refresh_token_ttl)

        logger.debug("updating config object with new attributes...")
        # update the model and commit --
        if new_allowable_grant_types:
            logger.debug(f"new_allowable_grant_types_str: {new_allowable_grant_types_str}")
            config.allowable_grant_types = new_allowable_grant_types_str
        if new_custom_idp_configuration:
            config.custom_idp_configuration = new_custom_idp_configuration_str
        config.use_ldap = new_use_ldap
        config.use_token_webapp = new_use_token_webapp
        config.default_access_token_ttl = new_default_access_token_ttl
        config.default_refresh_token_ttl = new_default_refresh_token_ttl
        config.max_access_token_ttl = new_max_access_token_ttl
        config.max_refresh_token_ttl = new_max_refresh_token_ttl
        try:
            db.session.commit()
            logger.info(f"update to tenant config committed to db. config object: {config}")
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit updated tenant config object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid PUT data; {msg}")
        logger.debug("returning serialized tenant object.")
        # reload the config cache updn update --
        tenant_configs_cache.load_tenant_config_cache()
        return utils.ok(result=config.serialize, msg="Tenant config object retrieved successfully.")


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
    if not client_redirect_uri:
        raise errors.ResourceError("Required query parameter redirect_uri missing.")
    if not response_type == 'code':
        raise errors.ResourceError("Required query parameter response_type missing or not supported.")
    # make sure the client exists and the redirect_uri matches
    logger.debug(f"checking for client with id: {client_id} in tenant {tenant_id}")
    client = Client.query.filter_by(tenant_id=tenant_id, client_id=client_id).first()
    if not client:
        raise errors.ResourceError("Invalid client.")
    if not client.callback_url == client_redirect_uri:
        raise errors.ResourceError(
            "redirect_uri query parameter does not match the registered callback_url for the client.")
    return client_id, client_redirect_uri, client_state, client


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


class LoginResource(Resource):
    """
    Implements the URLs used by the Authorization server for logging a user into a specific tenant.
    """

    def get(self):
        client_id, client_redirect_uri, client_state, client = check_client()
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
        context = {'error': '',
                   'client_display_name': client.display_name,
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
            client_id, client_redirect_uri, client_state, client = check_client()
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
        session['username'] = username
        return redirect(url_for('authorizeresource',
                                client_id=client_id,
                                redirect_uri=client_redirect_uri,
                                state=client_state,
                                client_display_name=client_display_name,
                                response_type='code'))


class AuthorizeResource(Resource):
    """
    This resource handles the activity of a user authorizing a client (web app) to get a token. It specifies the
    name of the client requesting authorization and asks the user to approve it. This resource is only called once
    the user has authenticated.
    """

    def get(self):
        logger.debug("top of GET /oauth2/authorize")
        client_id, client_redirect_uri, client_state, client = check_client()
        tenant_id = session.get('tenant_id')
        if not tenant_id:
            tenant_id = g.request_tenant_id
            session['tenant_id'] = tenant_id
        # if the user has not already authenticated, we need to issue a redirect to the login screen;
        # the login screen will depend on the tenant's IdP configuration
        if 'username' not in session:
            # if the tenant is configured with a custom oa2 extension, start the redirect for that --
            if tenant_configs_cache.get_custom_oa2_extension_type(tenant_id=tenant_id):
                logger.debug(f"username not in session; issuing redirect to 3rd party oauth URL.")
                is_local_development = 'localhost' in request.base_url
                oa2ext = OAuth2ProviderExtension(tenant_id, is_local_development=is_local_development)
                logger.debug(f"oa2ext.identity_redirect_url: {oa2ext.identity_redirect_url}")
                # we need to save the original client in the session in this case, because there is no
                # way to pass it through the third party OAuth server
                session['orig_client_id'] = client_id
                session['orig_client_redirect_uri'] = client_redirect_uri
                session['orig_client_response_type'] = 'code'
                session['orig_client_state'] = client_state
                # cii has its own format of callback url; there is no client id that is passed.
                if oa2ext.ext_type == 'cii':
                    url = f'{oa2ext.identity_redirect_url}?redirect={oa2ext.callback_url}'
                else:
                    url = f'{oa2ext.identity_redirect_url}?client_id={oa2ext.client_id}&redirect_uri={oa2ext.callback_url}'
                logger.debug(f"final redirect URL: {url}")
                return redirect(url)

            logger.debug("username not in session; issuing redirect to login.")
            return redirect(url_for('loginresource',
                                    client_id=client_id,
                                    redirect_uri=client_redirect_uri,
                                    state=client_state,
                                    response_type='code'))
        client_id, client_redirect_uri, client_state, client = check_client()
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        headers = {'Content-Type': 'text/html'}
        context = {'error': '',
                   'username': session['username'],
                   'tenant_id': tenant_id,
                   'client_display_name': client.display_name,
                   'client_id': client_id,
                   'client_redirect_uri': client_redirect_uri,
                   'client_state': client_state}

        return make_response(render_template('authorize.html', **context), 200, headers)

    def post(self):
        logger.debug("top of POST /oauth2/authorize")
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

        state = request.form.get("state")
        # retrieve client data from form and db -
        client_id = request.form.get('client_id')
        if not client_id:
            logger.debug("client_id missing from form.")
            raise errors.ResourceError("client_id missing.")
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            logger.debug(f"client not found in db. client_id: {client_id}")
            raise errors.ResourceError(f'Invalid client: {client_id}')
        # create the authorization code for the client -
        authz_code = AuthorizationCode(tenant_id=tenant_id,
                                       username=username,
                                       client_id=client_id,
                                       client_key=client.client_key,
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
        session['username'] = oa2ext.get_user_from_token()
        #  Get the origin client out of the session and then redirect to authorization page
        client_id, client_redirect_uri, client_state, client = check_client(use_session=True)
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
    """

    def post(self):
        logger.debug("top of POST /oauth2/tokens")
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        logger.debug(f"POST body validated; body: {validated_body}")
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
                logger.debug(f"ffound X-Tapis-Local-Tenant; override tenant to: {tenant_id}")
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
            username = AuthorizationCode.validate_and_consume_code(tenant_id=tenant_id,
                                                                   code=code,
                                                                   client_id=client_id,
                                                                   client_key=client_key)
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

        # call /v3/tokens to generate access token for the user
        url = f'{g.request_tenant_base_url}/v3/tokens'
        acces_token_ttl = config.default_access_token_ttl
        content = {
            "token_tenant_id": f"{tenant_id}",
            "account_type": "user",
            "token_username": f"{username}",
            "claims": {
                "tapis/client_id": client_id,
                "tapis/grant_type": grant_type,
            },
            "access_token_ttl": acces_token_ttl,
            "generate_refresh_token": False
        }
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
        return utils.ok(result=result, msg="Token created successfully.")


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


class WebappTokenAndRedirect(Resource):
    """
    This resource implements the GET method for the primary /oauth2/webapp URL path of the Token Web app. This method
    does the following:
      1) If the user already has an active OAuth2 token in their session, it simply renders it in an HTML page.
      2) If not, start the OAuth2 flow by redirecting to the Authorization server's /oauth2/authorize URL.
    """

    def get(self):
        token = session.get('access_token')
        if token:
            context = {'error': None,
                       'token': token}
            headers = {'Content-Type': 'text/html'}
            return make_response(render_template('token-display.html', **context), 200, headers)
        # otherwise, if there is no token in the session, check the type of OAuth configured for this tenant;
        tenant_id = session.get('tenant_id')
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
        # if the authenticator is running locally, redirect to the local instance of the Authorization server:
        if 'localhost' in request.base_url:
            base_redirect_url = 'http://localhost:5000'
        else:
            # otherwise, redirect based on the tenant in the request
            base_redirect_url = g.request_tenant_base_url
        response_type = 'code'
        url = f'{base_redirect_url}/v3/oauth2/authorize?client_id={client_id}&redirect_uri={client_redirect_uri}&response_type={response_type}'
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
            session.pop('username', None)
            session.pop('tenant_id', None)
            session.pop('access_token', None)
            make_response(render_template('logout.html', logout_message='You have been logged out.'), 200, headers)
        # if they submitted the logout form but did not check the box then just return them to the logout form -
        return redirect(url_for('webapptokenandredirect'))


class StaticFilesResource(Resource):
    def get(self, path):
        return send_from_directory('templates', path)
