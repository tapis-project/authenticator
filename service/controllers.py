import requests
import json
from flask import g, request, Response, render_template, redirect, make_response, send_from_directory, session, url_for
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest

from common import utils, errors
from common.config import conf

from service.errors import InvalidPasswordError
from service.models import db, Client, Token, AuthorizationCode
from service.ldap import list_tenant_users, get_tenant_user, check_username_password

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


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


class ProfileResource(Resource):
    def get(self, username):
        logger.debug(f'top of GET /profiles/{username}')
        tenant_id = g.request_tenant_id
        user = get_tenant_user(tenant_id=tenant_id, username=username)
        return utils.ok(result=user.serialize, msg="User profile retrieved successfully.")


def check_client():
    """
    Checks the request for associated client query parameters, validates them against the client registered in the DB
    and returns the associated objects.
    """
    # tenant_id should be determined by the request URL -
    tenant_id = session.get('tenant_id')
    if not tenant_id:
        tenant_id = g.request_tenant_id
    if not tenant_id:
        raise errors.ResourceError("tenant_id missing.")
    if not tenant_id in conf.tenants:
        raise errors.ResourceError(f"This application is not configured to serve the requested tenant {tenant_id}.")
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


# --------------------------
# Authorization Server Views
# --------------------------

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
        return redirect(url_for('loginresource',
                                client_id=tokenapp_client['client_id'],
                                redirect_uri=tokenapp_client['redirect_uri'],
                                state=client_state,
                                client_display_name=tokenapp_client['display_name'],
                                response_type='code'))


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
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
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
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            raise errors.ResourceError("Invalid session; please return to the original application or logout of this session.")
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
        client_id, client_redirect_uri, client_state, client = check_client()
        if not 'username' in session:
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

        return make_response(render_template('authorize.html',  **context), 200, headers)

    def post(self):
        # selecting a tenant id is required before logging in -
        tenant_id = g.request_tenant_id
        if not tenant_id:
            tenant_id = session.get('tenant_id')
        if not tenant_id:
            raise errors.ResourceError('Tenant ID missing from session. Please logout and select a tenant.')
        client_display_name = request.form.get('client_display_name')
        approve = request.form.get("approve")
        if not approve:
            headers = {'Content-Type': 'text/html'}
            context = {'error': f'To proceed with authorization application {client_display_name}, you '
                                f'must approve the request.'}
            return make_response(render_template('authorize.html', **context), 200, headers)

        state = request.form.get("state")
        # retrieve client data from form and db -
        client_id = request.form.get('client_id')
        if not client_id:
            raise errors.ResourceError("client_id missing.")
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            raise errors.ResourceError('Invalid client.')
        # create the authorization code for the client -
        authz_code = AuthorizationCode(tenant_id=tenant_id,
                                       client_id=client_id,
                                       client_key=client.client_key,
                                       redirect_url=client.callback_url,
                                       code=AuthorizationCode.generate_code(),
                                       expiry_time=AuthorizationCode.compute_expiry())
        # issue redirect to client callback_url with authorization code:
        url = f'{client.callback_url}?code={authz_code}&state={state}'

        return redirect(url)


class TokensResource(Resource):
    """
    Implements the oauth2/tokens endpoint for generating tokens for the following grant types:
      * password
      * authorization_code
    """

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        logger.debug(f"BODY: {validated_body}")
        data = Token.get_derived_values(validated_body)

        grant_type = data['grant_type']
        if not grant_type:
            raise errors.ResourceError(msg=f'Missing the required grant_type parameter.')

        tenant_id = g.request_tenant_id
        # get headers
        try:
            auth = request.authorization
            client_id = auth.username
            client_key = auth.password
        except Exception as e:
            raise errors.ResourceError(msg=f'Invalid headers. Basic authentication with client id and k'
                                           f'ey required but missing.')
        # check that client is in db
        logger.debug("Checking that client exists.")
        client = Client.query.filter_by(tenant_id=tenant_id, client_id=client_id, client_key=client_key).first()
        if not client:
            raise errors.ResourceError(msg=f'Invalid client credentials: {client_id}, {client_key}.')
        # check grant type:
        if grant_type == 'password':
            # validate user/pass against ldap
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                raise errors.ResourceError("Missing requried payload data; username and password are required for "
                                           "the password grant type.")
            check_ldap = check_username_password(tenant_id, username, password)
            logger.debug(f"returned: {check_ldap}")
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
            AuthorizationCode.validate_code(tenant_id=tenant_id,
                                            code=code,
                                            client_id=client_id,
                                            client_key=client_key)
        else:
            raise errors.ResourceError("Invalid grant_type")

        # call /v3/tokens to generate access token for the user
        url = f'{g.request_tenant_base_url}/v3/tokens'
        content = {
            "token_tenant_id": f"{tenant_id}",
            "account_type": "service",
            "token_username": f"{data['username']}",
        }
        r = requests.post(url, json=content)
        json_resp = json.loads(r.text)

        return utils.ok(result=json_resp, msg="Token created successfully.")



# ------------------
# Token Webapp Views
# ------------------

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
    #
    client_id = f'{tenant_id}.{conf.client_id}'
    client_key = conf.client_key
    redirect_uri_path = f'{conf.service_tenant_base_url}{conf.client_callback}'
    # if the authenticator is running locally, override with the local client data:
    if 'localhost' in request.base_url:
        redirect_uri_path = f'http://localhost:5000{conf.client_callback}'
        client_id = f'local.{tenant_id}.{conf.client_id}'
    return {
        'client_id': client_id,
        'client_key': client_key,
        'redirect_uri': redirect_uri_path,
        'display_name': conf.client_display_name
    }


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
        # otherwise, if there is no token in the session, start the OAuth2 flow with a redirect ---
        # redirect to login (oauth2/authorize)
            # maybe pass csrf token as well (state var)
            # get tenant_id based on url
        # http://localhost:5000/v3/oauth2/authorize?client_id=test_client&redirect_uri=http://localhost:5000/oauth2/webapp/callback&response_type=code
        # todo - in general, do not want to hard-code "dev.develop..."
        tokenapp_client = get_tokenapp_client()
        client_id = tokenapp_client['client_id']
        client_redirect_uri = tokenapp_client['redirect_uri']
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
        # Get query parameters from request
        # client_id, client_redirect_uri, client_state, client = check_client()
        client_redirect_uri = request.args.get('client_redirect_uri')
        client_state = request.args.get('client_state')
        client_secret = conf.client_key
        client_id = f'dev.develop.{conf.client_id}'
        if 'localhost' in request.base_url:
            client_id = conf.client_id
        # Receive the code (and state if passed)
        username = session.get('username')
        if not username:
            logger.error("GET request to /v3/oauth2/webapp/callback made but WebappTokenGen could not "
                         "find username in the session! ")
            raise errors.ResourceError(msg=f'The username could not be established from the session.')
        code = request.args.get('redirect_uri')
        tenant_id = g.request_tenant_id
        logger.debug(f"Client ID: {client_id} - tenant_id: {tenant_id}")

        #  POST to oauth2/tokens (passing code, client id, client secret, and redirect uri)
            # redirect uri is just callback url
        base_url = g.request_tenant_base_url
        logger.debug(f"HERE IS THE BASE URL: {base_url}")
        url = f'{base_url}/v3/tokens'
        content = {
            "token_tenant_id": tenant_id,
            "account_type": "user",
            "token_username": username,
            "claims": {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": client_redirect_uri,
                "code": code
            }
        }
        r = requests.post(url, json=content)
        json_resp = json.loads(r.text)

        # Get token from POST response
        token = json_resp['result']['access_token']['access_token']
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
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
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


