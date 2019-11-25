from flask import g, request, Response, render_template, redirect, make_response, send_from_directory, session, url_for
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest

from common import utils, errors

from service.errors import InvalidPasswordError
from service.models import db, Client
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


class TokensResource(Resource):
    """
    Work with OAuth client objects
    """

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body

        return validated_body
        # return utils.ok(result=client.serialize, msg="Client created successfully.")


class ProfilesResource(Resource):
    """
    Work with profiles.
    """

    def get(self):
        logger.debug('top of GET /profiles')
        # get the tenant id - we use the x_tapis_tenant if that is set (from some service account); otherwise, we use
        # the tenant_id assoicated with the JWT.
        tenant_id = getattr(g, 'x_tapis_tenant', None)
        if not tenant_id:
            logger.debug("didn't find x_tapis_tenant; using tenant id in token.")
            tenant_id = g.tenant_id
        logger.debug(f"using tenant_id {tenant_id}")
        try:
            limit = int(request.args.get('limit'))
        except:
            limit = None
        offset = None
        try:
            offset = int(request.args.get('offset'))
            # b64_offset = request.args.get('offset')
            # logger.debug(f'b64_offset: {b64_offset}')
            # if b64_offset:
            #     offset = base64.b64decode(b64_offset)
            #     logger.debug(f'offset: {offset}')
        except Exception as e:
            logger.debug(f'get exception parsing offset; exception: {e}; setting offset to none.')
            offset = 0
        users, offset = list_tenant_users(tenant_id=tenant_id, limit=limit, offset=offset)
        resp = utils.ok(result=[u.serialize for u in users], msg="Profiles retrieved successfully.")
        resp.headers['X-Tapis-Offset'] = offset
        return resp


class ProfileResource(Resource):
    def get(self, username):
        logger.debug(f'top of GET /profiles/{username}')
        tenant_id = getattr(g, 'x_tapis_tenant', None)
        if not tenant_id:
            logger.debug("didn't find x_tapis_tenant; using tenant id in token.")
            tenant_id = g.tenant_id
        user = get_tenant_user(tenant_id=tenant_id, username=username)
        return utils.ok(result=user.serialize, msg="User profile retrieved successfully.")


class AuthorizeResource(Resource):
    def get(self):
        if not 'username' in session:
            return redirect(url_for('loginresource'))
        headers = {'Content-Type': 'text/html'}
        context = {'error': '',
                   'username': session['username']}
        return make_response(render_template('authorize.html',  **context), 200, headers)


class SetTenantResource(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        error = ''
        return make_response(render_template('tenant.html', **{'error': error}), 200, headers)

    def post(self):
        tenant_id = request.form.get("tenant")
        logger.debug(f"setting session tenant_id to: {tenant_id}")
        session['tenant_id'] = tenant_id
        return redirect(url_for('loginresource'))


class LoginResource(Resource):
    def get(self):
        # selecting a tenant id is required before logging in -
        if not 'tenant_id' in session:
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            return redirect(url_for('settenantresource'))
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html', **{'error': '', 'tenant_id': session['tenant_id']}), 200, headers)

    def post(self):
        # process the login form -
        if not 'tenant_id' in session:
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            return redirect(url_for('settenantresource'))
        tenant_id = session['tenant_id']
        headers = {'Content-Type': 'text/html'}
        username = request.form.get("username")
        if not username:
            error = 'Username is required.'
            return make_response(render_template('login.html', **{'error': error}), 200, headers)
        password = request.form.get("password")
        if not password:
            error = 'Password is required.'
        try:
            check_username_password(tenant_id=tenant_id, username=username, password=password)
        except InvalidPasswordError:
            error = 'Invalid username/password combination.'
            return make_response(render_template('login.html', **{'error': error}), 200, headers)
        # the username and password were accepted; set the session and redirect to the authorization page.
        session['username'] = username
        return redirect(url_for('authorizeresource'))


class LogoutResource(Resource):

    def get(self):
        # selecting a tenant id is required before logging in -
        if not 'tenant_id' in session:
            logger.debug(f"did not find tenant_id in session; issuing redirect to SetTenantResource. session: {session}")
            # reset the session in case there is some weird cruft
            session.pop('username', None)
            session.pop('tenant_id', None)
            return redirect(url_for('settenantresource'))
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('logout.html'), 200, headers)

    def post(self):
        # process the logout form -
        if request.form.get("logout"):
            session.pop('username', None)
            session.pop('tenant_id', None)
            return redirect(url_for('settenantresource'))
        # if they submitted the logout form but did not check the box then just return them to the logout form -
        return redirect(url_for('logoutresource'))


class StaticFilesResource(Resource):
    def get(self, path):
        return send_from_directory('templates', path)