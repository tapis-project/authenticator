from flask_migrate import Migrate
from common.config import conf
from common.utils import TapisApi, handle_error, flask_errors_dict
import datetime

from service.auth import authn_and_authz
from service.controllers import AuthorizeResource, ClientsResource, ClientResource, TokensResource, \
    ProfilesResource, ProfileResource, StaticFilesResource, LoginResource, SetTenantResource, LogoutResource, \
    WebappTokenGen, WebappTokenAndRedirect
from service.ldap import populate_test_ldap
from service.models import db, app, Client

from common.logs import get_logger
logger = get_logger(__name__)

# authentication and authorization ---
@app.before_request
def authnz_for_authenticator():
    authn_and_authz()


# db and migrations ----
db.init_app(app)
migrate = Migrate(app, db)


def create_clients_for_tenant(tenant_id):
    """
    Create the OAuth clients for the Token Webapp for a specific tenant_id. There are two clients that get created in
    each tenant: one with a registered callback using the tenant's base_url and another with a "localhost" callback
    for running locally.

    :param tenant_id: The tenant_id to register the client in.
    :return:
    """
    logger.debug(f"top of create_client for tenant_id: {tenant_id}")
    # first register the localhost client:
    client_id = f'local.{tenant_id}.{conf.client_id}'
    data = {
        "client_id": client_id,
        "client_key": conf.client_key,
        "callback_url": f'http://localhost:5000{conf.client_callback}',
        "display_name": conf.client_display_name,
        "tenant_id": tenant_id,
        "username": "tapis",
        'create_time':  datetime.datetime.utcnow(),
        'last_update_time': datetime.datetime.utcnow()
    }
    add_client_to_db(data)
    # now register the client with the tenant's base url:
    client_id = f'{tenant_id}.{conf.client_id}'
    callback_url = f'{conf.service_tenant_base_url}{conf.client_callback}'
    data['client_id'] = client_id
    data['callback_url'] = callback_url
    add_client_to_db(data)


def add_client_to_db(data):
    """
    Add a client directly to the clients db.
    :param data: A Python dictionary containing a complete description of the client to add.
    :return:
    """
    try:
        client = Client.query.filter_by(
                    tenant_id=data['tenant_id'],
                    client_id=data['client_id'],
                    client_key=data['client_key']
                ).first()
        if not client:
            logger.debug(f"registering localhost {data['tenant_id']} client.")
            client = Client(**data)
            db.session.add(client)
            db.session.commit()
        else:
            logger.debug(f"client with id {data['client_id']} for tenant {data['tenant_id']} already existed.")
    except Exception as e:
        logger.info(f"Got exception trying to create the token web app client; this better be migrations; e: {e}")
        db.session.rollback()



# initialize the test LDAP ---
# TODO - this code is run by every thread but is not thread safe!
if conf.populate_dev_ldap:
    populate_test_ldap()

if conf.populate_all_clients:
    # generate a client for every tenant assigned to this instance -
    for tenant_id in conf.tenants:
        create_clients_for_tenant(tenant_id)


# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# API resources
api.add_resource(ClientsResource, '/v3/oauth2/clients')
api.add_resource(ClientResource, '/v3/oauth2/clients/<client_id>')
api.add_resource(TokensResource, '/v3/oauth2/tokens')
api.add_resource(ProfilesResource, '/v3/oauth2/profiles')
api.add_resource(ProfileResource, '/v3/oauth2/profiles/<username>')
api.add_resource(AuthorizeResource, '/v3/oauth2/authorize')
api.add_resource(LoginResource, '/v3/oauth2/login')
api.add_resource(SetTenantResource, '/v3/oauth2/tenant')
api.add_resource(LogoutResource, '/v3/oauth2/logout')

# Portal resources
api.add_resource(WebappTokenGen, '/v3/oauth2/webapp/callback')
api.add_resource(WebappTokenAndRedirect, '/v3/oauth2/webapp')

# Staticfiles
api.add_resource(StaticFilesResource, '/v3/oauth2/authorize/<path>')