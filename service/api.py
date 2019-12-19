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
import threading

from common.logs import get_logger
logger = get_logger(__name__)

# authentication and authorization ---
@app.before_request
def authnz_for_authenticator():
    authn_and_authz()


# db and migrations ----
db.init_app(app)
migrate = Migrate(app, db)

# initialize the test LDAP ---
# TODO - this code is run by every thread but is not thread safe!
if conf.populate_dev_ldap:
    logger.info(f'Starting thread {threading.currentThread().ident}')
    populate_test_ldap()
if conf.dev_client_key:
    logger.debug("dev client existed in config.")
    data = {
        "client_id": conf.dev_client_id,
        "client_key": conf.dev_client_key,
        "callback_url": f'http://localhost:5000{conf.client_callback}',
        "display_name": conf.client_display_name,
        "tenant_id": "dev",
        "username": "tapis",
        'create_time':  datetime.datetime.utcnow(),
        'last_update_time': datetime.datetime.utcnow()
    }
    try:
        client = Client.query.filter_by(
                    tenant_id='dev',
                    client_id=data['client_id'],
                    client_key=data['client_key']
                ).first()
        if not client:
            logger.debug("registering localhost dev client.")
            client = Client(**data)
            db.session.add(client)
            db.session.commit()
        else:
            logger.debug("localhost dev client already exists.")
        data['callback_url'] = f'https://dev.develop.tapis.io{conf.client_callback}'
        data['client_id'] = f'dev.develop.{conf.client_id}'
        data['client_key'] = f'dev.develop.{conf.client_key}'
        client = Client.query.filter_by(
                    tenant_id='dev',
                    client_id=data['client_id'],
                    client_key=data['client_key']
                ).first()
        if not client:
            logger.debug("registering dev.develop client.")
            client = Client(**data)
            db.session.add(client)
            db.session.commit()
        else:
            logger.debug("dev.develop client already exists.")
    except Exception as e:
        logger.info(f"Got exception trying to create the token web app client; this better be migrations; e: {e}")

# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Add resources
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