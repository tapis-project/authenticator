from flask_migrate import Migrate

from common.utils import TapisApi, handle_error, flask_errors_dict

from service.auth import authn_and_authz
from service.controllers import ClientsResource, ClientResource, TokensResource
from service.models import db, app

# authentication and authorization ---
@app.before_request
def authnz_for_authenticator():
    authn_and_authz()


# db and migrations ----
db.init_app(app)
migrate = Migrate(app, db)


# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Add resources
api.add_resource(ClientsResource, '/v3/clients')
api.add_resource(ClientResource, '/v3/clients/<client_id>')
api.add_resource(TokensResource, '/v3/oauth2/tokens')
