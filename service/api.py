from flask_migrate import Migrate
from tapisservice.config import conf
from tapisservice.tapisflask.utils import TapisApi, handle_error, flask_errors_dict
from tapisservice.tapisflask.resources import HelloResource, ReadyResource

from service import MIGRATIONS_RUNNING
from service.auth import authn_and_authz
from service.controllers import AuthorizeResource, ClientsResource, ClientResource, TokensResource, \
    ProfilesResource, ProfileResource, StaticFilesResource, LoginResource, SetTenantResource, LogoutResource, \
    WebappTokenGen, WebappTokenAndRedirect, TenantConfigResource, UserInfoResource, OAuth2ProviderExtCallback, \
    OAuthMetadataResource, MFAResource, DeviceFlowResource, DeviceCodeResource, V2TokenResource, \
    RevokeTokensResource, SetIdentityProvider, WebappLogout
from service.ldap import populate_test_ldap
from service.models import db, app, initialize_tenant_configs

from tapisservice.logs import get_logger
from tapisservice.errors import BaseTapisError


logger = get_logger(__name__)

# authentication and authorization ---
@app.before_request
def authnz_for_authenticator():
    authn_and_authz()


# db and migrations ----
db.init_app(app)
migrate = Migrate(app, db)


# create the initial tenantconfig objects for all tenants assigned to this authenticator if they do not exist
# don't run this during migrations
if not MIGRATIONS_RUNNING:
    logger.info("running initialization code.")
    initialize_code_has_run = True
    run_initialize_code = True
    # initialize the tenant configs
    for tenant_id in conf.tenants:
        result = initialize_tenant_configs(tenant_id)
        if not result:
            break

    # initialize the test LDAP ---
    if result and conf.populate_dev_ldap:
        # check that a tenant id was configure:
        if not conf.dev_ldap_tenant_id:
            msg = "Set populate_dev_ldap but did not set the dev_ldap_tenant_id. Quitting now..."
            logger.error(msg)
            BaseTapisError(msg)
        populate_test_ldap(tenant_id=conf.dev_ldap_tenant_id)

# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Health-checks
api.add_resource(ReadyResource, '/v3/oauth2/ready')
api.add_resource(HelloResource, '/v3/oauth2/hello')

# API resources
api.add_resource(OAuthMetadataResource, '/v3/oauth2/.well-known/oauth-authorization-server')
api.add_resource(TenantConfigResource, '/v3/oauth2/admin/config')
api.add_resource(ClientsResource, '/v3/oauth2/clients')
api.add_resource(ClientResource, '/v3/oauth2/clients/<client_id>')
api.add_resource(RevokeTokensResource, '/v3/oauth2/tokens/revoke')
api.add_resource(TokensResource, '/v3/oauth2/tokens')

api.add_resource(UserInfoResource, '/v3/oauth2/userinfo')
api.add_resource(ProfilesResource, '/v3/oauth2/profiles')
api.add_resource(ProfileResource, '/v3/oauth2/profiles/<username>')

# Auth server resources
api.add_resource(AuthorizeResource, '/v3/oauth2/authorize')
api.add_resource(LoginResource, '/v3/oauth2/login')
api.add_resource(MFAResource, '/v3/oauth2/mfa')
api.add_resource(DeviceFlowResource, '/v3/oauth2/device')
api.add_resource(DeviceCodeResource, '/v3/oauth2/device/code')
api.add_resource(SetTenantResource, '/v3/oauth2/tenant')
api.add_resource(SetIdentityProvider, '/v3/oauth2/idp')
api.add_resource(LogoutResource, '/v3/oauth2/logout')
api.add_resource(OAuth2ProviderExtCallback, '/v3/oauth2/extensions/oa2/callback')

# Portal resources
api.add_resource(WebappTokenGen, '/v3/oauth2/webapp/callback')
api.add_resource(WebappTokenAndRedirect, '/v3/oauth2/webapp')
api.add_resource(WebappLogout, '/v3/oauth2/webapp/logout')

# Staticfiles
api.add_resource(StaticFilesResource, '/v3/oauth2/authorize/<path>')

# v2 resources
api.add_resource(V2TokenResource, '/v3/oauth2/v2/token')

logger.info("Authenticator ready")