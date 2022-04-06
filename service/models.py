from copy import deepcopy
import datetime
import json
from flask import Flask, g
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from hashids import Hashids
import string
import random
import uuid

from tapisservice.config import conf
from tapisservice.errors import DAOError
from tapisservice.logs import get_logger
from service import errors

from service import MIGRATIONS_RUNNING

logger = get_logger(__name__)

from service import tenants

app = Flask(__name__)
# app.secret_key = b"\x00" + secrets.token_bytes(12) + b"\x00"
app.secret_key = b"AGHsjfh!#%$SNFJqw"
try:
    full_db_url = f'postgresql://{conf.postgres_user}:{conf.postgres_password}@{conf.sql_db_url}'
except Exception as e:
    logger.error(f"Got exception trying to build full_db_ulr; e: {e}")
    raise e
app.config['SQLALCHEMY_DATABASE_URI'] = full_db_url
db = SQLAlchemy(app, session_options={"expire_on_commit": False})
migrate = Migrate(app, db)

# get the logger instance -
from tapisservice.logs import get_logger
logger = get_logger(__name__)


class TenantConfig(db.Model):
    """
    Tenant-specific configurations for the Authenticator.
    """
    __tablename__ = 'tenantconfig'

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(50), unique=False, nullable=False)

    # json serialized list of strings of allowable grant types, comma separated
    # ex:'["authorization_code", "password", "implicit", "device_code", "refresh_token", "impersonation", "delegation"]'
    allowable_grant_types = db.Column(db.String(500), unique=False, nullable=False)

    # whether to use the LDAP configured in the Tenants API
    use_ldap = db.Column(db.Boolean(), unique=False, nullable=False)

    # whether to make the Authenticator token web app available
    use_token_webapp = db.Column(db.Boolean(), unique=False, nullable=False)

    # MFA config is a json-serialized string which includes various details such as which MFA system to use (tacc or
    # some other one) and configurations for it.
    mfa_config = db.Column(db.String(2500), unique=False, nullable=False)

    # for the standard grant types, such as password and authorization_code --
    default_access_token_ttl = db.Column(db.Integer)
    default_refresh_token_ttl = db.Column(db.Integer)

    # for grant types that allow the caller to specify the ttl --
    max_access_token_ttl = db.Column(db.Integer)
    max_refresh_token_ttl = db.Column(db.Integer)

    # Configuration for customizing the IdP integration, including custom ldap search filters and alternative IdPs
    # like github OAuth of Custos; stored as a JSON-serialized string.
    custom_idp_configuration = db.Column(db.String(2500), unique=False, nullable=False)

    @property
    def serialize(self):
        return {
            "allowable_grant_types": json.loads(self.allowable_grant_types),
            "use_ldap": self.use_ldap,
            "mfa_config": json.loads(self.mfa_config),
            "use_token_webapp": self.use_token_webapp,
            "default_access_token_ttl": self.default_access_token_ttl,
            "default_refresh_token_ttl": self.default_refresh_token_ttl,
            "max_access_token_ttl": self.max_access_token_ttl,
            "max_refresh_token_ttl": self.max_refresh_token_ttl,
            "custom_idp_configuration": json.loads(self.custom_idp_configuration),
        }


def initialize_tenant_configs(tenant_id):
    """
    Checks to see if a TenantConfig record exists for the tenant_id passed, and if it does not, it creates one
    with the default configs. This function is called at authenticator start up (from api.py) with each tenant id
    in the authenticator's conf.tenants configuration.

    :param tenant_id: The tenant id to check.
    :return: config -- the config object assoicated with the tenant.
    """
    # first, check for the existence of a record
    try:
        config = TenantConfig.query.filter_by(tenant_id=tenant_id).first()
    except Exception as e:
        logger.error(f"got exception trying to check for the existence of a TenantConfig record for tenant: {tenant_id};"
                     f"exception: {e}. Giving up..")
        raise e
    # if the config doesn't already exist, create it:
    if config:
        logger.debug(f"Found config for tenant {tenant_id}; config: {config.serialize}")
        return config
    # create the config object because it doesn't exist yet:
    config = TenantConfig(
        tenant_id=tenant_id,
        allowable_grant_types=json.dumps(["password", "implicit", "authorization_code", "refresh_token"]),
        use_ldap=True,
        use_token_webapp=True,
        mfa_config=json.dumps({}),
        # 4 hours
        default_access_token_ttl=14400,
        # 1 year
        default_refresh_token_ttl=31536000,
        max_access_token_ttl=31536000,
        # 2 years
        max_refresh_token_ttl=63072000,
        custom_idp_configuration=json.dumps({})
    )
    try:
        db.session.add(config)
        db.session.commit()
    except Exception as e:
        logger.error(f"Got exception trying to add a new config for tenant {tenant_id} to the db. Exception: {e}."
                     f" Giving up...")
        raise e


class TenantConfigsCache(object):
    """
    Object holding a cache of all tenant configs for this authenticator.
    """

    def __init__(self):
        self.tenant_config_models = self.load_tenant_config_cache()
        # self.cache_lifetime = datetime.timedelta(minutes=5)
        # todo -- setting this to 4 seconds for now but we can increase; 4 seconds should allow us to
        # use one cache instance throughout the life of a single request.
        self.cache_lifetime = datetime.timedelta(seconds=4)

    def load_tenant_config_cache(self):
        """
        Global cache of all tenant configs
        :return:
        """
        configs = TenantConfig.query.all()
        self.tenant_config_models = configs
        self.last_update = datetime.datetime.now()
        return configs

    def get_config(self, tenant_id):
        """
        Returns the config for a specific tenant from the cache.
        :param tenant_id:
        :return:
        """
        logger.debug(f"top of get_config for tenant: {tenant_id}")
        tries = 0
        # first, check if the cache is older than the configured max cache lifetime.
        if datetime.datetime.now() > self.last_update + self.cache_lifetime:
            self.load_tenant_config_cache()
            # if we just reloaded the cache, we don't need the check below
            tries = 1
        while tries < 2:
            for t in self.tenant_config_models:
                if t.tenant_id == tenant_id:
                    return t
            # the first pass through, if we didn't find the tenant_id, reload the cache and try again
            if tries==0:
                self.load_tenant_config_cache()
                tries = 1
                continue
            tries = 2
        raise errors.ServiceConfigError(f"tenant id {tenant_id} not found in tenant configurations.")

    def get_custom_oa2_extension_type(self, tenant_id):
        """
        Returns the custom OAuth2 extension type being used by the given tenant_id, or None if not.
        :param tenant_id: the tenant_id to check
        :return: string or None
        """
        logger.debug(f"top of get_custom_oa2_extension_type for tenant: {tenant_id}")
        config = self.get_config(tenant_id)
        custom_idp_config = json.loads(config.custom_idp_configuration)
        # check whether the tenant config has one of the OAuth2 extension configuration properties.
        # this check will expand over time as we add support for additional types of OAuth2 extension modules.
        # TODO -- this must be updated for every new custom oa2 extension type.
        if 'github' in custom_idp_config.keys():
            return 'github'
        if 'cii' in custom_idp_config.keys():
            return 'cii'
        if 'tacc_keycloak' in custom_idp_config.keys():
            return 'tacc_keycloak'

        return None


# singleton cache object -- when migrations are running the TenantConfig relations in Postgres could not
# exist
try:
    tenant_configs_cache = TenantConfigsCache()
except Exception as e:
    if not MIGRATIONS_RUNNING:
        logger.error(f"got exception trying to load tenant configs cache and migrations were NOT running."
                     f" giving up; exception: {e}")
        raise e
    else:
        logger.warn(f"got exception try to load tenant configs object while migrations were running. This better "
                    f"be because the migrations are creating the TenantConfigs relations. Setting cache object to"
                    f"none. e: {e}")
        tenant_configs_cache = None


class Client(db.Model):
    __tablename__ = 'clients'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    client_key = db.Column(db.String(80), unique=False, nullable=False)
    tenant_id = db.Column(db.String(50), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=False, nullable=False)
    callback_url = db.Column(db.String(200), unique=False, nullable=True)
    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    display_name = db.Column(db.String(50), unique=False, nullable=True)
    description = db.Column(db.String(70), unique=False, nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)

    HASH_SALT = 'hQb9xTr7j8vSu'

    def __repr__(self):
        return f'{self.client_id}'

    @property
    def serialize(self):
        return {
            "client_id": self.client_id,
            "client_key": self.client_key,
            "owner": self.username,
            "callback_url": self.callback_url,
            "create_time": self.create_time,
            "last_update_time": self.last_update_time,
            "display_name": self.display_name,
            "description": self.description,
            "tenant_id": self.tenant_id,
            "active": self.active,
        }

    @classmethod
    def generate_client_id(cls):
        """
        Generates a client_id when none is provided by the user.
        :return: 
        """
        hashids = Hashids(salt=Client.HASH_SALT)
        return hashids.encode(uuid.uuid1().int>>64)

    @classmethod
    def get_derived_values(cls, data):
        """
        Computes derived values for the client from input and defaults.
        :param data:
        :return: dict (result)
        """
        result = {}
        result['tenant_id'] = g.tenant_id
        result['username'] = g.username
        result['create_time'] = datetime.datetime.utcnow()
        result['last_update_time'] = datetime.datetime.utcnow()
        # client_id and client_key are optional fields -- if they are not passed, the service will generate them.
        try:
            result['client_id'] = getattr(data, 'client_id')
        except AttributeError:
            result['client_id'] = Client.generate_client_id()
        try:
            result['client_key'] = getattr(data, 'client_key')
        except AttributeError:
            result['client_key'] = Client.generate_client_id()
        try:
            result['callback_url'] = getattr(data, 'callback_url')
        except AttributeError:
            result['callback_url'] = ''

        try:
            result['display_name'] = getattr(data, 'display_name')
        except AttributeError:
            result['display_name'] = result['client_id'][:50]

        try:
            result['description'] = getattr(data, 'description')
        except AttributeError:
            result['description'] = ''

        try:
            result['active'] = getattr(data, 'active')
        except AttributeError:
            result['active'] = True

        # try:
        #     if result['callback_url'] != '':
        #         result['display_name'] = getattr(data, 'display_name')
        # except AttributeError:
        #     msg = f'The field display_name is required when callback_url is provided.'
        #     raise DAOError(msg)

        return result


class AuthorizationCode(db.Model):
    __tablename__ = 'authorization_codes'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    tenant_id = db.Column(db.String(50), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=False, nullable=False)
    client_id = db.Column(db.String(80), db.ForeignKey('clients.client_id'), unique=False, nullable=False)
    client_key = db.Column(db.String(80), unique=False, nullable=False)
    redirect_url = db.Column(db.String(200), unique=False, nullable=True)
    create_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'{self.code}'

    @property
    def serialize(self):
        return {
            "code": self.code,
            "expiry_time": self.expiry_time
        }

    # character set to use to generate random strings from to serve as the actual authorization codes themselves.
    UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits

    # time-to-live for authrorization codes, in seconds.
    CODE_TTL = 600

    @classmethod
    def generate_code(cls, length=40, chars=UNICODE_ASCII_CHARACTER_SET):
        """Generate an authorization code string."""
        rand = random.SystemRandom()
        return ''.join(rand.choice(chars) for _ in range(length))

    @classmethod
    def compute_expiry(cls):
        """Computes the expiry of an authorization code created now."""
        return datetime.datetime.utcnow() + datetime.timedelta(seconds=AuthorizationCode.CODE_TTL)

    @classmethod
    def validate_code(cls, tenant_id, code, client_id, client_key):
        """
        Validate the use of an authorization code. This method checks the code expiry and client credentials against the
        AuthorizationCode table.
        :param tenant_id (str) The tenant_id for which the authorization code belongs.
        :param code: (str) The authorization code.
        :param client_id: (str) The client_id owning the code.
        :param client_key: (str) Associated client_secret.
        :return:
        """
        code_result = cls.query.filter_by(tenant_id=tenant_id,
                                          code=code,
                                          client_id=client_id,
                                          client_key=client_key).first()
        if not code_result:
            raise errors.InvalidAuthorizationCodeError(msg="authorization code not valid.")
        # check for an expired code, plus a fudge factor for clock skew:
        if not datetime.datetime.utcnow() <= code_result.expiry_time + datetime.timedelta(seconds=6):
            raise errors.InvalidAuthorizationCodeError(msg="authorization code has expired.")
        return code_result
        
    @classmethod
    def validate_and_consume_code(cls, tenant_id, code, client_id, client_key):
        """
        Validate the use of an authorization code and then consume it. This method checks the code expiry and
        client credentials against the AuthorizationCode table; if valid the code is then expired.
        :param tenant_id (str) The tenant_id for which the authorization code belongs.
        :param code: (str) The authorization code.
        :param client_id: (str) The client_id owning the code.
        :param client_key: (str) Associated client_secret.
        :return:
        """
        code = AuthorizationCode.validate_code(tenant_id, code, client_id, client_key)
        try:
            db.session.delete(code)
            db.session.commit()
            logger.debug(f"validated and consumed authorization code: {code}")
        except Exception as e:
            logger.error(f"Got exception trying to delete authorization code; code: {code}; e: {e}; type(e): {type(e)}")
            raise errors.InvalidAuthorizationCodeError(msg="authorization code could not be deleted.")
        return code.username


class LdapUser(object):
    """
    Class for representing an LDAP user entry.
    """

    # LDAP meta-data ------
    # dn for the record;
    dn = None
    # we use inetOrgPerson for all LDAP user object
    object_class = 'inetOrgPerson'

    # attributes
    # inetOrgPerson -----
    given_name = None
    last_name = None
    full_name = None
    email = None
    phone = None
    mobile_phone = None
    create_time = None

    # posixAccount -----
    uid = None
    username = None
    password = None

    def __init__(self,
                 dn,
                 givenName=None,
                 sn=None,
                 mail=None,
                 telephoneNumber=None,
                 mobile=None,
                 createTimestamp=None,
                 uidNumber=None,
                 uid=None,
                 userPassword=None):
        """
        Create an LdapUser object corresponding to an entry in an LDAP server.
        :param dn: 
        :param givenName: 
        :param sn:
        :param mail: 
        :param telephoneNumber: 
        :param mobile: 
        :param createTimestamp: 
        :param uidNumber: 
        :param uid: 
        :param userPassword: 
        """
        self.dn = dn
        self.given_name = givenName
        self.last_name = sn
        self.email = mail
        self.phone = telephoneNumber
        self.mobile_phone = mobile
        self.create_time = createTimestamp
        self.uid = uidNumber
        self.username = uid
        self.password = userPassword

    @classmethod
    def from_ldap3_entry(cls, tenant_id, entry):
        """
        Create an LdapUser object from an ldap3 cn obect.
        {:param tenant_id: (str) The tenant_id associated with this entry.
        :param entry:
        :return: LdapUser
        """
        # the attributes of the LdapUser object
        attrs = {}
        try:
            cn = entry['cn'][0]
        except Exception as e:
            logger.error(f"Got exception trying to get cn from entry; entry: {entry}")
            raise DAOError("Unable to parse LDAP user objects.")
        # the cn is the uid/username
        attrs['uid'] = cn
        # compute the DN from the CN
        tenant = tenants.get_tenant_config(tenant_id)
        ldap_user_dn = tenant.ldap_user_dn
        attrs['dn'] = f'cn={cn},{ldap_user_dn}'
        # the remaining params are computed directly in the same way -- as the first entry in an array of bytes
        params = ['givenName', 'sn', 'mail', 'telephoneNumber', 'mobile', 'createTimestamp',
                  'uidNumber', 'userPassword']
        for param in params:
            if param in entry and entry[param][0]:
                # some parans are returned as bytes and others as strings:
                val = entry[param][0]
                if hasattr(val, 'decode'):
                    attrs[param] = val.decode('utf-8')
                else:
                    attrs[param] = val
        # now, construct and return a LdapUser object
        return LdapUser(**attrs)

    def save(self, conn):
        """
        Save an LdapUser object in an LDAP server with connection, conn.
        :param conn (ldap3.core.connection.Connection) A connection to the ldap server.
        :return:
        """
        # first, get the ldap representation of this object and remove any fields not allowed to be passed to
        # ldap on save:
        repr = self.serialize_to_ldap
        repr.pop('create_time', None)
        repr.pop('dn')
        try:
            result = conn.add(self.dn, self.object_class, repr)
        except Exception as e:
            msg = f'Got exception trying to add a user to LDAP; exception: {e}'
            logger.error(msg)
            raise DAOError("Unable to communicate with LDAP database when trying to save user account.")
        if not result:
            msg = f'Got False result trying to add a user with dn {self.dn} to LDAP; error data: {conn.result}'
            logger.error(msg)
            raise DAOError("Unable to save user account in LDAP database; "
                           "Required fields could be missing or improperly formatted.")
        # the object was saved successfully so we can now return it:
        return True

    @property
    def serialize_to_ldap(self):
        """
        Creates a Python dictionary using the LDAP inetorgperson attributes names.
        :return:
        """
        result = {'dn': self.dn}
        if self.given_name:
            result['givenName'] = self.given_name
        if self.last_name:
            result['sn'] = self.last_name
        if self.email:
            result['mail'] = self.email
        if self.phone:
            result['telephoneNumber'] = self.phone
        if self.mobile_phone:
            result['mobile'] = self.mobile_phone
        if self.create_time:
            result['createTimestamp'] = self.create_time
        if self.uid:
            result['uidNumber'] = self.uid
        if self.username:
            result['uid'] = self.username
        if self.password:
            result['userPassword'] = self.password
        return result

    @property
    def serialize(self):
        return {
            'dn': self.dn,
            'given_name': self.given_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone,
            'mobile_phone': self.mobile_phone,
            'create_time': self.create_time,
            'username': self.username,
            'uid': self.uid,
        }


class LdapOU(object):
    """
    Class for representing an LDAP organizational unit.
    """

    field_map = {
        "ou": "ou"
    }

    # LDAP meta-data -----
    dn = None
    object_class = 'organizationalUnit'

    # attributes
    ou = None

    def __init__(self, dn):
        self.dn = dn

    def __str__(self):
        return self.ou

    def __unicode__(self):
        return self.ou


class TokenRequestBody(object):
    """
    Represents a request body sent to the POST /v3/oauth2/tokens endpoint. This class is used to
    create a request body when www-form content types are passed instead of using the openapicore.validated_body
    object.
    """
    def __init__(self, form):
        """
        Send request.form to generate an object with the same attributes.
        :param form: A flask request.form object
        """
        self.grant_type = form.get('grant_type')
        self.username = form.get('username')
        self.password = form.get('password')
        self.redirect_uri = form.get('redirect_uri')
        self.code = form.get('code')
        self.refresh_token = form.get('refresh_token')


class Token(object):

    token = None

    def __init__(self, client_id=None, client_secret=None, username=None, password=None):
        """
        oauth2 token
        """
        pass
        # self.client_id = client_id
        # self.client_secret = client_secret
        # self.username = username
        # self.password = password

    @property
    def serialize(self):
     return {
         'token': self.token,
         # 'expires_in': self.ttl,
         # 'expires_at': self.expires_at
     }

    @classmethod
    def get_derived_values(cls, data):
        """
        Computes derived values for the client from input and defaults.
        :param data:
        :return: dict (result)
        """
        result = {}
        # always required:
        result['grant_type'] = getattr(data, 'grant_type', None)
        # depends on grant type
        # password grant:
        result['username'] = getattr(data, 'username', None)
        result['password'] = getattr(data, 'password', None)
        # authorization code grant:
        result['redirect_uri'] = getattr(data, 'redirect_uri', None)
        result['code'] = getattr(data, 'code', None)
        # refresh token:
        result['refresh_token'] = getattr(data, 'refresh_token', None)
        return result


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
    local_client = {
        "client_id": client_id,
        "client_key": conf.client_key,
        "callback_url": f'http://localhost:5000{conf.client_callback}',
        "display_name": conf.client_display_name,
        "tenant_id": tenant_id,
        "username": "tapis",
        'create_time':  datetime.datetime.utcnow(),
        'last_update_time': datetime.datetime.utcnow(),
        'active': True
    }
    add_client_to_db(local_client)
    # now register the client with the tenant's base url:
    client_id = f'{tenant_id}.{conf.client_id}'
    callback_url = f'{conf.primary_site_admin_tenant_base_url}{conf.client_callback}'
    # replace "admin" with the tenant_id:
    callback_url = callback_url.replace("admin", tenant_id)
    client = deepcopy(local_client)
    client['client_id'] = client_id
    client['callback_url'] = callback_url
    add_client_to_db(client)
    return local_client, client


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
            logger.debug(f"registering localhost {data['tenant_id']} client; callback_url: {data['callback_url']}.")
            client = Client(**data)
            db.session.add(client)
            db.session.commit()
        else:
            logger.debug(f"client with id {data['client_id']} for tenant {data['tenant_id']} already existed.")
    except Exception as e:
        logger.info(f"Got exception trying to create the token web app client; this better be migrations; e: {e}")
        db.session.rollback()


# dictionary of descriptions of the OAuth clients used by the Token Webapp
token_webapp_clients = {}

if conf.populate_all_clients:
    logger.debug("populating all clients...")
    # generate a client for every tenant assigned to this instance -
    for tenant_id in conf.tenants:
        local_client, client = create_clients_for_tenant(tenant_id)
        token_webapp_clients[f'local.{tenant_id}'] = local_client
        token_webapp_clients[tenant_id] = client
