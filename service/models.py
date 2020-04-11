from copy import deepcopy
import datetime
from flask import Flask, g
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from hashids import Hashids
import string
import random
import uuid

from common.config import conf
from common.errors import DAOError
from common.logs import get_logger
from common import errors

logger = get_logger(__name__)

from service import tenants

app = Flask(__name__)
# app.secret_key = b"\x00" + secrets.token_bytes(12) + b"\x00"
app.secret_key = b"AGHsjfh!#%$SNFJqw"
app.config['SQLALCHEMY_DATABASE_URI'] = conf.sql_db_url
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


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
            result['display_name'] = result['callback_url']

        try:
            result['description'] = getattr(data, 'description')
        except AttributeError:
            result['description'] = ''

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
        ldap_user_dn = tenant['ldap_user_dn']
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
        'last_update_time': datetime.datetime.utcnow()
    }
    add_client_to_db(local_client)
    # now register the client with the tenant's base url:
    client_id = f'{tenant_id}.{conf.client_id}'
    callback_url = f'{conf.service_tenant_base_url}{conf.client_callback}'
    # replace "master" with the tenant_id:
    callback_url = callback_url.replace("master", tenant_id)
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
    logger.debug("populting all clients...")
    # generate a client for every tenant assigned to this instance -
    for tenant_id in conf.tenants:
        local_client, client = create_clients_for_tenant(tenant_id)
        token_webapp_clients[f'local.{tenant_id}'] = local_client
        token_webapp_clients[tenant_id] = client
