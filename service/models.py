import datetime
from flask import Flask, g
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from hashids import Hashids
import secrets
import uuid

from common.config import conf
from common.errors import DAOError
from common.logs import get_logger
logger = get_logger(__name__)

from service import get_tenant_config

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
            "last_update_time": self.last_update_time
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
        return result


class AuthorizationCode(db.Model):
    __tablename__ = 'authorization_codes'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    tenant_id = db.Column(db.String(50), unique=False, nullable=False)
    client_id = db.Column(db.String(80), db.ForeignKey('clients.client_id'), unique=True, nullable=False)
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
        tenant = get_tenant_config(tenant_id)
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
        result['tenant_id'] = g.tenant_id
        result['username'] = getattr(data, 'username')
        result['password'] = getattr(data, 'password')
        result['client_id'] = getattr(data, 'client_id')
        result['client_secret'] = getattr(data, 'client_secret')

        return result