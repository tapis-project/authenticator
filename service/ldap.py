from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPBindError
import json

from service import get_tenant_config
from service.errors import InvalidPasswordError
from service.models import LdapOU, LdapUser

from common.config import conf
from common.errors import DAOError

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


def get_ldap_connection(ldap_server, ldap_port, bind_dn, bind_password, use_ssl=True):
    """
    Get a connection to an LDAP server.
    :param ldap_server: The URI of the ldap server.
    :param ldap_port: The port of the ldap server.
    :param bind_dn: The DN to use to bind.
    :param bind_password: The password associated with the bind DN.
    :param use_ssl: Whether to use SSL when connecting to the LDAP server.
    :return:
    """
    server = Server(ldap_server, port=ldap_port, use_ssl=use_ssl)
    conn = Connection(server, bind_dn, bind_password, auto_bind=True)
    return conn

def get_tapis_ldap_server_info():
    """
    Returns dictionary of Tapis LDAP server connection information.
    :return: (dict)
    """
    return {
        "server": conf.dev_ldap_url,
        "port": conf.dev_ldap_port,
        "bind_dn": conf.dev_ldap_bind_dn,
        "bind_password": conf.dev_ldap_bind_credential,
        "base_dn": conf.dev_ldap_tenants_base_dn,
        "use_ssl": conf.dev_ldap_use_ssl
    }

tapis_ldap = get_tapis_ldap_server_info()

def get_tapis_ldap_connection():
    """
    Convenience wrapper function to get an ldap connection to the Tapis dev ldap server.
    :return:
    """
    try:
        return get_ldap_connection(ldap_server = tapis_ldap['server'],
                                   ldap_port = tapis_ldap['port'],
                                   bind_dn = tapis_ldap['bind_dn'],
                                   bind_password = tapis_ldap['bind_password'],
                                   use_ssl = tapis_ldap['use_ssl'])
    except LDAPBindError as e:
        logger.debug(f'Invalid Tapis bind credential: {e}')
        raise InvalidPasswordError("Invalid username/password combination.")
    except Exception as e:
        msg = f"Got exception trying to create connection object to Tapis LDAP. e: {e}"
        logger.error(msg)
        raise DAOError(msg)


def add_tapis_ou(ou):
    """
    Add an LDAP record representing an Organizational Unit (ou) to the Tapis LDAP.
    :param ou: (LdapOU) The OU object to add.
    :return:
    """
    conn = get_tapis_ldap_connection()
    try:
        result = conn.add(ou.dn, ou.object_class)
    except Exception as e:
        msg = f'got an error trying to add an ou. Exception: {e}; ou.dn: {ou.dn}; ou.object_class: {ou.object_class}'
        logger.error(msg)
    if not result:
        msg = f'Got False result trying to add OU to LDAP; error data: {conn.result}'
        logger.error(msg)
        raise DAOError("Unable to add OU to LDAP database; "
                       "Required fields could be missing or improperly formatted.")
    return True


def list_tapis_ous():
    """
    List the OUs associated with the Tapis LDAP server.
    :return:
    """
    conn = get_tapis_ldap_connection()
    try:
        # search for all cn's under the tapis tenants base_dn and pull back all attributes
        result = conn.search(conf.dev_ldap_tenants_base_dn, '(ou=*)', attributes=['*'])
    except Exception as e:
        msg = f'Got an exception trying to list Tapis OUs. Exception: {e}'
        logger.error(msg)
        raise DAOError(msg)
    if not result:
        msg = f'Got an error trying to list Tapis OUs. message: {conn.result}'
        logger.error(msg)
    # return the results -
    result = []
    for ent in conn.entries:
        result.append(ent.entry_attributes_as_dict)
    return result


def create_tapis_ldap_tenant_ou(tenant_id):
    """
    Create an OU in the Tapis LDAP for a tenant id.
    :param tenant_id:
    :return:
    """
    base_dn = tapis_ldap['base_dn']
    ou = LdapOU(dn=f'ou=tenants.{tenant_id},{base_dn}')
    return add_tapis_ou(ou)


def get_tenant_ldap_connection(tenant_id, bind_dn=None, bind_password=None):
    """
    Convenience wrapper function to get an ldap connection to the ldap server corresponding to the tenant_id.
    :param tenant_id: (str) The id of the tenant.
    :param bind_dn: (str) Optional dn to use to bind. Pass this to check validity of a username/password.
    :param bind_password (str) Optional password to use to bind. Pass this to check validity of a username/password.
    :return: 
    """
    tenant = get_tenant_config(tenant_id)
    # if we are passed specific bind credentials, use those:
    if not bind_dn is None:
        return get_ldap_connection(ldap_server=tenant['ldap_url'],
                                   ldap_port=tenant['ldap_port'],
                                   bind_dn=bind_dn,
                                   bind_password=bind_password,
                                   use_ssl=tenant['ldap_use_ssl'])
    # otherwise, return the connection associated with the tenant's bind credentials -
    return get_ldap_connection(ldap_server=tenant['ldap_url'],
                               ldap_port=tenant['ldap_port'],
                               bind_dn=tenant['ldap_bind_dn'],
                               bind_password=tenant['ldap_bind_credential'],
                               use_ssl=tenant['ldap_use_ssl'])

def list_tenant_users(tenant_id):
    """
    List all users in a tenant
    :param tenant_id: (str) the tenant id to use.
    :return:
    """
    tenant = get_tenant_config(tenant_id)
    conn = get_tenant_ldap_connection(tenant_id)
    result = conn.search(tenant['ldap_user_dn'], '(cn=*)', attributes=['*'])
    if not result:
        msg = f'Error retrieving users; debug information: {conn.result}'
        logger.error(msg)
        raise DAOError(msg)
    result = []
    for ent in conn.entries:
        result.append(ent.entry_attributes_as_dict)
    return result

def get_dn(tenant_id, username):
    """
    Get the DN for a specific username within a tenant.
    :param tenant_id: 
    :param username: 
    :return: 
    """
    tenant = get_tenant_config(tenant_id)
    ldap_user_dn = tenant['ldap_user_dn']
    return f'cn={username},{ldap_user_dn}'

def check_username_password(tenant_id, username, password):
    """
    Check 
    :param tenant_id: 
    :param username: 
    :param password: 
    :return: 
    """
    bind_dn = get_dn(tenant_id, username)
    try:
        conn = get_tenant_ldap_connection(tenant_id, bind_dn=bind_dn, bind_password=password)
    except LDAPBindError as e:
        logger.debug(f'got exception checking password: {e}')
        raise InvalidPasswordError("Invalid username/password combination.")


def add_user(tenant_id, user):
    """
    Add an LDAP record representing a user in a specific tenant.
    :param tenant_id: (str) The tenant id of the tenant where the user should be added.
    :param user: (LdapUser) An LdapUser object containing the details of the user to add.
    :return: 
    """
    conn = get_tenant_ldap_connection(tenant_id)
    user.save(conn)

def add_test_user(tenant_id, username):
    """
    Add a testuser to the Tapis LDAP for tenant id, tenant_id. The username is required and from it, all inetorgperson
    attributes are derived.
    :param tenant_id: (str) the tenant id.
    :param username: (str) the username of the test account.
    :return:
    """
    # first, create an LdapUser object with the appropriate attributes.
    base_dn = tapis_ldap['base_dn']
    user = LdapUser(dn=f'cn={username},ou=tenants.{tenant_id},{base_dn}',
                    givenName=username,
                    sn=username,
                    mail=f'{username}@test.tapis.io',
                    userPassword=username)
    # now call the generic add user for the tenant id:
    add_user(tenant_id, user)