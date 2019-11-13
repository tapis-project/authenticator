from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPBindError

from service import get_tenant_config
from service.errors import InvalidPasswordError

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


def get_ldap_connection(tenant_id, bind_dn=None, bind_credential=None):
    """
    Get an ldap connection to the ldap server corresponding to the tenant_id. 
    :param tenant_id: 
    :return: 
    """
    tenant = get_tenant_config(tenant_id)
    server = Server(tenant['ldap_url'], port=tenant['ldap_port'], use_ssl=tenant['ldap_use_ssl'])
    if bind_dn and bind_credential:
        conn = Connection(server, bind_dn, bind_credential, auto_bind=True)
    else:
        conn = Connection(server, tenant['ldap_bind_dn'], tenant['ldap_bind_credential'], auto_bind=True)
    return conn

def get_dn(tenant_id, username):
    """
    Get the DN for a specific username within a tenant.
    :param tenant_id: 
    :param username: 
    :return: 
    """
    tenant = get_tenant_config(tenant_id)
    ldap_user_dn = tenant['ldap_user_dn']
    return f'uid={username},{ldap_user_dn}'

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
        get_ldap_connection(tenant_id, bind_dn, password)
    except LDAPBindError as e:
        logger.debg(f'got exception checking password: {e}')
        raise InvalidPasswordError("Invalid username/password combination.")

def add_user(tenant_id, username, password):
    """
    Add an LDAP record
    :param tenant_id: 
    :param username: 
    :param password: 
    :return: 
    """


