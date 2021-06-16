from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPBindError
import json

from service import tenants, MIGRATIONS_RUNNING
from service.errors import InvalidPasswordError
from service.models import LdapOU, LdapUser, tenant_configs_cache

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
    if conf.use_tenants:
        dev_tenant = tenants.get_tenant_config(tenant_id='dev')
        return {
            "server": dev_tenant.get('ldap_url'),
            "port": dev_tenant.get('ldap_port'),
            "bind_dn": dev_tenant.get('ldap_bind_dn'),
            "bind_password": dev_tenant.get('ldap_bind_credential'),
            "base_dn": dev_tenant.get('dev_ldap_tenants_base_dn'),
            "use_ssl": dev_tenant.get('ldap_use_ssl')
        }
    else:
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
    tenant = tenants.get_tenant_config(tenant_id)
    logger.debug(f"getting ldap connection for tenant {tenant_id}")
    # if we are passed specific bind credentials, use those:
    if not bind_dn is None:
        return get_ldap_connection(ldap_server=tenant.ldap_url,
                                   ldap_port=tenant.ldap_port,
                                   bind_dn=bind_dn,
                                   bind_password=bind_password,
                                   use_ssl=tenant.ldap_use_ssl)
    # otherwise, return the connection associated with the tenant's bind credentials -
    return get_ldap_connection(ldap_server=tenant.ldap_url,
                               ldap_port=tenant.ldap_port,
                               bind_dn=tenant.ldap_bind_dn,
                               bind_password=tenant.ldap_bind_credential,
                               use_ssl=tenant.ldap_use_ssl)

def get_custom_ldap_config(tenant_id):
    """
    Checks the authenticator tenant config for a custom idp config and returns the attributes
    as a python dictionary.
    :return: dictionary of attributes related to customizing the ldap configuration.
    """
    # if this is migrations, we won't be able to access the custom authenticator tenant config (in the db) so we just
    # return immediately --
    if MIGRATIONS_RUNNING:
        return {}
    # this is the authenticator configuration for the tenant --
    authenticator_tenant_config = tenant_configs_cache.get_config(tenant_id)
    custom_idp_configuration = json.loads(authenticator_tenant_config.custom_idp_configuration)
    try:
        return custom_idp_configuration['ldap']
    except KeyError:
        return {}


def list_tenant_users(tenant_id, limit=None, offset=0):
    """
    List users in a tenant
    :param tenant_id: (str) the tenant id to use.
    :param limit (int): The maximum number of users to return.
    :param offset (int): A position to start the paged search.
    :return:
    """
    logger.debug(f'top of list_tenant_users; tenant_id: {tenant_id}; limit: {limit}; offset: {offset}')
    # this gets the tenant object from the Tenants API cache --
    tenant = tenants.get_tenant_config(tenant_id)
    conn = get_tenant_ldap_connection(tenant_id)
    # this gets the custom authenticator config for the ldap --
    custom_ldap_config = get_custom_ldap_config(tenant_id)
    if not limit:
        limit = custom_ldap_config.get('default_page_limit')
    if not limit:
        limit = conf.default_page_limit

    cookie = None
    # there are multiple ways to modify the ldap search using the custom_ldap_config. If user_search_filter is provided,
    # that one is always used.
    user_search_filter = custom_ldap_config.get('user_search_filter')
    logger.debug(f"user_search_filter from custom ldap config: {user_search_filter}")
    # if user_search_filter is not specified, look for a user_search_prefix and/or user_search_supplemental_filter
    if not user_search_filter:
        # if user_search_prefix is not set, we default to using '(cn=*)'
        user_search_prefix = custom_ldap_config.get('user_search_prefix', '(cn=*)')
        logger.debug(f"user_search_prefix from custom ldap config: {user_search_prefix}")
        user_search_supplemental_filter = custom_ldap_config.get('user_search_supplemental_filter')
        logger.debug(f"user_search_supplemental_filter from custom ldap config: {user_search_supplemental_filter}")
        if user_search_supplemental_filter:
            user_search_filter = f'(&{user_search_prefix}{user_search_supplemental_filter})'
        else:
            user_search_filter = user_search_prefix
        logger.debug(f"final custom user_search_filter: {user_search_filter}")

    # the user_dn is always stored on the Tenants API's LDAP record. however, there are two possible user_dn
    # types: one that includes the user_search_prefix and one that does not. to include the user_search_prefix, the
    # user_dn will have the form <user_search_prefix>=${username},...
    user_dn = tenant.ldap_user_dn
    # if the tenant's user_dn config includes the template variable ${username}, we need to strip it out here and
    # pull out the user search prefix.
    if '${username},' in tenant.ldap_user_dn:
        parts = tenant.ldap_user_dn.split('${username},')
        if not len(parts) == 2:
            raise DAOError("Unable to compute LDAP user search DN.")
        # parts will be split into 'uid=' and 'ou=foo, o=bar, ..."
        # the user search prefix should therefore be of the form: '(<parts[0])*)'
        # we only use this for the user_search_filter if the user_search_filter was NOT set above (i.e., if it is still
        # just the default, (cn=*):
        if user_search_filter == '(cn=*)':
            user_search_filter = f'({parts[0]}*)'
        # regardless of the user_search_filter though, we need to strip out the ${username}, from the user_dn, so
        # override that now:
        user_dn = parts[1]
    logger.debug(f'using user_dn: {user_dn} and user_search_filter: {user_search_filter}')
    # As per RFC2696, the page cookie for paging can only be used by the same connection; we take the following
    # approach:
    # if the offset is not 0, we first pull the first <offset> entries to get the cookie, then we get use the returned
    # cookie to get the actual page of results that we want.
    if offset > 0:
        # we only need really need the cookie so we just get the cn attribute
        result = conn.search(user_dn, user_search_filter, attributes=['cn'], paged_size=offset)
        if not result:
            # it is possible to get a "success" result when there are no users in the OU -
            if hasattr(conn.result, 'get') and conn.result.get('description') == 'success':
                return [], None
            msg = f'Error retrieving users; debug information: {conn.result}'
            logger.error(msg)
            raise DAOError(msg)
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
    result = conn.search(user_dn, user_search_filter, attributes=['*'], paged_size=limit, paged_cookie=cookie)
    if not result:
        # it is possible to get a "success" result when there are no users in the OU -
        if hasattr(conn.result, 'get') and conn.result.get('description') == 'success':
            return [], None
        msg = f'Error retrieving users; debug information: {conn.result}'
        logger.error(msg)
        raise DAOError(msg)
    result = []
    for ent in conn.entries:
        # create LdapUser objects for each entry:
        user = LdapUser.from_ldap3_entry(tenant_id, ent.entry_attributes_as_dict)
        result.append(user)
    return result, offset+len(result)


def get_tenant_user(tenant_id, username):
    """
    Get the profile of a specific user in a tenant.
    :param tenant_id:
    :param username:
    :return:
    """
    logger.debug(f"top of get_tenant_user; tenant_id: {tenant_id}; username: {username}")
    tenant = tenants.get_tenant_config(tenant_id)
    conn = get_tenant_ldap_connection(tenant_id)
    tenant_base_dn = tenant.ldap_user_dn
    logger.debug(f"ldap_user_dn on tenant record: {tenant_base_dn}. Checking if we need to replace the "
                 f"$username token...")
    user_filter = f'(cn={username})'
    if '${username},' in tenant.ldap_user_dn:
        parts = tenant.ldap_user_dn.split('${username},')
        if not len(parts) == 2:
            raise DAOError("Unable to calculate search DN.")
        tenant_base_dn = parts[1]
        user_filter = f'({parts[0]}{username})'
    logger.debug(f'searching with params: {tenant_base_dn}; user_filter: {user_filter}')
    result = conn.search(f'{tenant_base_dn}', user_filter, attributes=['*'])
    if not result:
        # it is possible to get a "success" result when there are no users in the OU -
        if hasattr(conn.result, 'description') and conn.result.description == 'success':
            return [], None
        msg = f'Error retrieving user; debug information: {conn.result}'
        logger.error(msg)
        raise DAOError(msg)
    result = []
    logger.debug(f'conn.entries: {conn.entries}')
    user = LdapUser.from_ldap3_entry(tenant_id, conn.entries[0].entry_attributes_as_dict)
    return user


def get_dn(tenant_id, username):
    """
    Get the DN for a specific username within a tenant.
    :param tenant_id: 
    :param username: 
    :return: 
    """
    tenant = tenants.get_tenant_config(tenant_id)
    ldap_user_dn = tenant.ldap_user_dn
    if '${username},' in tenant.ldap_user_dn:
        parts = tenant.ldap_user_dn.split('${username},')
        if not len(parts) == 2:
            raise DAOError("Unable to calculate search DN.")
        ldap_user_dn = parts[1]
        return f'{parts[0]}{username},{ldap_user_dn}'
    # needed for test ldap:
    if tenant.ldap_bind_dn.startswith('cn'):
        return f'cn={username},{ldap_user_dn}'
    # needed for tacc:
    else:
        return f'uid={username},{ldap_user_dn}'


def check_username_password(tenant_id, username, password):
    """
    Check 
    :param tenant_id: 
    :param username: 
    :param password: 
    :return: 
    """
    logger.debug(f"top of check_username_password for: {tenant_id}; {username}")
    bind_dn = get_dn(tenant_id, username)
    logger.debug(f"got bind_dn: {bind_dn}")
    try:
        get_tenant_ldap_connection(tenant_id, bind_dn=bind_dn, bind_password=password)
    except LDAPBindError as e:
        logger.debug(f'got exception checking password: {e}; type(e): {type(e)}')
        raise InvalidPasswordError("Invalid username/password combination.")
    return True


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


def populate_test_ldap(tenant_id='dev'):
    """
    Initialize the test LDAP with an OU and set of test accounts.
    :return:
    """
    # number of users to create -
    NUM_USERS = 10
    # first check if the OU already exists
    ous = list_tapis_ous()
    found = False
    for ou in ous:
        if ou['ou'][0] == f'tenants.{tenant_id}':
            found = True
            logger.debug(f"OU tenants.{tenant_id} already present.")
    if not found:
        logger.debug(f'adding OU tenants.{tenant_id}')
        create_tapis_ldap_tenant_ou(tenant_id)
    users, _ = list_tenant_users(tenant_id, limit=NUM_USERS+1)
    usernames = [u.serialize['username'] for u in users]
    for i in range(1, NUM_USERS+1):
        username = f'testuser{i}'
        if username not in usernames:
            logger.debug(f"adding user {username}")
            add_test_user(tenant_id, username)
        else:
            logger.debug(f"user {username} already present.")
    # Add testadmin user
    username = f'testadmin'
    if username not in usernames:
        logger.debug(f"adding user {username}")
        add_test_user(tenant_id, username)
    else:
        logger.debug(f"user {username} already present.")
