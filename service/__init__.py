from common.auth import tenants as ts
from common.config import conf
from common import errors

def add_tenant_ldaps():
    """
    
    :return: 
    """
    result = []
    for tenant in ts:
        # in dev mode, the authenticator can be configured to not use the security kernel, in which case we must get
        # the ldap information for a "dev" tenant directly from the service configs:
        if not conf.use_sk:
            tenant['ldap_url'] = conf.dev_ldap_url
            tenant['ldap_port'] = conf.dev_ldap_port
            tenant['ldap_use_ssl'] = conf.dev_ldap_use_ssl
            tenant['ldap_user_dn'] = conf.dev_ldap_user_dn
            tenant['ldap_bind_dn'] = conf.dev_ldap_bind_dn
            tenant['ldap_bind_credential'] = conf.dev_ldap_bind_credential
            result.append(tenant)
        else:
            # TODO -- get ldap data from the Tenants API and get the ldap bind secret from the security kernel...
            pass
    return result


tenants = add_tenant_ldaps()


def get_tenant_config(tenant_id):
    """
    Return the config for a specific tenant_id from the tenants config.
    :param tenant_id:
    :return:
    """
    for tenant in tenants:
        if tenant['tenant_id'] == tenant_id:
            return tenant
    raise errors.BaseTapisError("invalid tenant id.")
