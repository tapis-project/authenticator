from common.auth import Tenants, get_service_tapy_client
from common.config import conf
from common import errors

from common.logs import get_logger
logger = get_logger(__name__)

t = get_service_tapy_client()

class AuthenticatorTenants(Tenants):

    def extend_tenant(self, tenant):
        """
        Add the LDAP metadata to the tenant description
        :param t: a tenant
        :return:
        """
        tenant_id = tenant['tenant_id']
        # if this is not a tenant that this authenticator is supposed to serve, then just return immediately
        if not tenant_id in conf.tenants:
            logger.debug(f"skipping tenant_id: {tenant_id} as it is not in the list of tenants.")
            return tenant
        if not conf.use_tenants:
            if tenant_id == 'dev':
                tenant['ldap_url'] = conf.dev_ldap_url
                tenant['ldap_port'] = conf.dev_ldap_port
                tenant['ldap_use_ssl'] = conf.dev_ldap_use_ssl
                tenant['dev_ldap_tenants_base_dn'] = conf.dev_ldap_tenants_base_dn
                tenant['ldap_user_dn'] = conf.dev_ldap_user_dn
                tenant['ldap_bind_dn'] = conf.dev_ldap_bind_dn
            # we only support testing the "dev" tenant ldap under the scenario of use_tenants == false.
        else:
            # todo - the "dev_ldap_tenants_base_dn" property describes where to store the organizational units (OUs) for
            #  the tenants. this property is unique to the dev LDAP where the authenticator has write access and can
            #  create OUs for each tenant. thus, it is not stored in /returned by the tenants service, so we hard code
            #  it based on a service config for now,
            if tenant_id == 'dev':
                tenant['dev_ldap_tenants_base_dn'] = conf.dev_ldap_tenants_base_dn
            # look up ldap info from tenants service
            try:
                tenant_response = t.tenants.get_tenant(tenant_id=tenant_id)
            except Exception as e:
                logger.error(f"Got exception trying to look up tenant info for tenant: {tenant_id}; e: {e}")
            if tenant_response.user_ldap_connection_id:
                logger.debug(f'got a user_ldap_connection_id: {tenant_response.user_ldap_connection_id} for '
                             f'tenant: {tenant_id}. Now looking up LDAP data...')
                try:
                    ldap_response = t.tenants.get_ldap(ldap_id=tenant_response.user_ldap_connection_id)
                except Exception as e:
                    logger.error(f"Got exception trying to look up ldap info for "
                                 f"ldap_id: {tenant_response.user_ldap_connection_id}; e: {e}")
                    raise e
                try:
                    tenant['ldap_url'] = ldap_response.url
                    tenant['ldap_port'] = ldap_response.port
                    tenant['ldap_use_ssl'] = ldap_response.use_ssl
                    tenant['ldap_user_dn'] = ldap_response.user_dn
                    tenant['ldap_bind_dn'] = ldap_response.bind_dn
                except AttributeError as e:
                    logger.error(f"Got KeyError looking for an LDAP attr in the response; e: {e}")
                    raise e
            else:
                logger.debug(f'did not get a user_ldap_connection_id: {tenant_response.user_ldap_connection_id} for '
                             f'tenant: {tenant_id}.')

        if not conf.use_sk:
            if tenant['tenant_id'] == 'dev':
                tenant['ldap_bind_credential'] = conf.dev_ldap_bind_credential
            elif tenant['tenant_id'] == 'tacc':
                tenant['ldap_bind_credential'] = conf.dev_tacc_ldap_bind_credential
        else:
            # TODO -- get ldap data from the Tenants API and get the ldap bind secret from the security kernel...
            pass
        return tenant


tenants = AuthenticatorTenants()

