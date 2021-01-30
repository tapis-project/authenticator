from common.auth import Tenants, get_service_tapis_client
from common.auth import tenants as auth_tenants
from common.config import conf
from common import errors

from common.logs import get_logger
logger = get_logger(__name__)

# there is a chicken and egg problem in that we need a tenants manager object to instantiate the tapis
# client, but we need a tapis client to create the AuthenticatorTenants manager. so, we first
# instantiate the tapis client here with the generic tenants manager from the common package, and then at the
# bottom of this module we replace it with the AuthenticatorTenants
logger.debug("creating the authenticator tapis service client...")
t = get_service_tapis_client(tenants=auth_tenants)


class AuthenticatorTenants(Tenants):

    def extend_tenant(self, tenant):
        """
        Add the LDAP metadata to the tenant description
        :param t: a tenant
        :return:
        """
        tenant_id = tenant.tenant_id
        # if this is not a tenant that this authenticator is supposed to serve, then just return immediately
        if not tenant_id in conf.tenants:
            logger.debug(f"skipping tenant_id: {tenant_id} as it is not in the list of tenants.")
            return tenant
        if not conf.use_tenants:
            if tenant_id == 'dev':
                tenant.ldap_url = conf.dev_ldap_url
                tenant.ldap_port = conf.dev_ldap_port
                tenant.ldap_use_ssl = conf.dev_ldap_use_ssl
                tenant.dev_ldap_tenants_base_dn = conf.dev_ldap_tenants_base_dn
                tenant.ldap_user_dn = conf.dev_ldap_user_dn
                tenant.ldap_bind_dn = conf.dev_ldap_bind_dn
            # we only support testing the "dev" tenant ldap under the scenario of use_tenants == false.
        else:
            # todo - the "dev_ldap_tenants_base_dn" property describes where to store the organizational units (OUs) for
            #  the tenants. this property is unique to the dev LDAP where the authenticator has write access and can
            #  create OUs for each tenant. thus, it is not stored in /returned by the tenants service, so we hard code
            #  it based on a service config for now,
            if tenant_id == 'dev':
                tenant.dev_ldap_tenants_base_dn = conf.dev_ldap_tenants_base_dn
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
                    tenant.ldap_url = ldap_response.url
                    tenant.ldap_port = ldap_response.port
                    tenant.ldap_use_ssl = ldap_response.use_ssl
                    tenant.ldap_user_dn = ldap_response.user_dn
                    tenant.ldap_bind_dn = ldap_response.bind_dn
                except AttributeError as e:
                    logger.error(f"Got KeyError looking for an LDAP attr in the response; e: {e}")
                    raise e
            else:
                logger.debug(f'did not get a user_ldap_connection_id: {tenant_response.user_ldap_connection_id} for '
                             f'tenant: {tenant_id}.')

        if not conf.use_sk:
            if tenant.tenant_id == 'dev':
                tenant.ldap_bind_credential = conf.dev_ldap_bind_credential
            elif tenant.tenant_id == 'tacc':
                tenant.ldap_bind_credential = conf.dev_tacc_ldap_bind_credential
        else:
            if tenant_response.user_ldap_connection_id:
                if not getattr(ldap_response, 'bind_credential'):
                    msg = f"Error -- ldap object missing bind credential; description: {ldap_response}."
                    logger.error(msg)
                    raise errors.BaseTapisError(msg)
                tenant.ldap_bind_credential = get_ldap_bind_from_sk(ldap_response.bind_credential)
        return tenant

def get_ldap_bind_from_sk(bind_credential_name):
    """
    Retrieve the ldap bind secret from SK for a specific ldap id.
    ldap_response: the ldap object description containing the bind_credential attribute
    :return:
    """
    logger.debug(f'top of get_ldap_bind_from_sk; bind_credential_name: {bind_credential_name}')
    if not bind_credential_name:
        msg = f"Error --get_ldap_bind_from_sk did not get a bind_credential_name."
        logger.error(msg)
        raise errors.BaseTapisError(msg)
    try:
        ldap_bind_secret = t.sk.readSecret(secretType='user',
                                           secretName=bind_credential_name,
                                           tenant=conf.service_tenant_id,
                                           user=conf.service_name)
    except Exception as e:
        msg = f"Got exception trying to retrieve ldap bind secret from SK; exception: {e}."
        logger.error(msg)
        raise errors.BaseTapisError(msg)
    # the SK stores secrets in the secretMap attribute, which is a mapping of user-provided string attributes
    # to string values. for the ldap bind secrets, the convention is that the secretMap should contain one
    # key, password, containing the actual password
    try:
        bind_credential = ldap_bind_secret.secretMap.password
    except Exception as e:
        msg = f"got exception trying to retrieve the ldap_bind_password from the SK secret; e: {e}"
        logger.error(msg)
        raise errors.BaseTapisError(msg)
    return bind_credential


def store_ldap_bind_secret_in_sk(ldap_connection_id, password, tenant='admin', user='authenticator'):
    """
    This utility documents how to create a new LDAP bind secret in SK. It is not actually used by authentcitor
    but it can be used by another utility for bootstrapping the creation of a tenant that will have a user
    LDAP.

    :param ldap_connection_id: the id of the ldap object.
    :param password: The password for the ldap bind.
    :param tenant: The tenant_id in which the secret belongs; should be the same as the tenant id of the
                   authetictor service that owns the secret.
    :param user: The name of the service that owns the secret; defaults to "authenticator".
    :return:
    """
    try:
        t.sk.writeSecret(secretType='user',
                         secretName=f'ldap.{ldap_connection_id}',
                         tenant=tenant,
                         user=user,
                         data={'password': password})
    except Exception as e:
        msg = f"could not save secret with sk; exception: {e}"
        logger.error(msg)


# create the AuthenticatorTenants object and attach it back to the tapis client
tenants = AuthenticatorTenants()
t.tenant_cache = tenants
