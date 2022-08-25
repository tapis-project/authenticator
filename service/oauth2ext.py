"""
Module to support OAuth2 extension identity providers. Here, a 3rd party OAuth2 provider server, such as
github, is being used as the IdP for the tenant. This module provides all required functionality for interacting
with the 3rd party OAuth server.

To implement a new OAuth2 provider, the following updates must be made:
1) Update the OAuth2ProviderExtension.__init__() to set the client id, key, identity redirect and token URL parameters.
2) Check the get_token_using_auth_code() to ensure the request parameters are the same as what the OAuth provider
is expecting and that the response type (e.g., json) is handled correctly.
3) Implement the get_user_from_token() method to determine the user's identity once an access token has been obtained.

Other changes:
1) Within models.py, update the get_custom_oa2_extension_type method to recognize the new extension type.


"""
import json
import jwt
from flask import session
import requests

from tapisservice import errors
from tapisservice.logs import get_logger
logger = get_logger(__name__)

from service import t
from service.models import tenant_configs_cache


class OAuth2ProviderExtension(object):
    """
    This class contains attributes and methods for working with a 3rd party OAuth2 provider.
    For each provider that is supported, some custom code is needed. See the module-level docstring.
    """
    def __init__(self, tenant_id, is_local_development=False):
        # the tenant id for this OAuth2 provider
        self.tenant_id = tenant_id
        # the custom tenant config for this tenant
        self.tenant_config = tenant_configs_cache.get_config(tenant_id=tenant_id)
        # the type of OAuth2 provider, such as github
        self.ext_type = tenant_configs_cache.get_custom_oa2_extension_type(tenant_id)
        # the actual custom_idp_configuration object, as a python dictionary
        self.custom_idp_config_dict = json.loads(self.tenant_config.custom_idp_configuration)
        # whether or not this authenticator is running in local development mode (i.e., on localhost)
        self.is_local_development = is_local_development
        # validate that this tenant should be using the OAuth2 extension module.
        if not self.ext_type:
            raise errors.ResourceError(f"Tenant {tenant_id} not configured for a custom OAuth2 extension.")
        tenant_base_url = t.tenant_cache.get_tenant_config(tenant_id).base_url
        if self.is_local_development:
            self.callback_url = f'http://localhost:5000/v3/oauth2/extensions/oa2/callback'
        else:
            self.callback_url = f'{tenant_base_url}/v3/oauth2/extensions/oa2/callback'
        # These attributes get computed later, as a result of the OAuth flow ----------
        self.authorization_code = None
        self.access_token = None
        self.username = None

        # Custom configs for each provider ---------------
        if self.ext_type == 'github':
            # github calls the client_key the "client_secret"
            self.client_id = self.custom_idp_config_dict.get('github').get('client_id')
            self.client_key = self.custom_idp_config_dict.get('github').get('client_secret')
            # initial redirect URL; used to start the oauth flow and log in the user
            self.identity_redirect_url = 'https://github.com/login/oauth/authorize'
            # URL to use to exchange the code for an qccess token
            self.oauth2_token_url = 'https://github.com/login/oauth/access_token'
        elif self.ext_type == 'cii':
            # we configure the CII redirect URL directly in the config because there are different CII environments.
            self.identity_redirect_url = self.custom_idp_config_dict.get('cii').get('login_url')
            if not self.identity_redirect_url:
                raise errors.ServiceConfigError(f"Missing required cii config, identity_redirect_url. "
                                                f"Config: {self.custom_idp_config_dict}")
            self.jwt_decode_key = self.custom_idp_config_dict.get('cii').get('jwt_decode_key')
            if not self.jwt_decode_key:
                raise errors.ServiceConfigError(f"Missing required cii config, jwt_decode_key. "
                                                f"Config: {self.custom_idp_config_dict}")
            self.check_jwt_signature = self.custom_idp_config_dict.get('check_jwt_signature')
            # note that CII does not implement standard OAuth2; they do not require a client id and key and they do not
            # create an authorization code to be exchanged for a token.
            self.client_id = 'not_used'
            self.client_key = 'not_used'
        elif self.ext_type == 'tacc_keycloak':
            # keycloak utilizes a client id and secret like github
            self.client_id = self.custom_idp_config_dict.get('tacc_keycloak').get('client_id')
            self.client_key = self.custom_idp_config_dict.get('tacc_keycloak').get('client_secret')
            # initial redirect URL; used to start the oauth flow and log in the user
            self.identity_redirect_url = 'https://identity.tacc.cloud/auth/realms/tapis/protocol/openid-connect/auth'
            # URL to use to exchange the code for an qccess token
            self.oauth2_token_url = 'https://identity.tacc.cloud/auth/realms/tapis/protocol/openid-connect/token'
        
        # NOTE: each provider type must implement this check
        # elif self.ext_type == 'google'
        #     ...
        else:
            logger.error(f"ERROR! OAuth2ProviderExtension constructor not implemented for OAuth2 provider "
                         f"extension {self.ext_type}.")
            raise errors.ServiceConfigError(f"Error processing callback URL: extension type {self.ext_type} not "
                                            f"supported.")

    def get_auth_code_from_callback(self, request):
        """
        This function processes the callback from the OAuth2 provider server; in particular, it gets the
        authorization code out of the request and checks the state parameter as well, if applicable.
        :param request: the request object made by the 3rd party OAuth2 provider server.
        :return:
        """
        # first, check for the state parameter and, if passed, compare it to the state in the session
        logger.debug(f"top of get_auth_code_from_callback; request.args: {request.args}; request: {request}")
        req_state = request.args.get('state')
        if req_state:
            state = session.get('state')
            if not state == req_state:
                logger.error(f"ERROR! state stored in the session ({state}) did not match the state passed in"
                             f"the callback ({req_state}")
                raise errors.ServiceConfigError("Error processing provider callback -- state mismatch.")
        req_code = request.args.get('code')
        if not req_code:
            logger.error(f"ERROR! did not receive an authorization code in the callback.")
            raise errors.ServiceConfigError("Error processing provider callback -- code missing.")
        self.authorization_code = req_code

    def get_token_using_auth_code(self):
        """
        Exchange the authorization code for an access token from the provider server.
        :return:
        """
        logger.debug("top of get_token_using_auth_code")
        # todo -- it is possible these body parameters will need to change for different oauth2 servers
        # note -- this function is not called by CII because it does non-standard OAuth.
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_key,
            "code": self.authorization_code,
            "redirect_uri": self.callback_url
        }
        # keycloak requires the "grant_type" parameter
        if self.ext_type == 'tacc_keycloak':
            body["grant_type"] = "authorization_code"
        logger.debug(f"making POST to token url {self.oauth2_token_url}...; body: {body}")
        try:
            rsp = requests.post(self.oauth2_token_url, data=body, headers={'Accept': 'application/json'})
        except Exception as e:
            logger.error(f"Got exception from POST request to OAuth server attempting to exchange the"
                         f"authorization code for a token. Debug data:"
                         f"request body: {body}"
                         f"exception: {e}")
            raise errors.ServiceConfigError("Error requesting access token. Contact server administrator.")
        logger.debug(f"successfully made POST to token url {self.oauth2_token_url}; rsp: {rsp};"
                     f"rsp.content: {rsp.content}")
        # todo -- it is possible different provider servers will not pass JSON
        try:
            self.access_token = rsp.json().get('access_token')
        except Exception as e:
            logger.error(f"Got exception trying to process response from POST request to exchange the"
                         f"authorization code for a token. Debug data:"
                         f"request body: {body};"
                         f"response: {rsp}"
                         f"exception: {e}")
            raise errors.ServiceConfigError("Error parsing access token. Contact server administrator.")
        logger.debug(f"successfully got access_token: {self.access_token}")
        return self.access_token

    def get_token_from_callback(self, request):
        """
        For the cii tenant, get the token directly from the callback URL. This function is only called by
        the CII tenant; other tenants do standard OAuth and pass an authorization code which is exchanged
        for the token.
        :param request: The request made to the Tapis callback URL.
        :return:
        """
        if not self.ext_type == 'cii':
            msg = f'get_token_from_callback() called for a non-cii ext type; ext type: {self.ext_type}; ' \
                  f'This function should only be called by cii tenants. ' \
                  f'request: {request}.'
            logger.error(msg)
            raise errors.ResourceError(f"Program error; contact system administrators. "
                                       f"(Debug message: {msg})")
        # the CII OAuth server returns the access token in a URL query parameter, "token"
        self.access_token = request.args.get('token')
        if not self.access_token:
            msg = f"Did not get access token from CII callback. request args: {request.args}"
            raise errors.ResourceError()
        return self.access_token

    def get_user_from_token(self):
        """
        Determines the username for the user once an access token has been obtained.
        :return:
        """
        logger.debug("top of get_user_from_token")
        # todo -- each OAuth2 provider will have a different mechanism for determining the user's identity
        if self.ext_type == 'github' or self.ext_type == 'tacc_keycloak':
            if self.ext_type == 'github':
                user_info_url = 'https://api.github.com/user'
            if self.ext_type == 'tacc_keycloak':
                user_info_url = 'https://identity.tacc.cloud/auth/realms/tapis/protocol/openid-connect/userinfo'
            if self.ext_type == 'github':
                headers = {'Authorization': f'token {self.access_token}',
                        'Accept': 'application/vnd.github.v3+json'}
            if self.ext_type == 'tacc_keycloak':
                headers = {'Authorization': f'Bearer {self.access_token}',}
            try:
                rsp = requests.get(user_info_url, headers=headers)
            except Exception as e:
                logger.error(f"Got exception from request to look up user's identity with {self.ext_type}. Debug data:"
                             f"exception: {e}")
                raise errors.ServiceConfigError("Error determining user identity. Contact server administrator.")
            if not rsp.status_code == 200:
                logger.error("Did not get 200 from request to look up user's identity with {self.ext_type}. Debug data:"
                             f"status code: {rsp.status_code};"
                             f"rsp content: {rsp.content}")
                raise errors.ServiceConfigError("Error determining user identity. Contact server administrator.")
            if self.ext_type == 'github':
                username = rsp.json().get('login')
                if not username:
                    logger.error(f"username was none after processing the github response. Debug data:"
                                f"response: {rsp}")
                    raise errors.ServiceConfigError("Error determining user identity: username was empty. "
                                                    "Contact server administrator.")
                
                    self.username = f'{username}@github.com'
            elif self.ext_type == 'tacc_keycloak':
                logger.info(f"Response content from keycloak: {rsp.content}")
                try:
                    username = rsp.json().get('email')
                except Exception as e:
                    logger.error(f"Got error trying to parse the username from the TACC Keycloak instance; error: {e}")
                    raise errors.ServiceConfigError("Error determining user identity: could not parse identity response. "
                                                    "Contact server administrator.")                    
                if not username:
                    logger.error(f"Could not parse the username from the TACC Keycloak instance; username was empty")
                    raise errors.ServiceConfigError("Error determining user identity: username was empty. "
                                                    "Contact server administrator.")
                self.username = username
            logger.debug(f"Successfully determined user's identity: {self.username}")
            return self.username

        elif self.ext_type == 'cii':
            # the CII token is a JWT; we only need to decode it and get the username out of the payload.
            # todo -- we should verify the signature if that is working...
            logger.debug(f"CII jwt: {self.access_token}")
            try:
                claims = jwt.decode(self.access_token, self.jwt_decode_key, verify_signature=self.check_jwt_signature, algorithms=["HS256"])
            except Exception as e:
                msg = f"got exception trying to decode the CII jwt; exception: {e}"
                logger.error(msg)
                raise errors.ResourceError(f"Unable to decode third-party JWT. Contact system administrator."
                                           f"(Debug message:{msg})")
            self.username = claims.get('username')
            if not self.username:
                msg = f"Did not get a username from the CII jwt; full claims: {claims}"
                logger.error(msg)
                raise errors.ResourceError(f"Unable to determine username from third-party JWT. Contact system "
                                           f"administrator."
                                           f"(Debug message:{msg})")
            logger.debug(f"Successfully determined user's identity: {self.username}")
            return self.username
        # elif self.ext_type == 'google':
        #     ...
        else:
            logger.error(f"ERROR! OAuth2ProviderExtension.get_user_from_token not implemented for OAuth2 provider "
                         f"extension {self.ext_type}.")
            raise errors.ServiceConfigError(f"Error determining user identity: extension type {self.ext_type} not "
                                            f"supported.")
