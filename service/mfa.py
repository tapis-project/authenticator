from tapisservice import errors
from tapisservice.config import conf
from tapisservice.tapisflask import utils
import json
import time
import requests
from service.models import TenantConfig, tenant_configs_cache

from tapisservice.logs import get_logger

logger = get_logger(__name__)

def needs_mfa(tenant_id, mfa_timestamp=None):
    if conf.turn_off_mfa:
        return False
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
        expired = check_mfa_expired(mfa_config, mfa_timestamp)
    except Exception as e:
        return False

    # mfa_config is a JSON object; if the tenant is not configured for MFA, then 
    # the mfa_config object will be an empty dict (i.e., {})
    if mfa_config and not expired:
        return True
    return False
    

def check_mfa_expired(mfa_config, mfa_timestamp=None):
    """
    Based on the tenant's MFA config and an optional MFA timestamp corresponding to the 
    last time an MFA was completed, determine whether the MFA session should be expired.
    """
    if mfa_timestamp is not None:
        if "tacc" in mfa_config:
            if 'expire' in mfa_config['tacc']:
                current_time = time.time()
                if current_time - mfa_timestamp > int(mfa_config['tacc']['expiry_frequency']):
                    return True
    return False


def call_mfa(token, tenant_id, username):
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
    except Exception as e:
        return e

    if not mfa_config:
        return ''

    if "tacc" in mfa_config:
        return privacy_idea_tacc(mfa_config, token, username)

def privacy_idea_tacc(config, token, username):
    if not config:
        return False
    
    if config:
        privacy_idea_url = config['tacc']['privacy_idea_url']
        privacy_idea_client_id = config['tacc']['privacy_idea_client_id']
        privacy_idea_client_key = config['tacc']['privacy_idea_client_key']
        grant_types = config['tacc'].get('grant_types', '')
        realm = config['tacc'].get('realm', 'tacc')

        jwt = get_privacy_idea_jwt(privacy_idea_url, privacy_idea_client_id, privacy_idea_client_key)

        if not jwt:
            return False
         
        return verify_mfa_token(privacy_idea_url, jwt, token, username, realm)

def get_privacy_idea_jwt(url, username, password):
    data = {
        "username": username,
        "password": password
    }
    url = f"{url}/auth"
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
    except Exception as e:
        return
    jwt = response.json()['result']['value']['token']
    return jwt

def verify_mfa_token(url, jwt, token, username, realm):
    url = f"{url}/validate/check"
    data = {
        "user": username,
        "realm": realm,
        "pass": token
    }
    headers = {
        "x-tapis-token": jwt
    }
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
    except Exception as e:
        return False
    valid = response.json()['result']['value']
    return valid
