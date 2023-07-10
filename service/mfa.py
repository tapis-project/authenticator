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
    logger.debug("checking if tenant needs mfa")
    tenant_config = tenant_configs_cache.get_config(tenant_id)
    logger.debug(tenant_config.mfa_config)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
    except Exception as e:
        logger.debug(f"Error parsing mfa config: {e}")
        return False

    return not not mfa_config
    expired = check_mfa_expired(mfa_config, mfa_timestamp)

    return expired
    

def check_mfa_expired(mfa_config, mfa_timestamp=None):
    """
    Based on the tenant's MFA config and an optional MFA timestamp corresponding to the 
    last time an MFA was completed, determine whether the MFA session should be expired.
    """
    logger.info("Checking MFA expired")
    if mfa_timestamp is not None:
        logger.info(f"mfa_timestamp: {mfa_timestamp}")
        if "tacc" in mfa_config:
            logger.info(f"check mfa expired config: {mfa_config}")
            if mfa_config['tacc']['expire']:
                current_time = time.time()
                if current_time - mfa_timestamp > int(mfa_config['tacc']['expiry_frequency']):
                    return True
    return False


def call_mfa(token, tenant_id, username):
    logger.debug(f"calling mfa for: {username}")
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
    except Exception as e:
        logger.debug(f"Error parsing mfa config: {e}")
        return e
    
    logger.debug(f"Tenant mfa config: {mfa_config}")

    if not mfa_config:
        return ''

    if "tacc" in mfa_config:
        return privacy_idea_tacc(mfa_config, token, username)

def privacy_idea_tacc(config, token, username):
    logger.debug("In privacy_idea_tacc function")

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
    logger.debug("Generating privacy idea JWT")
    data = {
        "username": username,
        "password": password
    }
    url = f"{url}/auth"
    logger.debug(url)
    try:
        response = requests.post(url, json=data)
        logger.debug(f"Response: {response}")
        response.raise_for_status()
    except Exception as e:
        logger.debug(f"error: {e}")
        return
    jwt = response.json()['result']['value']['token']
    logger.debug(jwt)
    return jwt

def verify_mfa_token(url, jwt, token, username, realm):
    logger.debug(f"Verifying MFA token: {token} for: {username}")
    url = f"{url}/validate/check"
    logger.debug(url)
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
        logger.debug(f"Response: {response}")
        response.raise_for_status()
    except Exception as e:
        logger.debug(f"error: {e}")
        return False
    valid = response.json()['result']['value']
    return valid
