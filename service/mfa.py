from common import utils, errors
import json
import requests
from service.models import TenantConfig, tenant_configs_cache

from common.logs import get_logger

logger = get_logger(__name__)

def needs_mfa(tenant_id):
    logger.debug("checking if tenant needs mfa")
    tenant_config = tenant_configs_cache.get_config(tenant_id)
    logger.debug(tenant_config.mfa_config)
    return False
    return not not tenant_config.mfa_config
    
def call_mfa(token, tenant_id, username):
    logger.debug(f"calling mfa for: {username}")
    tenant_config = tenant_configs_cache.get_config(tenant_id)
    mfa_config = json.loads(tenant_config.mfa_config)
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
        grant_types = config['tacc']['grant_types']

        jwt = get_privacy_idea_jwt(privacy_idea_url, privacy_idea_client_id, privacy_idea_client_key)
         
        return verify_mfa_token(privacy_idea_url, jwt, token, username)

def get_privacy_idea_jwt(url, username, password):
    logger.debug("Generating privacy idea JWT")
    data = {
        "username": username,
        "password": password
    }
    url = f"{url}/auth"
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

def verify_mfa_token(url, jwt, token, username):
    logger.debug(f"Verifying MFA token: {token} for: {username}")
    url = f"{url}/validate/check"
    data = {
        "user": username,
        "realm": "tacc",
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
