import json
import time

import requests
from tapisservice.config import conf
from tapisservice.logs import get_logger

from service.models import tenant_configs_cache

logger = get_logger(__name__)


def needs_mfa(tenant_id, mfa_timestamp=None):
    if conf.turn_off_mfa:
        return False
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
        expired = check_mfa_expired(mfa_config, mfa_timestamp)
    except Exception:
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
            if "expire" in mfa_config["tacc"]:
                current_time = time.time()
                if current_time - mfa_timestamp > int(
                    mfa_config["tacc"]["expiry_frequency"]
                ):
                    return True
    return False


def check_sms(tenant_id, username):
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
        if "tacc" in mfa_config:
            config = get_config_data(mfa_config)

            if config:
                jwt = get_privacy_idea_jwt(config)
                headers = {"Authorization": jwt}
                logger.debug(headers)
                data = {"serial": username}
                res = requests.get(
                    f"{config['privacy_idea_url']}/token?serial={username}",
                    headers=headers,
                    data=data,
                )
                result = res.json()["result"]
                logger.debug(
                    f"Serial request from Privacy Idea for {username}: {result}"
                )
                return res.json()["result"]["value"]["tokens"][0]["tokentype"] == "sms"
    except Exception as e:
        logger.debug(f"Error checking SMS for {username}: {e}")

    return False


def send_sms(tenant_id, username):
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
        if "tacc" in mfa_config:
            config = get_config_data(mfa_config)

            if config:
                jwt = get_privacy_idea_jwt(config)
                headers = {"Authorization": jwt}
                logger.debug(headers)
                data = {"serial": username}
                res = requests.post(
                    f"{config['privacy_idea_url']}/validate/triggerchallenge",
                    headers=headers,
                    data=data,
                )
                return res.status_code == 200
    except Exception as e:
        logger.debug(f"Error sending SMS to {username}: {e}")


def call_mfa(token, tenant_id, username):
    tenant_config = tenant_configs_cache.get_config(tenant_id)

    try:
        mfa_config = json.loads(tenant_config.mfa_config)
    except Exception as e:
        return e

    if not mfa_config:
        return ""

    if "tacc" in mfa_config:
        config = get_config_data(mfa_config)
        jwt = get_privacy_idea_jwt(config)
        return verify_mfa_token(
            config["privacy_idea_url"], jwt, token, username, config["realm"]
        )


def get_config_data(config):
    data = {}
    data["privacy_idea_url"] = config["tacc"].get("privacy_idea_url", None)
    data["privacy_idea_client_id"] = config["tacc"].get("privacy_idea_client_id", None)
    data["privacy_idea_client_key"] = config["tacc"].get(
        "privacy_idea_client_key", None
    )
    data["privacy_idea_jwt"] = config["tacc"].get("privacy_idea_jwt", None)
    data["grant_types"] = config["tacc"].get("grant_types", "")
    data["realm"] = config["tacc"].get("realm", "tacc")

    return data


def get_privacy_idea_jwt(config):
    jwt = config.get("privacy_idea_jwt", None)
    if jwt:
        return jwt
    data = {
        "username": config["privacy_idea_client_id"],
        "password": config["privacy_idea_client_key"],
    }
    if config["privacy_idea_url"] and data["username"] and data["password"]:
        try:
            url = f"{config['privacy_idea_url']}/auth"
            response = requests.post(url, json=data)
            response.raise_for_status()

            jwt = response.json()["result"]["value"]["token"]
        except Exception as e:
            logger.debug(f"Error generating jwt: {e}")

    return jwt


def verify_mfa_token(url, jwt, token, username, realm):
    url = f"{url}/validate/check"
    data = {"user": username, "realm": realm, "pass": token}
    headers = {"x-tapis-token": jwt}
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
    except Exception:
        return False
    valid = response.json()["result"]["value"]
    return valid
