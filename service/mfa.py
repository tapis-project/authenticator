import json

def needs_mfa():
    print("In needs mfa")
    tenant_config_json = {
        "tacc": {
            "privacy_idea_url": "p.auth.mfa/verify",
            "privacy_idea_client_id": "p_client",
            "privacy_idea_client_key": "p_key",
            "grant_types": [
                "authorization_code",
                "implicit"
            ]
        }
    }
    tenant_config_string = json.dumps(tenant_config_json)

    tenant_config = json.loads(tenant_config_string)
    return not not tenant_config
    
def call_mfa(token):
    print("In call mfa")
    tenant_config_json = {
        "tacc": {
            "privacy_idea_url": "p.auth.mfa/verify",
            "privacy_idea_client_id": "p_client",
            "privacy_idea_client_key": "p_key",
            "grant_types": [
                "authorization_code",
                "implicit"
            ]
        }
    }
    tenant_config_string = json.dumps(tenant_config_json)

    tenant_config = json.loads(tenant_config_string)
    if not tenant_config:
        return ''

    if "tacc" in tenant_config:
        return privacy_idea_tacc(tenant_config, token)

def privacy_idea_tacc(config, token):
    print("In privacy_idea_tacc function")
    tenant_config = config

    if not tenant_config:
        return False
    
    if tenant_config:
        # get config data
        privacy_idea_url = config['tacc']['privacy_idea_url']
        privacy_idea_client_id = config['tacc']['privacy_idea_client_id']
        privacy_idea_client_key = config['tacc']['privacy_idea_client_key']
        grant_types = config['tacc']['grant_types']
        return verify_mfa_token(privacy_idea_url, privacy_idea_client_id, privacy_idea_client_key, token)

def verify_mfa_token(url, client_id, client_key, token):
    print("Verifying MFA token")
    # call privacy idea API
    if token == '123':
        return True
    else:
        return False