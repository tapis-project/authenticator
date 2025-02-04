from base64 import b64encode
import datetime
import pytest
import json
import pyotp
import os

from tapisservice.auth import validate_token
from tapisservice.config import conf as tapisconf
from service.models import tenant_configs_cache, DeviceCode
from service.api import app
from service import models, mfa


# These tests are intended to be run locally.

# client id and key for the test suite. a client with these credentials is added by the test suite at start up.
TEST_TENANT_ID = 'dev'
TEST_CLIENT_ID = 'tapis_authn_test_suite_client_id'
TEST_CLIENT_KEY = 'Dkrio2odj2AbvR'
TEST_CLIENT_REDIRECT_URI = 'http://localhost:5000/testsuite'
TEST_USERNAME = 'testuser1'
TEST_PASSWORD = 'testuser1'
MFA_USERNAME = 'cicsvc'
MFA_GEN_CODE = os.environ.get('MFA_GEN_CODE')

@pytest.fixture
def client():
    app.debug = True
    return app.test_client()

@pytest.fixture(scope='module')
def init_db():
    with app.app_context():
        # add a test client to be used in all the tests
        data = {'tenant_id': TEST_TENANT_ID,
                "username": "tapis-authn-testsuite",
                'client_id': TEST_CLIENT_ID,
                'client_key': TEST_CLIENT_KEY,
                "display_name": "Tapis Authenticator Testsuite",
                "callback_url": TEST_CLIENT_REDIRECT_URI,
                'create_time': datetime.datetime.utcnow(),
                'last_update_time': datetime.datetime.utcnow(),
                'active': True
                }
        models.delete_tenant_from_db(TEST_TENANT_ID)
        print(f'got tapisconf:: {tapisconf}')
        config = {
            "tenant_id":TEST_TENANT_ID,
            "allowable_grant_types":json.dumps(["password", "implicit", "authorization_code", "refresh_token", "device_code"]),
            "use_ldap":True,
            "use_token_webapp":True,
            "mfa_config":json.dumps({
                "tacc": {
                    "privacy_idea_url": "https://pidea01.tacc.utexas.edu",
                    "privacy_idea_client_id": "p_client",
                    "privacy_idea_client_key": "p_key",
                    "grant_types": [
                        "authorization_code",
                        "implicit"
                    ]
                }
            }),
            # 4 hours
            "default_access_token_ttl":14400,
            # 1 year
            "default_refresh_token_ttl":31536000,
            "max_access_token_ttl":31536000,
            # 2 years
            "max_refresh_token_ttl":63072000,
            "custom_idp_configuration":json.dumps({}),
            "token_url": 'http://localhost:5000/v3/oauth2/tokens',
            "impers_oauth_client_id": "",
            "impers_oauth_client_secret": "",
            "impersadmin_username": "",
            "impersadmin_password": ""
        }
        models.add_tenant_to_db(config)
        models.add_client_to_db(data)
        client = models.Client.query.filter_by(
            tenant_id=data['tenant_id'],
            client_id=data['client_id'],
            client_key=data['client_key']
        ).first()
        tenant = models.TenantConfig.query.filter_by(
            tenant_id=config['tenant_id']
        ).first()

        # if it is somehow not there, we are in real trouble; just bail out.
        if not tenant:
            assert False
        if not client:
            assert False

def teardown_module():
    # clean up all the mess we made
    with app.app_context():
        models.AuthorizationCode.query.filter_by(tenant_id=TEST_TENANT_ID,
                                                 client_id=TEST_CLIENT_ID,
                                                 client_key=TEST_CLIENT_KEY).delete()
        models.db.session.commit()


def get_basic_auth_header(username, password):
    """
    Convenience function with will return a properly formatted Authorization header from a username and password.
    """
    user_pass = bytes(f"{username}:{password}", 'utf-8')
    return 'Basic {}'.format(b64encode(user_pass).decode())

def validate_access_token(response):
    """
    Validate the a response has an access token and it is properly formatted.
    """
    assert 'access_token' in response.json['result']['access_token']
    assert 'id_token' in response.json['result']['access_token']
    assert 'expires_at' in response.json['result']['access_token']
    assert 'expires_in' in response.json['result']['access_token']
    assert 'jti' in response.json['result']['access_token']
    claims = validate_token(response.json['result']['access_token']['access_token'])
    assert claims['tapis/tenant_id'] == TEST_TENANT_ID
    assert claims['tapis/username'] == TEST_USERNAME
    assert claims['sub'] == f'{TEST_USERNAME}@{TEST_TENANT_ID}'
    return claims
    
def check_access_token_table(claims, grant_type, token_revoked, client_id=None):
    """
    Check that a token with `claims` generated using `grant_type` with `token_revoked` status 
    appears on the AccessTokens table.
    
    Additionally, if a `client_id` was used to generate the token, this checks that the client_id
    appears correctly.
    """
    jti = claims['jti']
    token = models.AccessTokens.query.filter_by(jti=jti).first()
    # the token should be on the table
    if not token:
        raise Exception()
    # check that the attributes on the table match the token's claims:
    assert token.subject == claims['sub']
    assert token.tenant_id == claims['tapis/tenant_id']
    assert token.username == claims['tapis/username']
    assert token.token_revoked == token_revoked
    assert token.grant_type == grant_type
    if client_id:
        assert token.client_id == client_id
    
def check_refresh_token_table(claims, grant_type, token_revoked, client_id=None):
    """
    Check that a token with `claims` generated using `grant_type` with `token_revoked` status 
    appears on the RefreshTokens table.
    
    Additionally, if a `client_id` was used to generate the token, this checks that the client_id
    appears correctly.
    """
    jti = claims['jti']
    token = models.RefreshTokens.query.filter_by(jti=jti).first()
    # the token should be on the table
    if not token:
        raise Exception()
    # check that the attributes on the table match the token's claims:
    assert token.subject == claims['sub']
    assert token.tenant_id == claims['tapis/tenant_id']
    assert token.username == claims['tapis/access_token']['tapis/username']
    assert token.token_revoked == token_revoked
    assert token.grant_type == grant_type
    if client_id:
        assert token.client_id == client_id

def check_clients_table(client_id, callback_url=None, display_name=None, description=None, negative=False):
    """
    Check that a client created with the 'create client' endpoint exists with correct info
    If negative=true, check that this client doesn't exist instead
    """
    print(f'checking clients table')
    retrieved = models.Client.query.filter_by(client_id=client_id).first()
    print(f'DEBUG got client:: {retrieved}')
    try:
        if not client:
            raise AssertionError()
        # validate info for client
        if callback_url:
            assert retrieved.callback_url == callback_url
        if display_name:
            assert retrieved.display_name == display_name
        if description:
            assert retrieved.description == description
    except AssertionError as e:
        if not negative:
            raise AssertionError
        pass

def check_device_code_table(client_id, user_code, device_code, verification_url, status, negative=False):
    """
    Check that a device code created with the device code endpoint exists with correct info
    """
    print('Checking device_codes table')
    retrieved = models.DeviceCode.query.filter_by(user_code=user_code).first()
    print(f'DEBUG: got device code object:: {retrieved}')
    if negative:
        assert retrieved is None
        return
    assert retrieved.code == device_code
    assert retrieved.user_code == user_code
    assert retrieved.tenant_id == TEST_TENANT_ID
    assert retrieved.client_id == client_id
    assert retrieved.client_key == TEST_CLIENT_KEY
    assert retrieved.status == status
    assert retrieved.verification_uri == verification_url


def validate_refresh_token(response):
    """
    Validate that a response has a refresh token and it is properly formatted.
    """
    assert 'refresh_token' in response.json['result']['refresh_token']
    assert 'expires_at' in response.json['result']['refresh_token']
    assert 'expires_in' in response.json['result']['refresh_token']
    assert 'jti' in response.json['result']['refresh_token']
    claims = validate_token(response.json['result']['refresh_token']['refresh_token'])
    assert claims['tapis/token_type'] == 'refresh'
    assert claims['tapis/tenant_id'] == TEST_TENANT_ID
    # the refresh token embeds the access token claims within:
    assert 'tapis/access_token' in claims
    print(claims['tapis/access_token'])
    assert claims['tapis/access_token']['sub'] == f'{TEST_USERNAME}@{TEST_TENANT_ID}'
    return claims


def get_jwt(client):
    # TODO: add assertions for failing to get a token -- this should fail the current test somehow
    # auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
    payload = {
        'grant_type': 'password',
        'username': TEST_USERNAME,
        'password': TEST_PASSWORD
    }
    response = client.post(
        "http://localhost:5000/v3/oauth2/tokens",
        # headers=auth_header,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status_code == 200
    assert 'access_token' in response.json['result']
    # access_token:
    access_token_str = response.json['result']['access_token']['access_token']
    return access_token_str


@pytest.fixture
def mfa_token(tokencode=None):
    """
    Generate a OTP mfa code using pyotp given a username and token code.
    If a token code is not provided, a random one will be used.
    """
    if tokencode is None:
        tokencode = MFA_GEN_CODE
    print(f'DEBUG:: generating MFA token with tokencode: {tokencode}')
    totp = pyotp.TOTP(tokencode)
    return totp.now()

# =====================
# Actual test functions
# =====================


## utility tests
# get jwt
def test_get_jwt(client):
    # note: This serves as a smoke test to verify the validity of the other results. 
    # If this is failing, it will likely cause other authenticated endpoint tests to fail, but they won't always give the correct reason
    # the assertions made in the get_jwt func are enough to verify success. No addtl checks needed here
    print(f'Starting test of getting JWT')
    result = get_jwt(client)
    print(f'got result = {result}')


# get mfa config
def test_get_mfa_config(client):
    print('top of get mfa config')
    try:
        tenant_config = tenant_configs_cache.get_config(TEST_TENANT_ID)
        print(f'after tenant config get:: {tenant_config}')
        mfa_config = json.loads(tenant_config.mfa_config)
        if not mfa_config:
            print(f'No mfa config found in tenant_config. Creating... ')
            mfa_config = json.dumps({
                "tacc": {
                    "privacy_idea_url": "https://pidea01.tacc.utexas.edu",
                    "privacy_idea_client_id": "p_client",
                    "privacy_idea_client_key": "p_key",
                    "grant_types": [
                        "authorization_code",
                        "implicit"
                    ]
                }
            })
            tenant_config.mfa_config = mfa_config
        print(f'Got mfa config:: {mfa_config}')
    except Exception as e:
        print(f'got {e} while trying to get mfa config for tenant {TEST_TENANT_ID}')
        raise Exception()

def test_get_mfa_code(client, mfa_token):
    print(f'got mfa tken:: {mfa_token}')
    assert mfa_token is not None

## Health Check
# hello
def test_authenticator_hello(client):
    # result = client.authenticator.hello()
    result = client.get('http://localhost:5000/v3/oauth2/hello')
    assert result.status_code == 200
# ready
def test_authenticator_ready(client):
    # result = client.authenticator.ready()
    result = client.get('http://localhost:5000/v3/oauth2/ready')
    assert result.status_code == 200


## Metadata
# get_server_metadata
def test_get_metadata(client):
    result = client.get("http://localhost:5000/v3/oauth2/.well-known/oauth-authorization-server")
    assert result.status_code == 200


## Admin
# get_config
# TODO
# update_config
# TODO
     
## Clients


def test_invalid_post(client):
    with client:
        response = client.post("http://localhost:5000/v3/oauth2/clients")
        assert response.status_code == 400


# list_clients
def test_authenticator_list_clients(client, capsys):
    # result = client.authenticator.list_clients()
    with client:
        header = {'X-Tapis-Token': get_jwt(client)}
        result = client.get('http://localhost:5000/v3/oauth2/clients', headers=header)
        assert result.status_code == 200


# create_client
def test_authenticator_create_clients(client, capsys): ## TODO: this works, but doing it twice violates uniqueness constraint. Need to find a way to reliably erase it without using another endpoint
    # result = client.authenticator.create_client(client_id=TEST_CLIENT_ID, callback_url='https://foo.example.com/oauth2/callback')
    header = {'X-Tapis-Token': get_jwt(client)}
    payload = {
        "client_id": TEST_CLIENT_ID,
        "client_key": TEST_CLIENT_KEY,
        "callback_url": TEST_CLIENT_REDIRECT_URI,
        "display_name": "A Test Client",
        "description": "This is a client just for testing"
    }
    result = client.post(
        'http://localhost:5000/v3/oauth2/clients', 
        headers=header,
        data=json.dumps(payload),
        content_type='application/json'
    )
    
    assert result.status_code == 200
    # check the clients table to make sure it was created in the DB
    check_clients_table(TEST_CLIENT_ID, TEST_CLIENT_REDIRECT_URI, 'A Test Client', "This is a client just for testing")
    
# Get client details
# TODO

# Update client details
# TODO

# Permanantly set a client to inactive
def test_authenticator_delete_clients(client):
    header = {'X-Tapis-Token': get_jwt(client)}
    result = client.delete(f'http://localhost:5000/v3/oauth2/clients/{TEST_CLIENT_ID}', headers=header)
    print(f'DEBUG: got result of delete call: {result.json}')
    assert result.status_code == 200
    check_clients_table(TEST_CLIENT_ID, negative=True)

## Tokens
# Generate a Tapis JWT
def test_password_grant_invalid_client(client, init_db):
    with client:
        # pass a client that does not exist
        auth_header = {'Authorization': get_basic_auth_header('bad_client_id', 'bad_client_key')}
        payload = {
            'grant_type': 'password'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "Invalid client credentials" in response.json['message']

def test_password_grant_invalid_grant(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'passw0rd'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "Invalid grant_type" in response.json['message']

def test_password_grant_missing_username(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'password': 'abcd'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "username and password are required" in response.json['message']

def test_password_grant_missing_password(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': 'abcd'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "username and password are required" in response.json['message']

def test_password_grant_invalid_user_pass(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': TEST_USERNAME,
            'password': 'the_wrong_password'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "Invalid username/password combination." in response.json['message']


def test_password_grant_invalid_uppercase_user(client, init_db):
    # ldap clients are case insensitive, but the ldap.py bind code checks for upper case letters in the 
    # username and rejects it if any appear. 
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': TEST_USERNAME.upper(),
            'password': TEST_PASSWORD,
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert "Invalid username/password combination." in response.json['message']


def test_password_grant_valid(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': TEST_USERNAME,
            'password': TEST_PASSWORD
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        assert 'access_token' in response.json['result']
        # validate access_token:
        claims = validate_access_token(response)
        assert claims['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/grant_type'] == 'password'
        check_access_token_table(claims, "password", False, TEST_CLIENT_ID)

        # validate refresh_token:
        claims = validate_refresh_token(response)
        assert claims['tapis/access_token']['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/access_token']['tapis/grant_type'] == 'password'
        check_refresh_token_table(claims, "password", False, TEST_CLIENT_ID)

def test_password_grant_clientkey_in_post_data(client, init_db):
    payload = {
        'grant_type': 'password',
        'client_id': TEST_CLIENT_ID,
        'client_key': TEST_CLIENT_KEY,
        'username': TEST_USERNAME,
        'password': TEST_PASSWORD
    }
    response = client.post(
        "http://localhost:5000/v3/oauth2/tokens",
        data=json.dumps(payload),
        content_type='application/json'
    )
    print(f'DEBUG: got response: {response.json}')
    assert response.status_code == 200

def test_password_grant_no_client(client, init_db):
    payload = {
        'grant_type': 'password',
        'username': TEST_USERNAME,
        'password': TEST_PASSWORD
    }
    response = client.post(
        "http://localhost:5000/v3/oauth2/tokens",
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status_code == 200
    assert 'access_token' in response.json['result']
    # validate access_token:
    claims = validate_access_token(response)
    assert claims['tapis/client_id'] is None
    assert claims['tapis/grant_type'] == 'password'
    # when not using an oauth client, refresh tokens are not returned:
    assert 'refresh_token' not in response.json['result']

# Create a v2 bearer token from a Tapis v3 JWT
# TODO

# Revoke a token 
def test_revoke_token(client, init_db):
    """
    Test the revocation endpoint, and check the status of the tokens are updated on the table
    after revoking. 
    """
    # first, generate an access and refresh token pair
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': TEST_USERNAME,
            'password': TEST_PASSWORD
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        assert 'access_token' in response.json['result']
        # access_token:
        access_token_str = response.json['result']['access_token']['access_token']
        access_token_claims = validate_access_token(response)
        # refresh_token:
        refresh_token_claims = validate_refresh_token(response)
        refresh_token_str = response.json['result']['refresh_token']['refresh_token']
        
        # now, revoke the tokens ----
        # first, the access token
        payload = {'token': access_token_str}
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens/revoke",
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200 
        check_access_token_table(access_token_claims, "password", True, TEST_CLIENT_ID)

        # then the refresh token
        payload = {'token': refresh_token_str}
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens/revoke",
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200       

        check_refresh_token_table(refresh_token_claims, "password", True, TEST_CLIENT_ID)

# Note: Device code checks are below

## Profiles
# get_userinfo
# TODO
# list_profiles
# TODO
# get_profile
# TODO

## grant type tests

def test_authorization_code(client, init_db):
    # simulate the authorization approval -
    with client:
        # use hte session_transaction to enable modification of the session object:
        # cf., https://flask.palletsprojects.com/en/1.1.x/testing/#accessing-and-modifying-sessions
        with client.session_transaction() as sess:
            sess['username'] = TEST_USERNAME
        # once we leave the context, session updates applied via sess object are available -
        print("post to authorize in test")
        response = client.post('http://localhost:5000/v3/oauth2/authorize',
                               data={'tenant_id': TEST_TENANT_ID,
                                     'approve': True,
                                     'client_id': TEST_CLIENT_ID,
                                     'client_redirect_uri': TEST_CLIENT_REDIRECT_URI,
                                     'client_response_type': 'code'
                                     })
        print(response)
        assert response.status_code == 302
        # note: response.data is a raw bytes object containing the full HTML returned from the page.
        # try this if you want to debug ===>  print(response.data)
        response_str = response.data.decode('utf-8')
        assert 'code=' in response_str
        assert 'state=' in response_str
        # look up the authorization_code in the db:
        auth_code = models.AuthorizationCode.query.filter_by(tenant_id=TEST_TENANT_ID,
                                                             client_id=TEST_CLIENT_ID,
                                                             client_key=TEST_CLIENT_KEY,
                                                             username=TEST_USERNAME).first()
        assert auth_code.tenant_id == TEST_TENANT_ID
        assert auth_code.username == TEST_USERNAME
        assert auth_code.client_id == TEST_CLIENT_ID
        assert auth_code.client_key == TEST_CLIENT_KEY
        assert f'code={auth_code.code}' in response_str


def test_authorization_code_grant(client, init_db):
    with client:
        # look up the authorization_code from the previous test:
        auth_code = models.AuthorizationCode.query.filter_by(tenant_id=TEST_TENANT_ID,
                                                             client_id=TEST_CLIENT_ID,
                                                             client_key=TEST_CLIENT_KEY,
                                                             username=TEST_USERNAME).first()
        headers = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        data = {
            'grant_type': 'authorization_code',
            'code': auth_code.code,
            'redirect_uri': TEST_CLIENT_REDIRECT_URI
        }
        rs = client.post("http://localhost:5000/v3/oauth2/tokens",
                         headers=headers,
                         data=json.dumps(data),
                         content_type='application/json')
        print(f'Got result:: {rs.json}')
        assert rs.status_code == 200
        assert 'access_token' in rs.json['result']
        # validate access_token:
        claims = validate_access_token(rs)
        assert claims['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/grant_type'] == 'authorization_code'
        assert claims['tapis/redirect_uri'] == TEST_CLIENT_REDIRECT_URI
        assert claims['tapis/refresh_count'] == 0
        # refresh tokens are returned on authorization_code grant:
        assert 'refresh_token' in rs.json['result']
        # refresh_token attributes:
        claims = validate_refresh_token(rs)
        assert claims['tapis/access_token']['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/access_token']['tapis/grant_type'] == 'authorization_code'
        assert claims['tapis/access_token']['tapis/redirect_uri'] == TEST_CLIENT_REDIRECT_URI
        # make sure authorization code was deleted from the database -
        auth_code = models.AuthorizationCode.query.filter_by(code=auth_code.code).first()
        assert not auth_code

def test_refresh_token(client, init_db):
    # first, use the password grant with a client to get an access and refresh token:
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': TEST_USERNAME,
            'password': TEST_PASSWORD
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        assert 'refresh_token' in response.json['result']
        refresh_token_str = response.json['result']['refresh_token']['refresh_token']
        # now, use that to get a new token --
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token_str
        }
        response =  client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        # check that both an access and refresh token were generated:
        claims = validate_access_token(response)
        assert claims['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/grant_type'] == 'refresh_token'
        assert claims['tapis/refresh_count'] == 1
        refresh_token_str = response.json['result']['refresh_token']['refresh_token']
        # and one more time --
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token_str
        }
        response =  client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        # check that both an access and refresh token were generated:
        claims = validate_access_token(response)
        assert claims['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/grant_type'] == 'refresh_token'
        assert claims['tapis/refresh_count'] == 2


def test_implicit_grant(client, init_db):
    # simulate the authorization approval -
    with client:
        # use the session_transaction to enable modification of the session object:
        # cf., https://flask.palletsprojects.com/en/1.1.x/testing/#accessing-and-modifying-sessions
        with client.session_transaction() as sess:
            sess['username'] = TEST_USERNAME
        # once we leave the context, session updates applied via sess object are available -
        response = client.post('http://localhost:5000/v3/oauth2/authorize',
                               data={'tenant_id': TEST_TENANT_ID,
                                     'approve': True,
                                     'client_id': TEST_CLIENT_ID,
                                     'client_redirect_uri': TEST_CLIENT_REDIRECT_URI,
                                     'client_response_type': 'token'
                                     })
        print(response.data)
        assert response.status_code == 302
        # note: response.data is a raw bytes object containing the full HTML returned from the page.
        # try this if you want to debug ===>  print(response.data)
        response_str = response.data.decode('utf-8')
        assert 'token=' in response_str
        assert 'state=' in response_str
        print(response_str)
        # pull the JWT out of the full response_str. to do this, we split the respnse string (which is the entire
        # html document) first by the "access_token=" substring and take the second part (index 1) to get the part
        # after, then we split again up to the first encoded ampersand (&) character and take the first part (index 0)
        # which gives us everything in the access_token query parameter.
        jwt = response_str.split('access_token=')[1].split('&amp')[0]
        # decode jwt and check claims
        claims = validate_token(jwt)
        assert claims['tapis/tenant_id'] == TEST_TENANT_ID
        assert claims['tapis/username'] == TEST_USERNAME
        assert claims['sub'] == f'{TEST_USERNAME}@{TEST_TENANT_ID}'
        # TODO -- validate that the token returned has the correct claims.. to do this, will need to parse the token
        # from out of the raw string.

## Device code checks
def test_get_device_code(client):
    # TODO: get a device code, then use it to get a token
    # verify that we get a access token using it
    # verify that the code can't be used a second time to get another token
    # verify that the device code is tied to the user in the db
    with client:
        # get device code url
        data={'client_id': TEST_CLIENT_ID}
        
        response = client.post('http://localhost:5000/v3/oauth2/device/code',
                                data=json.dumps(data),
                                content_type='application/json')
        # print(response.json)
        assert response.status_code == 200
        device_code = response.json["result"]["device_code"]
        user_code = response.json["result"]["user_code"]
        verification_url = response.json["result"]["verification_uri"]
        assert device_code is not None
        assert user_code is not None
        assert verification_url is not None

        # verify data is correct in table
        check_device_code_table(TEST_CLIENT_ID, user_code, device_code, verification_url, "Created")

def test_authorize_device_code(client):
    # TODO: not sure how to do this one yet, since it tyically requires manually going to the verification url and signing in.
    # the test_exchange_device_code func directly inserts the "Entered" status in the device_codes table to simulate this.
    # Skipping this one for now
    pass

def test_exchange_device_code(client):
    # directly create the device code in the DB
    device_code = None
    code=models.DeviceCode.generate_code()
    user_code=models.DeviceCode.generate_user_code()
    verification_url=models.DeviceCode.generate_verification_uri(TEST_TENANT_ID, TEST_CLIENT_ID, BASE_URL='https://localhost:5000'),
    try:
        device_code = models.DeviceCode(tenant_id=TEST_TENANT_ID,
                                    username=TEST_USERNAME,
                                    client_id=TEST_CLIENT_ID,
                                    client_key=TEST_CLIENT_KEY,
                                    code=code,
                                    user_code=user_code,
                                    status="Entered",
                                    verification_uri=verification_url,
                                    expiry_time=models.DeviceCode.compute_expiry(),
                                    access_token_ttl=models.DeviceCode.set_ttl())
    except Exception as e:
        print(f'ERROR: exception while generating device code object:: {e}')
    assert device_code is not None
    print(f'DEBUG: have device code object: {device_code}')
    try:
        models.db.session.add(device_code)
        models.db.session.commit()
        print('DEBUG: committed device code object to DB')
    except Exception as e:
            print(f"Got exception trying to add and commit the device code. e: {e}; type(e): {type(e)}")
            raise Exception("Internal error saving device code. Please try again later.")
    # verify that it was added to the db correctly
    check_device_code_table(TEST_CLIENT_ID, user_code, code, verification_url, "Entered")

    # call the tokens url with the device code
    body = {
        "client_id": TEST_CLIENT_ID,
        "device_code": code,
        "grant_type": "device_code"
    }
    header = {
        "X-Tapis-Local-Tenant": "dev",
        "content-type": "application/json"
    }
    response = client.post(
        'http://localhost:5000/v3/oauth2/tokens',
        data=json.dumps(body),
        headers=header
    )
    
    print(f'DEBUG: got response requesting token w/ device code:: {response.json}')

    # verify token in response
    assert response.status_code == 200
    validate_access_token(response)

## MFA tests
# TODO
def test_mfa_valid_code(mfa_token):
    # uses the cicsvc creds to auth. 
    response = mfa.call_mfa(mfa_token, TEST_TENANT_ID, MFA_USERNAME)
    print(f'DEBUG:: mfa response: {response}')
    assert response is True

def test_mfa_invalid_code(mfa_token):
    response = mfa.call_mfa('123456', TEST_TENANT_ID, MFA_USERNAME)
    print(f'DEBUG:: mfa response: {response}')
    assert response is False

## OAuth2ProviderExtCallback tests
# TODO


