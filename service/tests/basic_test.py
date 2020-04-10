from base64 import b64encode
import datetime
import pytest
import json
from unittest import TestCase
from service.api import app
from service import models
from common import auth

# These tests are intended to be run locally.

# client id and key for the test suite. a client with these credentials is added by the test suite at start up.
TEST_CLIENT_ID = 'tapis_authn_test_suite_client_id'
TEST_CLIENT_KEY = 'Dkrio2odj2AbvR'
TEST_CLIENT_REDIRECT_URI = 'http://localhost:5000/testsuite'

@pytest.fixture
def client():
    app.debug = True
    return app.test_client()

@pytest.fixture(scope='module')
def init_db():
    with app.app_context():
        data = {'tenant_id': 'dev',
                "username": "tapis-authn-testsuite",
                'client_id': TEST_CLIENT_ID,
                'client_key': TEST_CLIENT_KEY,
                "display_name": "Tapis Authenticator Testsuite",
                "callback_url": TEST_CLIENT_REDIRECT_URI,
                'create_time': datetime.datetime.utcnow(),
                'last_update_time': datetime.datetime.utcnow()
                }
        models.add_client_to_db(data)
        client = models.Client.query.filter_by(
            tenant_id=data['tenant_id'],
            client_id=data['client_id'],
            client_key=data['client_key']
        ).first()
        if not client:
            assert False

def get_basic_auth_header(username, password):
    """
    Convenience function with will return a properly formatted Authorization header from a username and password.
    """
    user_pass = bytes(f"{username}:{password}", 'utf-8')
    return 'Basic {}'.format(b64encode(user_pass).decode())


def test_invalid_post(client):
    with client:
        response = client.post("http://localhost:5000/v3/oauth2/clients")
        assert response.status_code == 400


# grant type tests
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
            'username': 'testuser1',
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

def test_password_grant_valid(client, init_db):
    with client:
        auth_header = {'Authorization': get_basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_KEY)}
        payload = {
            'grant_type': 'password',
            'username': 'testuser1',
            'password': 'testuser1'
        }
        response = client.post(
            "http://localhost:5000/v3/oauth2/tokens",
            headers=auth_header,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        assert 'access_token' in response.json['result']
        # access_token attributes:
        assert 'access_token' in response.json['result']['access_token']
        assert 'expires_at' in response.json['result']['access_token']
        assert 'expires_in' in response.json['result']['access_token']
        assert 'jti' in response.json['result']['access_token']

        assert 'refresh_token' in response.json['result']
        # refresh_token attributes:
        assert 'refresh_token' in response.json['result']['refresh_token']
        assert 'expires_at' in response.json['result']['access_token']
        assert 'expires_in' in response.json['result']['access_token']
        assert 'jti' in response.json['result']['access_token']

def test_password_grant_no_client(client, init_db):
    payload = {
        'grant_type': 'password',
        'username': 'testuser1',
        'password': 'testuser1'
    }
    response = client.post(
        "http://localhost:5000/v3/oauth2/tokens",
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status_code == 200
    assert 'access_token' in response.json['result']
    # access_token attributes:
    assert 'access_token' in response.json['result']['access_token']
    assert 'expires_at' in response.json['result']['access_token']
    assert 'expires_in' in response.json['result']['access_token']
    assert 'jti' in response.json['result']['access_token']
    # when not using an oauth client, refresh tokens are not returned:
    assert 'refresh_token' not in response.json['result']

def test_authorization_code(client, init_db):
    # simulate the authorization approval -
    response = client.post('http://localhost:5000/v3/oauth2/authorize',
                           data={'tenant_id': 'dev',
                                 'approve': True,
                                 'client_id': TEST_CLIENT_ID,
                                 'client_redirect_uri': TEST_CLIENT_REDIRECT_URI,
                                 })
    assert response.status_code == 302
    # print(response.data)
    # note: response.data is a raw bytes object containing the full HTML returned from the page.
    response_str = response.data.decode('utf-8')
    assert 'code=' in response_str
    assert 'state=' in response_str
