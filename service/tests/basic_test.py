from base64 import b64encode
import datetime
import pytest
import json

from common.auth import validate_token
from service.api import app
from service import models



# These tests are intended to be run locally.

# client id and key for the test suite. a client with these credentials is added by the test suite at start up.
TEST_TENANT_ID = 'dev'
TEST_CLIENT_ID = 'tapis_authn_test_suite_client_id'
TEST_CLIENT_KEY = 'Dkrio2odj2AbvR'
TEST_CLIENT_REDIRECT_URI = 'http://localhost:5000/testsuite'
TEST_USERNAME = 'testuser1'
TEST_PASSWORD = 'testuser1'

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
                'last_update_time': datetime.datetime.utcnow()
                }
        models.add_client_to_db(data)
        client = models.Client.query.filter_by(
            tenant_id=data['tenant_id'],
            client_id=data['client_id'],
            client_key=data['client_key']
        ).first()
        # if it is somehow not there, we are in real trouble; just bail out.
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
    assert 'expires_at' in response.json['result']['access_token']
    assert 'expires_in' in response.json['result']['access_token']
    assert 'jti' in response.json['result']['access_token']
    claims = validate_token(response.json['result']['access_token']['access_token'])
    assert claims['tapis/tenant_id'] == TEST_TENANT_ID
    assert claims['tapis/username'] == TEST_USERNAME
    assert claims['sub'] == f'{TEST_USERNAME}@{TEST_TENANT_ID}'
    return claims


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


# =====================
# Actual test functions
# =====================

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

        # validate refresh_token:
        claims = validate_refresh_token(response)
        assert claims['tapis/access_token']['tapis/client_id'] == TEST_CLIENT_ID
        assert claims['tapis/access_token']['tapis/grant_type'] == 'password'

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
    assert claims['tapis/client_id'] == None
    assert claims['tapis/grant_type'] == 'password'
    # when not using an oauth client, refresh tokens are not returned:
    assert 'refresh_token' not in response.json['result']

def test_authorization_code(client, init_db):
    # simulate the authorization approval -
    with client:
        # use hte session_transaction to enable modification of the session object:
        # cf., https://flask.palletsprojects.com/en/1.1.x/testing/#accessing-and-modifying-sessions
        with client.session_transaction() as sess:
            sess['username'] = TEST_USERNAME
        # once we leave the context, session updates applied via sess object are available -
        response = client.post('http://localhost:5000/v3/oauth2/authorize',
                               data={'tenant_id': TEST_TENANT_ID,
                                     'approve': True,
                                     'client_id': TEST_CLIENT_ID,
                                     'client_redirect_uri': TEST_CLIENT_REDIRECT_URI,
                                     'client_response_type': 'code'
                                     })
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

