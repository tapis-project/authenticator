import pytest
import json
from unittest import TestCase
from service.api import app
from common import auth

# These tests are intended to be run locally.

@pytest.fixture
def client():
    app.debug = True
    return app.test_client()


def test_invalid_post(client):
    with client:
        response = client.post("http://localhost:5000/v3/oauth/clients")
        assert response.status_code == 400