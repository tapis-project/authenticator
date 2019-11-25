from flask import g, request
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest

from common import utils, errors

from service.models import db, Client, Token

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


class ClientsResource(Resource):
    """
    Work with OAuth client objects
    """

    # @swag_from("resources/ldaps/list.yml")
    def get(self):
        clients = Client.query.filter_by(tenant_id=g.tenant_id, username=g.username)
        return utils.ok(result=[cl.serialize for cl in clients], msg="Clients retrieved successfully.")

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        data = Client.get_derived_values(validated_body)
        client = Client(**data)
        db.session.add(client)
        db.session.commit()
        return utils.ok(result=client.serialize, msg="Client created successfully.")


class ClientResource(Resource):
    """
    Work with a single OAuth client objects
    """

    def get(self, client_id):
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        return utils.ok(result=client.serialize, msg='Client object retrieved successfully.')

    def delete(self, client_id):
        client = Client.query.filter_by(tenant_id=g.tenant_id, client_id=client_id).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {client_id}.')
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        db.session.delete(client)
        db.session.commit()


class TokensResource(Resource):
    """
    Work with OAuth client objects
    """

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_body = result.body
        data = Token.get_derived_values(validated_body)
        # token = Token(**data)

        # check that client is in db
        logger.debug("Checking that client exists.")
        client = Client.query.filter_by(client_id=data['client_id']).first()
        if not client:
            raise errors.ResourceError(msg=f'No client found with id {data["client_id"]}.')
        if not client.username == data['username']:
            raise errors.PermissionsError("Not authorized for this client.")

        # get ldap for the tenant

        # validate user/pass against ldap

        # call /v3/tokens to generate access token for the user

        token = Token()

        return utils.ok(result=token.serialize, msg="Token created successfully.")

