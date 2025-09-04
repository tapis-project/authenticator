"""
This file contains the Resources responsible for managing OAuth client objects.

Resources:
- ClientResource: Handles operations on a single OAuth client,
including retrieval, updates, and deactivation.
- ClientsResource: Handles operations on multiple OAuth clients,
including listing and creation.
"""

import sqlalchemy
from flask import g, request
from flask_restful import Resource
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
from tapisservice import errors
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service.models import Client, db

logger = get_logger(__name__)


class ClientResource(Resource):
    """
    Work with a single OAuth client objects
    """

    def get(self, client_id):
        logger.debug("top of GET /clients/{client_id}")
        g.tenant_id = g.request_tenant_id
        g.username = g.request_username
        client = Client.query.filter_by(
            tenant_id=g.request_tenant_id, client_id=client_id
        ).first()
        if not client:
            raise errors.ResourceError(msg=f"No client found with id {client_id}.")
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        return utils.ok(
            result=client.serialize, msg="Client object retrieved successfully."
        )

    def put(self, client_id):
        logger.debug("top of PUT /clients/{client_id}")
        if "client_id" in request.json:
            raise errors.ResourceError("Changing client_id not currently supported.")
        if "client_key" in request.json:
            raise errors.ResourceError("Changing client_key not currently supported.")
        if "description" in request.json:
            raise errors.ResourceError("Changing description not currently supported.")
        logger.debug(
            "got past checks for unsupported fields. using "
            f"tenant_id: {g.request_tenant_id}; client_id: {client_id}"
        )
        g.tenant_id = g.request_tenant_id
        g.username = g.request_username
        clients = Client.query.filter_by(
            tenant_id=g.request_tenant_id, client_id=client_id
        )
        client = clients.first()
        logger.debug(f"clients: {clients}; client: {client}")
        if not client:
            raise errors.ResourceError(msg=f"No client found with id {client_id}.")
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        result = openapi_request_validator.validate(
            utils.spec, FlaskOpenAPIRequest(request)
        )
        if result.errors:
            print(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f"Invalid PUT data: {result.errors}")
        validated_body = result.body
        new_callback_url = getattr(validated_body, "callback_url", client.callback_url)
        new_display_name = getattr(validated_body, "display_name", client.display_name)
        client.callback_url = new_callback_url
        client.display_name = new_display_name
        db.session.commit()
        logger.debug(f"client updated; client: {client}")
        return utils.ok(result=client.serialize, msg="Client updated successfully")

    def delete(self, client_id):
        logger.debug("top of DELETE /clients/{client_id}")
        client = Client.query.filter_by(
            tenant_id=g.request_tenant_id, client_id=client_id
        ).first()
        if not client:
            raise errors.ResourceError(msg=f"No client found with id {client_id}.")
        if not client.username == g.username:
            raise errors.PermissionsError("Not authorized for this client.")
        client.active = False
        db.session.commit()
        return utils.ok(
            result=client.serialize,
            msg="Client status updated to inactive successfully",
        )


class ClientsResource(Resource):
    """
    Work with OAuth client objects
    """

    def get(self):
        logger.debug("top of GET /clients")
        show_inactive = request.args.get("show_inactive", False)
        if show_inactive:
            clients = Client.query.filter_by(
                tenant_id=g.request_tenant_id, username=g.request_username
            )
        else:
            clients = Client.query.filter_by(
                tenant_id=g.request_tenant_id, username=g.request_username, active=True
            )
        return utils.ok(
            result=[cl.serialize for cl in clients],
            msg="Clients retrieved successfully.",
        )

    def post(self):
        logger.debug("top of POST /clients")
        result = openapi_request_validator.validate(
            utils.spec, FlaskOpenAPIRequest(request)
        )
        if result.errors:
            raise errors.ResourceError(msg=f"Invalid POST data: {result.errors}.")
        validated_body = result.body
        data = Client.get_derived_values(validated_body)
        data.update({"tenant_id": g.request_tenant_id, "username": g.request_username})
        g.tenant_id = g.request_tenant_id
        g.username = g.request_username
        client = Client(**data)
        logger.debug(
            f"creating new client; data: {data}; "
            f"client: {client}; "
            f"g.request_tenant_id: {g.request_tenant_id}; "
            f"g.tenant_id: {g.tenant_id}; "
            f"g.request_username: {g.request_username}; "
            f"g.username: {g.username}"
        )
        try:
            db.session.add(client)
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit client object to db: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        except Exception as e:
            msg = (
                f"Got unexpected exception trying to add client to database. "
                f"Contact system administrator. (Debug data: {e})"
            )
            logger.error(msg)
            raise errors.ResourceError(f"{msg}")
        return utils.ok(result=client.serialize, msg="Client created successfully.")
