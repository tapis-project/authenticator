"""
This file contains the Resources responsible for handling device authorization flows.

Resources:
- DeviceCodeResource: Handles the creation of device codes for device authorization.
- DeviceFlowResource: Provides web pages and logic for
    user authentication using device codes.
"""

from flask import g, make_response, redirect, render_template, request, session, url_for
from flask_restful import Resource
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
from tapisservice import errors
from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

from service.models import Client, DeviceCode, db

logger = get_logger(__name__)


class DeviceCodeResource(Resource):
    """
    POST request for creating a device code
    input:
    * client_id: created by user
    optional:
    * ttl: time to live for token
    """

    def post(self):
        logger.debug("In device code resource")
        # support content-type www-form by setting the body on the request
        # eqaul to the JSON

        result = openapi_request_validator.validate(
            utils.spec, FlaskOpenAPIRequest(request)
        )
        if result.errors:
            raise errors.ResourceError(msg=f"Invalid POST data: {result.errors}.")
        validated_body = result.body
        logger.debug(f"validate_body: {validated_body}")
        client_id = validated_body.client_id
        logger.debug("Checked client_id: %s", client_id)
        tenant_id = g.request_tenant_id
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            logger.debug(f"client not found in db. client_id: {client_id}")
            raise errors.ResourceError(f"Invalid client: {client_id}")
        # we just need the part of the URL up to the "/v3/oauth2" (i.e., the base URL)
        #  so we split on that:
        device_code_base_url = request.base_url.split("/v3/oauth2")[0]
        if "localhost" not in device_code_base_url:
            device_code_base_url = device_code_base_url.replace("http://", "https://")

        device_code = DeviceCode(
            tenant_id=tenant_id,
            username=None,
            client_id=client_id,
            client_key=client.client_key,
            code=DeviceCode.generate_code(),
            user_code=DeviceCode.generate_user_code(),
            status="Created",
            verification_uri=DeviceCode.generate_verification_uri(
                tenant_id, client_id, BASE_URL=device_code_base_url
            ),
            expiry_time=DeviceCode.compute_expiry(),
            access_token_ttl=DeviceCode.set_ttl(),
        )
        try:
            db.session.add(device_code)
            db.session.commit()
        except Exception as e:
            logger.error(
                "Got exception trying to add and commit the device code. "
                f"e: {e}; type(e): {type(e)}"
            )
            raise errors.ResourceError(
                "Internal error saving device code. Please try again later."
            )
        result = {}
        result["client_id"] = client_id
        result["user_code"] = device_code.user_code
        result["device_code"] = device_code.code
        result["verification_uri"] = device_code.verification_uri
        result["expires_in"] = device_code.expiry_time

        return utils.ok(result=result, msg="Token created successfully.")


class DeviceFlowResource(Resource):
    """
    Web page responsible for authentication using user code
    """

    def get(self):
        """
        Displays page with box to enter user code
        """
        logger.info("GET - Device Flow")
        tenant_id = g.request_tenant_id
        headers = {"Content-Type": "text/html"}
        client_id = request.args.get("client_id")
        if not client_id:
            context = {"error": "Invalid URL: client_id must be passed."}
            return make_response(
                render_template("device-code.html", **context), 200, headers
            )
        logger.debug(f"Got client id: {client_id}")

        session["device_login"] = True
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; "
                f"issuing redirect to AuthorizeResource. session: {session}"
            )
            return redirect(url_for("authorizeresource", client_id=client_id))
        if "username" not in session:
            logger.debug(
                f"username not found in session: {session}; "
                "issuing redirect to authorize"
            )
            return redirect(url_for("authorizeresource", client_id=client_id))
        context = {
            "error": "",
            "tenant_id": tenant_id,
            "username": session.get("username"),
        }
        return make_response(
            render_template("device-code.html", **context), 200, headers
        )

    def post(self):
        logger.debug("POST - Device Flow")
        tenant_id = g.request_tenant_id
        headers = {"Content-Type": "text/html"}
        session["device_login"] = True
        if not tenant_id:
            tenant_id = session.get("tenant_id")
        if not tenant_id:
            logger.debug(
                "did not find tenant_id in session; issuing redirect to LoginResource. "
                f"session: {session}"
            )
            return redirect(url_for("loginresource"), 302, headers)
        if "username" not in session:
            logger.debug(
                "did not find username in session; issuing redirect to LoginResource. "
                f"session: {session}"
            )
            return redirect(url_for("loginresource"), 302, headers)

        user_code = request.form.get("user_code")
        device_code = DeviceCode.query.filter_by(
            tenant_id=tenant_id, user_code=user_code
        ).first()
        if not device_code:
            raise errors.ResourceError("Invalid code.")
        # ask about this
        try:
            client = Client.query.filter_by(client_id=device_code.client_id).first()
        except Exception as e:
            logger.debug(
                f"Unable to retrieve client: {device_code.client_id}; error: {e}"
            )
            raise errors.ResourceError(
                "Unable to retrieve client, cannot continue device flow"
            )
        if device_code:
            status = device_code.status
            if status == "Created":
                status = "Entered"
                try:
                    device_code.status = status
                    device_code.username = session.get("username")
                    db.session.commit()
                except Exception as e:
                    logger.error(
                        f"Error trying to update device code entry; error: {e}"
                    )
                    raise errors.ResourceError(
                        "Unable to update device, cannot continue device flow"
                    )
                return redirect(
                    url_for(
                        "authorizeresource",
                        client_id=client.client_id,
                        redirect_uri=None,
                        state=None,
                        client_display_name=client.display_name,
                        response_type="device_code",
                        user_code=user_code,
                    )
                )
            else:
                response = "Code not eligible to be entered"
                context = {"error": response, "username": session.get("username")}
                return make_response(
                    render_template("device-code.html", **context), 200, headers
                )
        else:
            response = "No device code found"
            context = {"error": response, "username": session.get("username")}
            return make_response(
                render_template("device-code.html", **context), 200, headers
            )
