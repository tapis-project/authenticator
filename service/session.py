from flask import session


def logout():
    """
    Helper function to reset the session whenever a logout needs to occur.
    """
    session.clear()


def clear_orig_client_data():
    session.pop("orig_client_id", None)
    session.pop("orig_client_redirect_uri", None)
    session.pop("orig_client_response_type", None)
    session.pop("orig_client_state", None)
    session.pop("nonce", None)

def logout_from_webapp():
    """
    Helper function that just removes the Token Webapp's attributes from the session.
    """
    session.pop("access_token", None)


def get_state_tag(state):
    """
    Returns a log prefix for the client state. We truncate to max 64 chars for readability.
    """
    return f"[state={state!r:.64}]"
