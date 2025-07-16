# Copyright 2025 © BeeAI a Series of LF Projects, LLC
# SPDX-License-Identifier: Apache-2.0

import uuid
from beeai_server.api.dependencies import ConfigurationDependency
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Query
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse


router = APIRouter()
login_sessions = {}


def build_oauth(configuration: ConfigurationDependency):
    oidc_auth = configuration.oidc

    if oidc_auth.disable_oidc:
        return

    oauth = OAuth()
    oauth.register(
        name="oidc_provider",
        client_id=oidc_auth.client_id,
        client_secret=oidc_auth.client_secret._secret_value,
        authorize_url=str(oidc_auth.authorize_url),
        access_token_url=str(oidc_auth.token_url),
        userinfo_endpoint=str(oidc_auth.userinfo_url),
        client_kwargs={"scope": "openid email profile", "token_endpoint_auth_method": "client_secret_basic"},
        server_metadata_url="https://sox.verify.ibm.com/v1.0/endpoint/default/.well-known/openid-configuration",
        jwks_uri="https://sox.verify.ibm.com/v1.0/endpoint/default/jwks",
    )
    return oauth


pending_states: dict[str, {}] = {}  # state --> login-id
pending_tokens: dict[str, str] = {}  # login-id --> id_token


@router.post("/login")
async def login(
    request: Request,
    configuration: ConfigurationDependency,
    cli: bool = Query(default=False, description="Set to true if the login request is from a CLI tool"),
):
    # oauth = build_oauth(configuration=configuration)
    # if oauth is None:
    #     return {"login_url": None, "login_id": "dev", "dev_token": "beeai-dev-token"}

    # login_id = str(uuid.uuid4())
    # is_cli = request.query_params.get("cli") == "true"
    # request.session["is_cli"] = is_cli
    # request.session["login_id"] = login_id
    # redirect_uri = str(request.url_for("auth_callback"))

    # if is_cli:
    #     response = await oauth.oidc_provider.authorize_redirect(request, redirect_uri)
    #     authorization_url = response.headers.get("location")
    #     return JSONResponse({"login_url":str(authorization_url), "login_id":login_id})
    # return await oauth.oidc_provider.authorize_redirect(request, redirect_uri)

    oauth = build_oauth(configuration=configuration)
    if oauth is None:
        return {"login_url": None, "login_id": "dev", "dev_token": "beeai-dev-token"}

    login_id = str(uuid.uuid4())
    redirect_uri = str(request.url_for("auth_callback"))

    if cli:
        # For CLI clients, manually manage the state
        state = str(uuid.uuid4())

        # Inject state manually in redirect URL
        response = await oauth.oidc_provider.authorize_redirect(request, redirect_uri, state=state)
        authorization_url = response.headers.get("location")
        key = f"_state_oidc_provider_{state}"
        oidc_state_dict = request.session.get(key)
        pending_states[state] = {
            "login_id": login_id,
            "oidc_state": oidc_state_dict,
        }
        return JSONResponse({"login_url": str(authorization_url), "login_id": login_id})

    # UI clients - use session (cookie-backed)
    request.session["is_cli"] = False
    request.session["login_id"] = login_id
    return await oauth.oidc_provider.authorize_redirect(request, redirect_uri)


@router.get("/auth/callback")
async def auth_callback(request: Request, configuration: ConfigurationDependency):
    oauth = build_oauth(configuration)
    if oauth is None:
        raise HTTPException(status_code=503, detail="OIDC disabled in configuration")

    state = request.query_params.get("state")
    login_id = None

    if state and state in pending_states:
        stored = pending_states.pop(state)
        login_id = stored["login_id"]
        key = f"_state_oidc_provider_{state}"
        request.session[key] = stored["oidc_state"]
        is_cli = True
    else:
        login_id = request.session.get("login_id")
        is_cli = request.session.get("is_cli", False)

    token = await oauth.oidc_provider.authorize_access_token(request)
    id_token = token.get("id_token")

    if login_id and id_token:
        pending_tokens[login_id] = id_token

    response = RedirectResponse("/api/v1/auth/cli-complete" if is_cli else "/")
    if is_cli:
        response.set_cookie("token", token, secure=True, samesite="strict")
    else:
        response.set_cookie("beeai-platform", token, httponly=True, secure=True, samesite="strict")

    return response


@router.get("/cli-complete")
async def cli_complete():
    return HTMLResponse("""
        <html><body>
        <h3>Login Successful</h3>
        <script>
            const token = document.cookie.split('; ').find(row => row.startsWith('token=')).split('=')[1];
            fetch('/auth/poll', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });
        </script>
        You can close this window.
        </body></html>
    """)


@router.get("/cli/token")
async def get_token(login_id: str):
    if login_id == "dev":
        return JSONResponse(status_code=200, content={"token": "beeai-dev-token"})
    token = pending_tokens.pop(login_id, None)
    if token:
        return JSONResponse(status_code=200, content={"token": token})
    raise HTTPException(status_code=404, detail="Token not found or expired")
