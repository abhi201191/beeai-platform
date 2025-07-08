# Copyright 2025 © BeeAI a Series of LF Projects, LLC
# SPDX-License-Identifier: Apache-2.0

import uuid
from beeai_server.api.dependencies import ConfigurationDependency
from authlib.integrations.starlette_client import OAuth
import fastapi

router = fastapi.APIRouter()
login_sessions = {}


def build_oauth(configuration: ConfigurationDependency):
    oidc_auth = configuration.oidc

    if oidc_auth.disable_oidc:
        return

    oauth = OAuth()
    oauth.register(
        name="oidc_provider",
        client_id=oidc_auth.client_id,
        client_secret=oidc_auth.client_secret,
        authorize_url=oidc_auth.authorize_url,
        access_token_url=oidc_auth.token_url,
        userinfo_endpoint=oidc_auth.userinfo_url,
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth


@router.post("/login")
async def login(request: fastapi.Request, configuration: ConfigurationDependency):
    oauth = build_oauth(configuration=configuration)
    if oauth is None:
        return {"verification_url": None, "login_id": "dev", "dev_token": "beeai-dev-token"}

    login_id = str(uuid.uuid4())
    request.session["login_id"] = login_id
    redirect_uri = request.url_for("auth_callback")
    url = await oauth.oidc_provider.authorize_redirect(request, redirect_uri)
    return {"verification_url": str(url), "login_id": login_id}


@router.get("/login/callback")
async def auth_callback(request: fastapi.Request, configuration: ConfigurationDependency):
    oauth = build_oauth(configuration)
    if oauth is None:
        raise fastapi.HTTPException(status_code=503, detail="OIDC disabled in configuration")

    token = await oauth.oidc_provider.authorize_access_token(request)
    userinfo = await oauth.oidc_provider.parse_id_token(request, token)

    login_id = request.session.get("login_id")
    if login_id:
        login_sessions[login_id] = {"token": token, "user": userinfo}
    return fastapi.responses.RedirectResponse(url="/login-complete")


@router.get("/login/status")
async def login_status(login_id: str):
    if login_id == "dev":
        # dev mode fake user
        return {
            "status": "complete",
            "access_token": "beeai-dev-token",
            "user": {"sub": "devuser", "email": "devuser@example.com"},
        }
    session = login_sessions.get(login_id)
    if session:
        return {"status": "complete", "access_token": session["token"]["access_token"], "user": session["user"]}
    return {"status": "pending"}
