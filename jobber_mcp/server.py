"""Jobber MCP Server - entry point."""

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import uvicorn
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from jobber_mcp.jobber_client import JobberClient
from jobber_mcp.oauth_provider import JobberOAuthProvider
from jobber_mcp.token_store import TokenStore
from jobber_mcp.tools import register_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_server() -> FastMCP:
    server_url = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
    port = int(os.environ.get("MCP_SERVER_PORT", "8000"))

    token_store = TokenStore()
    http_client = httpx.AsyncClient()
    oauth_provider = JobberOAuthProvider(token_store, http_client)
    jobber = JobberClient(token_store, http_client)

    auth_settings = AuthSettings(
        issuer_url=server_url,
        resource_server_url=f"{server_url}/mcp",
        client_registration_options=ClientRegistrationOptions(enabled=True),
        revocation_options=RevocationOptions(enabled=True),
    )

    # Allow the public hostname (e.g. ngrok) through transport security
    from urllib.parse import urlparse

    parsed_url = urlparse(server_url)
    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    if parsed_url.hostname and parsed_url.hostname not in ("127.0.0.1", "localhost", "::1"):
        allowed_hosts.append(parsed_url.hostname)
        allowed_hosts.append(f"{parsed_url.hostname}:*")

    mcp = FastMCP(
        name="Jobber MCP",
        instructions=(
            "This server provides access to Jobber's field service management platform. "
            "You can manage clients, jobs, invoices, quotes, and service requests."
        ),
        auth_server_provider=oauth_provider,
        auth=auth_settings,
        port=port,
        transport_security=TransportSecuritySettings(allowed_hosts=allowed_hosts),
    )

    # Stash references for app-level lifespan
    mcp._token_store = token_store  # type: ignore[attr-defined]
    mcp._http_client = http_client  # type: ignore[attr-defined]

    # Jobber OAuth callback route
    @mcp.custom_route("/jobber/callback", methods=["GET"])
    async def jobber_callback(request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            logger.error("Jobber OAuth error: %s", error)
            return Response(
                content=f"Authorization failed: {error}",
                status_code=400,
            )

        if not code or not state:
            return Response(
                content="Missing code or state parameter",
                status_code=400,
            )

        redirect_url = await oauth_provider.handle_jobber_callback(code, state)
        return RedirectResponse(url=redirect_url)

    register_tools(mcp, jobber)
    return mcp


mcp = create_server()


def create_app() -> Starlette:
    """Create the Starlette app with a proper lifespan that initializes the token store."""
    inner_app = mcp.streamable_http_app()
    original_lifespan = inner_app.router.lifespan_context

    @asynccontextmanager
    async def app_lifespan(app: Starlette) -> AsyncIterator[None]:
        token_store = mcp._token_store  # type: ignore[attr-defined]
        http_client = mcp._http_client  # type: ignore[attr-defined]
        await token_store.initialize()
        logger.info("Token store initialized")
        try:
            async with original_lifespan(app):
                yield
        finally:
            await token_store.close()
            await http_client.aclose()
            logger.info("Resources cleaned up")

    inner_app.router.lifespan_context = app_lifespan
    return inner_app


def main() -> None:
    port = int(os.environ.get("MCP_SERVER_PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
