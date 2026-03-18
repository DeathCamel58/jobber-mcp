"""OAuth Authorization Server Provider that proxies to Jobber's OAuth."""

import logging
import os
import time
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthToken,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from jobber_mcp.token_store import TokenStore

logger = logging.getLogger(__name__)

JOBBER_AUTHORIZE_URL = "https://api.getjobber.com/api/oauth/authorize"
JOBBER_TOKEN_URL = "https://api.getjobber.com/api/oauth/token"


class JobberOAuthProvider:
    """MCP OAuth provider that proxies authentication to Jobber."""

    def __init__(self, token_store: TokenStore, http_client: httpx.AsyncClient) -> None:
        self.token_store = token_store
        self.http_client = http_client
        self.jobber_client_id = os.environ["JOBBER_CLIENT_ID"]
        self.jobber_client_secret = os.environ["JOBBER_CLIENT_SECRET"]
        self.server_url = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = await self.token_store.get_client(client_id)
        if data is None:
            return None
        return OAuthClientInformationFull(**data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        assert client_info.client_id is not None
        await self.token_store.save_client(
            client_info.client_id, client_info.model_dump(mode="json")
        )

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        # Generate a state key that links the Jobber OAuth callback back to this auth request
        state_key = TokenStore.generate_token()

        await self.token_store.save_pending_auth(
            state_key=state_key,
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=params.scopes or [],
            mcp_state=params.state,
            resource=str(params.resource) if params.resource else None,
        )

        # Redirect user to Jobber's OAuth authorization page
        jobber_params = {
            "client_id": self.jobber_client_id,
            "redirect_uri": f"{self.server_url}/jobber/callback",
            "response_type": "code",
            "state": state_key,
        }
        return f"{JOBBER_AUTHORIZE_URL}?{urlencode(jobber_params)}"

    async def handle_jobber_callback(
        self, jobber_code: str, state_key: str
    ) -> str:
        """Handle Jobber's OAuth callback. Returns the redirect URL for the MCP client."""
        pending = await self.token_store.get_pending_auth(state_key)
        if not pending:
            raise AuthorizeError(error="invalid_request", error_description="Unknown state")

        # Exchange the Jobber auth code for Jobber tokens
        token_resp = await self.http_client.post(
            JOBBER_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": jobber_code,
                "client_id": self.jobber_client_id,
                "client_secret": self.jobber_client_secret,
                "redirect_uri": f"{self.server_url}/jobber/callback",
            },
        )
        if token_resp.status_code != 200:
            logger.error("Jobber token exchange failed: %s", token_resp.text)
            raise AuthorizeError(
                error="server_error",
                error_description="Failed to exchange Jobber authorization code",
            )

        jobber_tokens = token_resp.json()

        # Generate an MCP authorization code
        mcp_code = TokenStore.generate_token()
        expires_at = time.time() + 300  # 5 minute expiry

        await self.token_store.save_authorization_code(
            code=mcp_code,
            client_id=pending["client_id"],
            scopes=pending["scopes"],
            expires_at=expires_at,
            code_challenge=pending["code_challenge"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            resource=pending["resource"],
        )

        # Store the Jobber tokens, keyed by the MCP auth code temporarily.
        # They'll be re-keyed to the MCP access token during exchange.
        await self.token_store.save_jobber_tokens(
            mcp_access_token=f"authcode:{mcp_code}",
            jobber_access_token=jobber_tokens["access_token"],
            jobber_refresh_token=jobber_tokens.get("refresh_token"),
            expires_at=int(time.time()) + jobber_tokens.get("expires_in", 3600),
        )

        await self.token_store.delete_pending_auth(state_key)

        # Redirect back to the MCP client's redirect_uri with the MCP auth code
        params = {"code": mcp_code}
        if pending["mcp_state"]:
            params["state"] = pending["mcp_state"]

        redirect_uri = pending["redirect_uri"]
        separator = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{separator}{urlencode(params)}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = await self.token_store.get_authorization_code(authorization_code)
        if data is None:
            return None
        if data["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=data["code"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=AnyUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data["resource"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Retrieve Jobber tokens stored under the auth code key
        jobber_data = await self.token_store.get_jobber_tokens(
            f"authcode:{authorization_code.code}"
        )
        if not jobber_data:
            raise TokenError(error="invalid_grant", error_description="No Jobber tokens found")

        # Generate MCP tokens
        mcp_access = TokenStore.generate_token()
        mcp_refresh = TokenStore.generate_token()
        expires_in = 3600
        now = int(time.time())

        scopes = authorization_code.scopes
        resource = str(authorization_code.resource) if authorization_code.resource else None

        await self.token_store.save_access_token(
            token=mcp_access,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=now + expires_in,
            resource=resource,
        )
        await self.token_store.save_refresh_token(
            token=mcp_refresh,
            client_id=client.client_id,
            scopes=scopes,
        )

        # Re-key Jobber tokens from auth code to MCP access token
        await self.token_store.save_jobber_tokens(
            mcp_access_token=mcp_access,
            jobber_access_token=jobber_data["jobber_access_token"],
            jobber_refresh_token=jobber_data["jobber_refresh_token"],
            expires_at=jobber_data["expires_at"],
        )
        await self.token_store.delete_jobber_tokens(f"authcode:{authorization_code.code}")

        # Clean up used authorization code
        await self.token_store.delete_authorization_code(authorization_code.code)

        return OAuthToken(
            access_token=mcp_access,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=mcp_refresh,
            scope=" ".join(scopes) if scopes else None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        data = await self.token_store.get_refresh_token(refresh_token)
        if data is None:
            return None
        if data["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=data["token"],
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Find the current MCP access token linked to this refresh token's client
        # We need the Jobber refresh token to get new Jobber tokens
        # Look up Jobber tokens by finding the access token for this client
        old_access_rows = await self.token_store.db.execute_fetchall(
            "SELECT token FROM access_tokens WHERE client_id = ? ORDER BY expires_at DESC LIMIT 1",
            (client.client_id,),
        )
        if not old_access_rows:
            raise TokenError(error="invalid_grant", error_description="No access token found")

        old_mcp_access = old_access_rows[0][0]
        jobber_data = await self.token_store.get_jobber_tokens(old_mcp_access)

        if not jobber_data or not jobber_data["jobber_refresh_token"]:
            raise TokenError(
                error="invalid_grant", error_description="No Jobber refresh token available"
            )

        # Refresh Jobber tokens upstream
        token_resp = await self.http_client.post(
            JOBBER_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": jobber_data["jobber_refresh_token"],
                "client_id": self.jobber_client_id,
                "client_secret": self.jobber_client_secret,
            },
        )
        if token_resp.status_code != 200:
            logger.error("Jobber token refresh failed: %s", token_resp.text)
            raise TokenError(
                error="invalid_grant", error_description="Jobber token refresh failed"
            )

        new_jobber = token_resp.json()

        # Generate new MCP tokens
        new_mcp_access = TokenStore.generate_token()
        new_mcp_refresh = TokenStore.generate_token()
        expires_in = 3600
        now = int(time.time())

        effective_scopes = scopes or refresh_token.scopes

        await self.token_store.save_access_token(
            token=new_mcp_access,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=now + expires_in,
            resource=None,
        )
        await self.token_store.save_refresh_token(
            token=new_mcp_refresh,
            client_id=client.client_id,
            scopes=effective_scopes,
        )

        # Store new Jobber tokens
        await self.token_store.save_jobber_tokens(
            mcp_access_token=new_mcp_access,
            jobber_access_token=new_jobber["access_token"],
            jobber_refresh_token=new_jobber.get("refresh_token"),
            expires_at=now + new_jobber.get("expires_in", 3600),
        )

        # Clean up old tokens
        await self.token_store.delete_jobber_tokens(old_mcp_access)
        await self.token_store.delete_access_token(old_mcp_access)
        await self.token_store.delete_refresh_token(refresh_token.token)

        return OAuthToken(
            access_token=new_mcp_access,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_mcp_refresh,
            scope=" ".join(effective_scopes) if effective_scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        data = await self.token_store.get_access_token(token)
        if data is None:
            return None
        # Check expiry
        if data["expires_at"] and data["expires_at"] < int(time.time()):
            await self.token_store.delete_access_token(token)
            return None
        return AccessToken(
            token=data["token"],
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            resource=data["resource"],
        )

    async def revoke_token(
        self, token: AccessToken | RefreshToken
    ) -> None:
        if isinstance(token, AccessToken):
            await self.token_store.delete_jobber_tokens(token.token)
            await self.token_store.delete_access_token(token.token)
        elif isinstance(token, RefreshToken):
            await self.token_store.delete_refresh_token(token.token)
