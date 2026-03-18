"""GraphQL client for the Jobber API."""

import logging

import httpx

from jobber_mcp.token_store import TokenStore

logger = logging.getLogger(__name__)

JOBBER_GRAPHQL_URL = "https://api.getjobber.com/api/graphql"
JOBBER_GRAPHQL_VERSION = "2025-01-20"


class JobberClient:
    """Async GraphQL client for Jobber's API."""

    def __init__(self, token_store: TokenStore, http_client: httpx.AsyncClient) -> None:
        self.token_store = token_store
        self.http_client = http_client

    async def execute_query(
        self,
        query: str,
        variables: dict | None,
        mcp_access_token: str,
    ) -> dict:
        """Execute a GraphQL query against Jobber's API.

        Looks up the user's Jobber token from the MCP access token,
        then executes the query.
        """
        jobber_data = await self.token_store.get_jobber_tokens(mcp_access_token)
        if not jobber_data:
            return {"errors": [{"message": "No Jobber tokens found. Please re-authenticate."}]}

        headers = {
            "Authorization": f"Bearer {jobber_data['jobber_access_token']}",
            "X-JOBBER-GRAPHQL-VERSION": JOBBER_GRAPHQL_VERSION,
            "Content-Type": "application/json",
        }

        payload: dict = {"query": query}
        if variables:
            payload["variables"] = variables

        resp = await self.http_client.post(
            JOBBER_GRAPHQL_URL, json=payload, headers=headers
        )

        if resp.status_code == 401:
            # Try refreshing the Jobber token
            refreshed = await self._refresh_jobber_token(mcp_access_token, jobber_data)
            if refreshed:
                headers["Authorization"] = f"Bearer {refreshed}"
                resp = await self.http_client.post(
                    JOBBER_GRAPHQL_URL, json=payload, headers=headers
                )
            else:
                return {"errors": [{"message": "Jobber token expired. Please re-authenticate."}]}

        return resp.json()

    async def _refresh_jobber_token(
        self, mcp_access_token: str, jobber_data: dict
    ) -> str | None:
        """Attempt to refresh the Jobber access token. Returns the new token or None."""
        import os
        import time

        refresh_token = jobber_data.get("jobber_refresh_token")
        if not refresh_token:
            return None

        resp = await self.http_client.post(
            "https://api.getjobber.com/api/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": os.environ["JOBBER_CLIENT_ID"],
                "client_secret": os.environ["JOBBER_CLIENT_SECRET"],
            },
        )

        if resp.status_code != 200:
            logger.error("Jobber token refresh failed: %s", resp.text)
            return None

        new_tokens = resp.json()
        await self.token_store.save_jobber_tokens(
            mcp_access_token=mcp_access_token,
            jobber_access_token=new_tokens["access_token"],
            jobber_refresh_token=new_tokens.get("refresh_token"),
            expires_at=int(time.time()) + new_tokens.get("expires_in", 3600),
        )
        return new_tokens["access_token"]
