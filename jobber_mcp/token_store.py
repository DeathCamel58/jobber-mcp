"""SQLite-backed token and client storage for the Jobber MCP server."""

import json
import secrets
import time

import aiosqlite

DB_PATH = "jobber_mcp.db"


class TokenStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_info_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                expires_at REAL NOT NULL,
                code_challenge TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                redirect_uri_provided_explicitly INTEGER NOT NULL,
                resource TEXT
            );

            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                expires_at INTEGER,
                resource TEXT
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                expires_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS jobber_tokens (
                mcp_access_token TEXT PRIMARY KEY,
                jobber_access_token TEXT NOT NULL,
                jobber_refresh_token TEXT,
                expires_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS pending_auth (
                state_key TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                redirect_uri_provided_explicitly INTEGER NOT NULL,
                code_challenge TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                mcp_state TEXT,
                resource TEXT,
                created_at REAL NOT NULL
            );
        """)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "TokenStore not initialized"
        return self._db

    # --- Client Registration ---

    async def get_client(self, client_id: str) -> dict | None:
        row = await self.db.execute_fetchall(
            "SELECT client_info_json FROM clients WHERE client_id = ?",
            (client_id,),
        )
        if not row:
            return None
        return json.loads(row[0][0])

    async def save_client(self, client_id: str, client_info: dict) -> None:
        await self.db.execute(
            "INSERT OR REPLACE INTO clients (client_id, client_info_json) VALUES (?, ?)",
            (client_id, json.dumps(client_info)),
        )
        await self.db.commit()

    # --- Pending Auth (for Jobber OAuth callback) ---

    async def save_pending_auth(
        self,
        state_key: str,
        client_id: str,
        redirect_uri: str,
        redirect_uri_provided_explicitly: bool,
        code_challenge: str,
        scopes: list[str],
        mcp_state: str | None,
        resource: str | None,
    ) -> None:
        await self.db.execute(
            """INSERT OR REPLACE INTO pending_auth
               (state_key, client_id, redirect_uri, redirect_uri_provided_explicitly,
                code_challenge, scopes_json, mcp_state, resource, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                state_key,
                client_id,
                redirect_uri,
                int(redirect_uri_provided_explicitly),
                code_challenge,
                json.dumps(scopes),
                mcp_state,
                resource,
                time.time(),
            ),
        )
        await self.db.commit()

    async def get_pending_auth(self, state_key: str) -> dict | None:
        rows = await self.db.execute_fetchall(
            "SELECT * FROM pending_auth WHERE state_key = ?",
            (state_key,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "state_key": row[0],
            "client_id": row[1],
            "redirect_uri": row[2],
            "redirect_uri_provided_explicitly": bool(row[3]),
            "code_challenge": row[4],
            "scopes": json.loads(row[5]),
            "mcp_state": row[6],
            "resource": row[7],
            "created_at": row[8],
        }

    async def delete_pending_auth(self, state_key: str) -> None:
        await self.db.execute("DELETE FROM pending_auth WHERE state_key = ?", (state_key,))
        await self.db.commit()

    # --- Authorization Codes ---

    async def save_authorization_code(
        self,
        code: str,
        client_id: str,
        scopes: list[str],
        expires_at: float,
        code_challenge: str,
        redirect_uri: str,
        redirect_uri_provided_explicitly: bool,
        resource: str | None,
    ) -> None:
        await self.db.execute(
            """INSERT INTO authorization_codes
               (code, client_id, scopes_json, expires_at, code_challenge,
                redirect_uri, redirect_uri_provided_explicitly, resource)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                code,
                client_id,
                json.dumps(scopes),
                expires_at,
                code_challenge,
                redirect_uri,
                int(redirect_uri_provided_explicitly),
                resource,
            ),
        )
        await self.db.commit()

    async def get_authorization_code(self, code: str) -> dict | None:
        rows = await self.db.execute_fetchall(
            "SELECT * FROM authorization_codes WHERE code = ?",
            (code,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "code": row[0],
            "client_id": row[1],
            "scopes": json.loads(row[2]),
            "expires_at": row[3],
            "code_challenge": row[4],
            "redirect_uri": row[5],
            "redirect_uri_provided_explicitly": bool(row[6]),
            "resource": row[7],
        }

    async def delete_authorization_code(self, code: str) -> None:
        await self.db.execute("DELETE FROM authorization_codes WHERE code = ?", (code,))
        await self.db.commit()

    # --- Access Tokens ---

    async def save_access_token(
        self,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int | None,
        resource: str | None,
    ) -> None:
        await self.db.execute(
            """INSERT INTO access_tokens (token, client_id, scopes_json, expires_at, resource)
               VALUES (?, ?, ?, ?, ?)""",
            (token, client_id, json.dumps(scopes), expires_at, resource),
        )
        await self.db.commit()

    async def get_access_token(self, token: str) -> dict | None:
        rows = await self.db.execute_fetchall(
            "SELECT * FROM access_tokens WHERE token = ?",
            (token,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "token": row[0],
            "client_id": row[1],
            "scopes": json.loads(row[2]),
            "expires_at": row[3],
            "resource": row[4],
        }

    async def delete_access_token(self, token: str) -> None:
        await self.db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
        await self.db.commit()

    # --- Refresh Tokens ---

    async def save_refresh_token(
        self,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: int | None = None,
    ) -> None:
        await self.db.execute(
            """INSERT INTO refresh_tokens (token, client_id, scopes_json, expires_at)
               VALUES (?, ?, ?, ?)""",
            (token, client_id, json.dumps(scopes), expires_at),
        )
        await self.db.commit()

    async def get_refresh_token(self, token: str) -> dict | None:
        rows = await self.db.execute_fetchall(
            "SELECT * FROM refresh_tokens WHERE token = ?",
            (token,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "token": row[0],
            "client_id": row[1],
            "scopes": json.loads(row[2]),
            "expires_at": row[3],
        }

    async def delete_refresh_token(self, token: str) -> None:
        await self.db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        await self.db.commit()

    # --- Jobber Tokens (upstream tokens keyed by MCP access token) ---

    async def save_jobber_tokens(
        self,
        mcp_access_token: str,
        jobber_access_token: str,
        jobber_refresh_token: str | None,
        expires_at: int | None,
    ) -> None:
        await self.db.execute(
            """INSERT OR REPLACE INTO jobber_tokens
               (mcp_access_token, jobber_access_token, jobber_refresh_token, expires_at)
               VALUES (?, ?, ?, ?)""",
            (mcp_access_token, jobber_access_token, jobber_refresh_token, expires_at),
        )
        await self.db.commit()

    async def get_jobber_tokens(self, mcp_access_token: str) -> dict | None:
        rows = await self.db.execute_fetchall(
            "SELECT * FROM jobber_tokens WHERE mcp_access_token = ?",
            (mcp_access_token,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "mcp_access_token": row[0],
            "jobber_access_token": row[1],
            "jobber_refresh_token": row[2],
            "expires_at": row[3],
        }

    async def delete_jobber_tokens(self, mcp_access_token: str) -> None:
        await self.db.execute(
            "DELETE FROM jobber_tokens WHERE mcp_access_token = ?",
            (mcp_access_token,),
        )
        await self.db.commit()

    # --- Helpers ---

    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically secure token (>=160 bits entropy)."""
        return secrets.token_urlsafe(32)
