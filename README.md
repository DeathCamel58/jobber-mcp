# Jobber MCP Server

An MCP server that exposes [Jobber's](https://getjobber.com) GraphQL API as MCP tools. Supports multiple users via OAuth, where each user authenticates with their own Jobber account.

## Architecture

```
MCP Client  <-->  MCP Server (OAuth AS + RS)  <-->  Jobber GraphQL API
```

The server acts as both an OAuth Authorization Server (for MCP clients) and a Resource Server. It proxies OAuth authentication to Jobber and stores tokens in SQLite.

## Setup

### Prerequisites

- Python 3.12+
- A [Jobber Developer](https://developer.getjobber.com/) app with OAuth credentials
- A publicly accessible URL (e.g., via ngrok) for the OAuth callback

### Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Configuration

Create a `.env` file:

```
JOBBER_CLIENT_ID=your-jobber-client-id
JOBBER_CLIENT_SECRET=your-jobber-client-secret
MCP_SERVER_URL=https://your-public-url.example.com
MCP_SERVER_PORT=8000
```

| Variable | Description | Default |
|---|---|---|
| `JOBBER_CLIENT_ID` | Jobber OAuth app client ID | *required* |
| `JOBBER_CLIENT_SECRET` | Jobber OAuth app client secret | *required* |
| `MCP_SERVER_URL` | Public URL of this server (used for OAuth callbacks and metadata) | `http://localhost:8000` |
| `MCP_SERVER_PORT` | Port to listen on | `8000` |
| `JOBBER_SHARED_AUTH` | Share one Jobber login across all users (`true`/`false`) | `false` |

Set your Jobber app's redirect URI to `{MCP_SERVER_URL}/jobber/callback`.

### Running

```bash
python jobber_mcp/server.py
```

## Available Tools

| Tool | Description |
|---|---|
| `get_account` | Get current Jobber account info |
| `list_clients` / `get_client` / `create_client` | Manage clients |
| `list_jobs` / `get_job` / `create_job` | Manage jobs |
| `list_invoices` / `get_invoice` / `create_invoice` | Manage invoices |
| `list_quotes` / `get_quote` / `create_quote` | Manage quotes |
| `list_requests` / `get_request` | View service requests |
| `execute_graphql` | Run raw GraphQL queries |

## Connecting from Claude

1. Start the server and ensure it's publicly accessible
2. In Claude, go to Settings > Connectors > Add Connector
3. Enter your server's public URL
4. Click Connect — you'll be redirected to Jobber to authorize
5. After authorization, the tools will be available in your conversations
