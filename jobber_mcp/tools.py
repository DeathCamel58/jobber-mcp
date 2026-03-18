"""MCP tool definitions for Jobber operations."""

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.fastmcp import FastMCP

from jobber_mcp.jobber_client import JobberClient


def _get_mcp_token() -> str:
    """Get the current user's MCP access token."""
    access_token = get_access_token()
    if not access_token:
        raise ValueError("Not authenticated. Please complete the OAuth flow first.")
    return access_token.token


def register_tools(mcp: FastMCP, jobber: JobberClient) -> None:
    """Register all Jobber MCP tools on the server."""

    # --- Generic GraphQL ---

    @mcp.tool()
    async def execute_graphql(query: str, variables: dict | None = None) -> dict:
        """Execute a raw GraphQL query against the Jobber API.

        Use this for advanced queries not covered by other tools.
        See Jobber's GraphQL API docs for the schema.
        """
        return await jobber.execute_query(query, variables, _get_mcp_token())

    # --- Account ---

    @mcp.tool()
    async def get_account() -> dict:
        """Get the current Jobber account information."""
        query = """
        query {
            account {
                id
                name
                phone
                billingAddress {
                    street1
                    street2
                    city
                    province
                    postalCode
                    country
                }
            }
        }
        """
        return await jobber.execute_query(query, None, _get_mcp_token())

    # --- Clients ---

    @mcp.tool()
    async def list_clients(
        first: int = 20,
        after: str | None = None,
        search_term: str | None = None,
    ) -> dict:
        """List clients in Jobber.

        Args:
            first: Number of clients to return (max 50).
            after: Cursor for pagination.
            search_term: Optional search term to filter clients.
        """
        query = """
        query ListClients($first: Int!, $after: String, $searchTerm: String) {
            clients(first: $first, after: $after, searchTerm: $searchTerm) {
                nodes {
                    id
                    firstName
                    lastName
                    companyName
                    emails {
                        address
                        primary
                    }
                    phones {
                        number
                        primary
                    }
                    billingAddress {
                        street1
                        street2
                        city
                        province
                        postalCode
                        country
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        variables = {"first": min(first, 50)}
        if after:
            variables["after"] = after
        if search_term:
            variables["searchTerm"] = search_term
        return await jobber.execute_query(query, variables, _get_mcp_token())

    @mcp.tool()
    async def get_client(client_id: str) -> dict:
        """Get a specific client by ID.

        Args:
            client_id: The Jobber client ID.
        """
        query = """
        query GetClient($id: EncodedId!) {
            client(id: $id) {
                id
                firstName
                lastName
                companyName
                emails {
                    address
                    primary
                }
                phones {
                    number
                    primary
                }
                billingAddress {
                    street1
                    street2
                    city
                    province
                    postalCode
                    country
                }
                properties {
                    nodes {
                        id
                        address {
                            street1
                            street2
                            city
                            province
                            postalCode
                            country
                        }
                    }
                }
            }
        }
        """
        return await jobber.execute_query(query, {"id": client_id}, _get_mcp_token())

    @mcp.tool()
    async def create_client(
        first_name: str,
        last_name: str,
        company_name: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> dict:
        """Create a new client in Jobber.

        Args:
            first_name: Client's first name.
            last_name: Client's last name.
            company_name: Optional company name.
            email: Optional email address.
            phone: Optional phone number.
        """
        query = """
        mutation CreateClient($input: ClientCreateInput!) {
            clientCreate(input: $input) {
                client {
                    id
                    firstName
                    lastName
                    companyName
                }
                userErrors {
                    message
                    path
                }
            }
        }
        """
        client_input: dict = {
            "firstName": first_name,
            "lastName": last_name,
        }
        if company_name:
            client_input["companyName"] = company_name
        if email:
            client_input["emails"] = [{"address": email, "primary": True}]
        if phone:
            client_input["phones"] = [{"number": phone, "primary": True}]

        return await jobber.execute_query(
            query, {"input": client_input}, _get_mcp_token()
        )

    # --- Jobs ---

    @mcp.tool()
    async def list_jobs(
        first: int = 20,
        after: str | None = None,
        search_term: str | None = None,
    ) -> dict:
        """List jobs in Jobber.

        Args:
            first: Number of jobs to return (max 50).
            after: Cursor for pagination.
            search_term: Optional search term to filter jobs.
        """
        query = """
        query ListJobs($first: Int!, $after: String, $searchTerm: String) {
            jobs(first: $first, after: $after, searchTerm: $searchTerm) {
                nodes {
                    id
                    jobNumber
                    title
                    jobStatus
                    startAt
                    endAt
                    total
                    client {
                        id
                        firstName
                        lastName
                    }
                    property {
                        id
                        address {
                            street1
                            city
                            province
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        variables = {"first": min(first, 50)}
        if after:
            variables["after"] = after
        if search_term:
            variables["searchTerm"] = search_term
        return await jobber.execute_query(query, variables, _get_mcp_token())

    @mcp.tool()
    async def get_job(job_id: str) -> dict:
        """Get a specific job by ID.

        Args:
            job_id: The Jobber job ID.
        """
        query = """
        query GetJob($id: EncodedId!) {
            job(id: $id) {
                id
                jobNumber
                title
                jobStatus
                instructions
                startAt
                endAt
                total
                client {
                    id
                    firstName
                    lastName
                }
                property {
                    id
                    address {
                        street1
                        street2
                        city
                        province
                        postalCode
                        country
                    }
                }
                lineItems {
                    nodes {
                        id
                        name
                        description
                        quantity
                        unitPrice
                        totalPrice
                    }
                }
            }
        }
        """
        return await jobber.execute_query(query, {"id": job_id}, _get_mcp_token())

    @mcp.tool()
    async def create_job(
        client_id: str,
        title: str,
        instructions: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        line_items: list[dict] | None = None,
    ) -> dict:
        """Create a new job in Jobber.

        Args:
            client_id: The client ID this job is for.
            title: Job title.
            instructions: Optional job instructions/notes.
            start_at: Optional start datetime (ISO 8601).
            end_at: Optional end datetime (ISO 8601).
            line_items: Optional list of line items, each with 'name', 'quantity', 'unitPrice'.
        """
        query = """
        mutation CreateJob($input: JobCreateInput!) {
            jobCreate(input: $input) {
                job {
                    id
                    jobNumber
                    title
                    jobStatus
                }
                userErrors {
                    message
                    path
                }
            }
        }
        """
        job_input: dict = {
            "clientId": client_id,
            "title": title,
        }
        if instructions:
            job_input["instructions"] = instructions
        if start_at:
            job_input["startAt"] = start_at
        if end_at:
            job_input["endAt"] = end_at
        if line_items:
            job_input["lineItems"] = line_items

        return await jobber.execute_query(
            query, {"input": job_input}, _get_mcp_token()
        )

    # --- Invoices ---

    @mcp.tool()
    async def list_invoices(
        first: int = 20,
        after: str | None = None,
    ) -> dict:
        """List invoices in Jobber.

        Args:
            first: Number of invoices to return (max 50).
            after: Cursor for pagination.
        """
        query = """
        query ListInvoices($first: Int!, $after: String) {
            invoices(first: $first, after: $after) {
                nodes {
                    id
                    invoiceNumber
                    subject
                    invoiceStatus
                    total
                    amountDue
                    issuedDate
                    dueDate
                    client {
                        id
                        firstName
                        lastName
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        variables = {"first": min(first, 50)}
        if after:
            variables["after"] = after
        return await jobber.execute_query(query, variables, _get_mcp_token())

    @mcp.tool()
    async def get_invoice(invoice_id: str) -> dict:
        """Get a specific invoice by ID.

        Args:
            invoice_id: The Jobber invoice ID.
        """
        query = """
        query GetInvoice($id: EncodedId!) {
            invoice(id: $id) {
                id
                invoiceNumber
                subject
                invoiceStatus
                total
                amountDue
                issuedDate
                dueDate
                message
                client {
                    id
                    firstName
                    lastName
                }
                lineItems {
                    nodes {
                        id
                        name
                        description
                        quantity
                        unitPrice
                        totalPrice
                    }
                }
            }
        }
        """
        return await jobber.execute_query(query, {"id": invoice_id}, _get_mcp_token())

    @mcp.tool()
    async def create_invoice(
        client_id: str,
        subject: str | None = None,
        message: str | None = None,
        line_items: list[dict] | None = None,
    ) -> dict:
        """Create a new invoice in Jobber.

        Args:
            client_id: The client ID to invoice.
            subject: Optional invoice subject.
            message: Optional invoice message.
            line_items: Optional list of line items, each with 'name', 'quantity', 'unitPrice'.
        """
        query = """
        mutation CreateInvoice($input: InvoiceCreateInput!) {
            invoiceCreate(input: $input) {
                invoice {
                    id
                    invoiceNumber
                    subject
                    invoiceStatus
                    total
                }
                userErrors {
                    message
                    path
                }
            }
        }
        """
        invoice_input: dict = {"clientId": client_id}
        if subject:
            invoice_input["subject"] = subject
        if message:
            invoice_input["message"] = message
        if line_items:
            invoice_input["lineItems"] = line_items

        return await jobber.execute_query(
            query, {"input": invoice_input}, _get_mcp_token()
        )

    # --- Quotes ---

    @mcp.tool()
    async def list_quotes(
        first: int = 20,
        after: str | None = None,
    ) -> dict:
        """List quotes in Jobber.

        Args:
            first: Number of quotes to return (max 50).
            after: Cursor for pagination.
        """
        query = """
        query ListQuotes($first: Int!, $after: String) {
            quotes(first: $first, after: $after) {
                nodes {
                    id
                    quoteNumber
                    title
                    quoteStatus
                    total
                    createdAt
                    client {
                        id
                        firstName
                        lastName
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        variables = {"first": min(first, 50)}
        if after:
            variables["after"] = after
        return await jobber.execute_query(query, variables, _get_mcp_token())

    @mcp.tool()
    async def get_quote(quote_id: str) -> dict:
        """Get a specific quote by ID.

        Args:
            quote_id: The Jobber quote ID.
        """
        query = """
        query GetQuote($id: EncodedId!) {
            quote(id: $id) {
                id
                quoteNumber
                title
                quoteStatus
                total
                message
                createdAt
                client {
                    id
                    firstName
                    lastName
                }
                lineItems {
                    nodes {
                        id
                        name
                        description
                        quantity
                        unitPrice
                        totalPrice
                    }
                }
            }
        }
        """
        return await jobber.execute_query(query, {"id": quote_id}, _get_mcp_token())

    @mcp.tool()
    async def create_quote(
        client_id: str,
        title: str,
        message: str | None = None,
        line_items: list[dict] | None = None,
    ) -> dict:
        """Create a new quote in Jobber.

        Args:
            client_id: The client ID for the quote.
            title: Quote title.
            message: Optional quote message.
            line_items: Optional list of line items, each with 'name', 'quantity', 'unitPrice'.
        """
        query = """
        mutation CreateQuote($input: QuoteCreateInput!) {
            quoteCreate(input: $input) {
                quote {
                    id
                    quoteNumber
                    title
                    quoteStatus
                    total
                }
                userErrors {
                    message
                    path
                }
            }
        }
        """
        quote_input: dict = {
            "clientId": client_id,
            "title": title,
        }
        if message:
            quote_input["message"] = message
        if line_items:
            quote_input["lineItems"] = line_items

        return await jobber.execute_query(
            query, {"input": quote_input}, _get_mcp_token()
        )

    # --- Requests ---

    @mcp.tool()
    async def list_requests(
        first: int = 20,
        after: str | None = None,
    ) -> dict:
        """List service requests in Jobber.

        Args:
            first: Number of requests to return (max 50).
            after: Cursor for pagination.
        """
        query = """
        query ListRequests($first: Int!, $after: String) {
            requests(first: $first, after: $after) {
                nodes {
                    id
                    title
                    requestStatus
                    createdAt
                    client {
                        id
                        firstName
                        lastName
                    }
                    property {
                        id
                        address {
                            street1
                            city
                            province
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        variables = {"first": min(first, 50)}
        if after:
            variables["after"] = after
        return await jobber.execute_query(query, variables, _get_mcp_token())

    @mcp.tool()
    async def get_request(request_id: str) -> dict:
        """Get a specific service request by ID.

        Args:
            request_id: The Jobber request ID.
        """
        query = """
        query GetRequest($id: EncodedId!) {
            request(id: $id) {
                id
                title
                requestStatus
                instructions
                createdAt
                client {
                    id
                    firstName
                    lastName
                }
                property {
                    id
                    address {
                        street1
                        street2
                        city
                        province
                        postalCode
                        country
                    }
                }
            }
        }
        """
        return await jobber.execute_query(query, {"id": request_id}, _get_mcp_token())
