---
authors: ShutdownRepo, felixbillieres
category: web
---

# GraphQL

GraphQL is a query language and runtime for APIs that allows clients to request exactly the data they need. Unlike REST APIs, GraphQL uses a single endpoint and allows clients to specify the structure of the response.

During reconnaissance, GraphQL endpoints can reveal schema structure and available queries/mutations, field names and types, internal API structure, business logic and relationships, and potentially sensitive information through introspection. GraphQL endpoints are typically found at `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, or custom paths defined by the application.

GraphQL can be vulnerable to information disclosure through introspection, Denial of Service (DoS) through complex queries, authorization bypasses, and injection attacks (SQL, NoSQL, command injection).

## Endpoint discovery

GraphQL endpoints can be discovered through various methods:

### Common paths

```bash
# Test common GraphQL endpoint paths
curl -X POST "http://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

curl -X POST "http://target.com/api/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

curl -X POST "http://target.com/v1/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

curl -X POST "http://target.com/query" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'
```

### GET requests

Some GraphQL implementations accept queries via GET parameters:

```bash
# Try GET request with query parameter
# Note: In practice, GraphQL queries in GET requests should be URL-encoded ({ → %7B, } → %7D, etc.)
# Some servers may accept unencoded queries, but this is not reliable
curl "http://target.com/graphql?query={__schema{queryType{name}}}"

# URL-encoded version (recommended)
curl "http://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Try GET request with variables (should also be URL-encoded)
curl "http://target.com/graphql?query=query{users{id}}&variables={}"
```

> [!NOTE]
> In practice, all GraphQL GET requests shown above should be URL-encoded. Some servers may still accept raw braces, but this is not reliable across all implementations.

### JavaScript analysis

GraphQL endpoints are often hardcoded in JavaScript files:

```bash
# Search for GraphQL endpoints in JavaScript
grep -r "graphql" downloaded_js_files/
grep -r "/graphql" downloaded_js_files/
grep -r "query.*{" downloaded_js_files/
grep -r "mutation" downloaded_js_files/
```

## Automated tools

::: tabs

=== Graphw00f

[Graphw00f](https://github.com/dolevf/graphw00f) (Python) is a tool for fingerprinting and identifying GraphQL implementations.

```bash
# Fingerprint GraphQL endpoint
python3 graphw00f.py -d -t http://target.com/graphql

# Test multiple endpoints
python3 graphw00f.py -d -t http://target.com/graphql -t http://target.com/api/graphql
```

=== GraphQLmap

[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) (Python) is an interactive GraphQL security testing tool.

```bash
# Start interactive session
python3 graphqlmap.py -u http://target.com/graphql

# Execute introspection
python3 graphqlmap.py -u http://target.com/graphql -i

# Execute custom query
python3 graphqlmap.py -u http://target.com/graphql -q "{ users { id name } }"
```

=== InQL

[InQL](https://github.com/doyensec/inql) is a Burp Suite extension for GraphQL security testing.

Features:
* Automatic schema introspection
* Query generation
* Vulnerability detection
* Integration with Burp Suite

Install via Burp Suite's BApp Store and use through the context menu or active scan.

=== GraphQL Cop

[GraphQL Cop](https://github.com/dolevf/GraphQL-Cop) (Python) is a security auditing tool for GraphQL endpoints.

```bash
# Audit GraphQL endpoint
python3 graphql-cop.py -t http://target.com/graphql

# Test with authentication
python3 graphql-cop.py -t http://target.com/graphql -H "Authorization: Bearer token"
```

:::

## Introspection

GraphQL introspection allows querying the schema to understand available types, queries, and mutations. This is enabled by default in many implementations but can be disabled in production.

### Basic introspection query

```bash
# Get schema information
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'
```

### Full schema introspection

For full schema introspection, it's recommended to use automated tools (InQL, GraphQLmap, GraphQL-Cop) as they handle the complex introspection queries reliably. Manual introspection can be done with simpler queries:

```bash
# Simple introspection query (more reliable)
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# For full schema, use automated tools instead of manual complex queries
```

### Common introspection queries

```bash
# List all types
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# List all queries
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } } }"}'

# List all mutations
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name description args { name type { name } } } } } }"}'
```

## GraphiQL interface

Many GraphQL implementations expose a GraphiQL (or GraphQL Playground) interface for interactive querying. These interfaces are often found at `/graphql` (with HTML content-type), `/graphiql`, `/playground`, `/explorer`, or `/console`.

```bash
# Check for GraphiQL interface
curl http://target.com/graphql
curl http://target.com/graphiql
curl http://target.com/playground

# Look for HTML response with GraphiQL
curl -s http://target.com/graphql | grep -i "graphiql\|graphql\|playground"
```

## Identifying GraphQL implementations

Different GraphQL implementations have different characteristics:

::: tabs

=== Apollo Server

```bash
# Apollo Server often exposes /graphql endpoint
# Look for "apollo" in response headers or error messages
curl -I http://target.com/graphql | grep -i apollo
```

=== GraphQL Yoga

```bash
# GraphQL Yoga may expose /graphql endpoint
# Check for specific error messages
```

=== Hasura

```bash
# Hasura typically uses /v1/graphql
# May expose /console for admin interface
curl http://target.com/v1/graphql
curl http://target.com/console
```

:::

## Testing queries and authentication

::: tabs

=== Common queries

Once you've discovered a GraphQL endpoint, test these common queries:

```bash
# Test basic query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'

# Test introspection
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

# Test for users query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name email } }"}'

# Test for admin queries
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ admin { users { id name } } }"}'
```

=== Authentication

GraphQL endpoints may require authentication:

```bash
# Test with common authentication headers
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

# Test with API key
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "X-API-Key: key" \
  -d '{"query":"{ __schema { queryType { name } } }"}'

# Test with cookies
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Cookie: session=value" \
  -d '{"query":"{ __schema { queryType { name } } }"}'
```

=== Error messages

GraphQL error messages can reveal valuable information:

```bash
# Invalid query to trigger error
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ invalid }"}'

# Error messages may reveal:
# - GraphQL implementation (Apollo, GraphQL Yoga, etc.)
# - Stack traces
# - Internal paths
# - Database information
```

> [!NOTE]
> If you receive an error like "Introspection is not allowed" or similar, this means introspection is disabled, not that the endpoint is unusable. You can still query the API if you know the schema structure.

:::

## Example workflow

```bash
# 1. Discover GraphQL endpoint
curl -X POST http://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{ __typename }"}'

# 2. Fingerprint implementation
python3 graphw00f.py -d -t http://target.com/graphql

# 3. Test introspection
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name fields { name } } } }"}'

# 4. Use automated tool for deeper analysis
python3 graphqlmap.py -u http://target.com/graphql -i

# 5. Test for common queries
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name email } }"}'
```

> [!TIP]
> GraphQL introspection is often enabled by default in development environments. Always test for introspection even if it's disabled, as it can reveal the entire API structure.

> [!CAUTION]
> GraphQL endpoints can be vulnerable to DoS attacks through complex nested queries. Be careful when testing to avoid overwhelming the server.
