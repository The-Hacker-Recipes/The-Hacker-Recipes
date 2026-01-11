---
authors: ShutdownRepo, felixbillieres
category: web
---

# GraphQL

GraphQL exposes an API through a single endpoint. During web assessments, particular attention should be given to areas that GraphQL implementations frequently leave vulnerable: **schema discovery**, **authorization issues (BOLA/IDOR)**, and **dangerous resolver inputs**.

## Quick workflow

1. Find the endpoint and confirm it behaves like GraphQL
2. Map the schema (introspection, GraphiQL/Playground, frontend queries)
3. Use the schema to generate requests
4. Test authorization and input handling on high-signal operations (object fetchers, list resolvers, write mutations)

## Find the endpoint

Common locations include `/graphql`, `/api/graphql`, `/v1/graphql` and `/query`, but guessing should be avoided:

- Frontend JS: see [JavaScript analysis](javascript-analysis.md)
- Source code leaks: see [Source code discovery](source-code-discovery.md)
- Proxy traffic: Burp "HTTP history" and "Site map"

## Confirm it is GraphQL

Universal queries work across all GraphQL implementations and confirm the endpoint:

:::: tabs

=== Burp (recommended)

- Create a POST request to the suspected endpoint
- Send it to Repeater
- Use `{"query":"query{__typename}"}` and look for `data` and/or `errors` in the response

=== CLI

```bash
curl -sS "http://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__typename}"}'
```

::::

> [!NOTE]
> Some stacks accept GET queries, but POST + JSON should be used for efficient testing unless specific requirements exist (caching, WAF behavior, logging).

## Map the schema

### Introspection (preferred)

When introspection is available, tooling should be used instead of manually crafting long queries.

:::: tabs

=== InQL (Burp)

- [InQL](https://github.com/doyensec/inql) can be installed from Burp's BApp Store
- A GraphQL request can be selected, right-clicked, and introspection can be run through InQL
- The generated schema can be used to create query/mutation templates

=== GraphQLmap

```bash
python3 graphqlmap.py -u "http://$TARGET/graphql" -i
```

::::

### When introspection is disabled

Some implementations block full introspection but allow partial queries. Incremental introspection fragments can be attempted:

- `__schema{queryType{name}}` or `__type(name:"User"){name}` can be tested
- Errors can be triggered to identify field/type names (invalid fields, wrong args)
- Operations can be extracted from the frontend (Apollo clients, bundled queries, persisted queries)
- GraphiQL/Playground interfaces should be checked (often left enabled in non-production environments)

> [!TIP]
> When one valid operation has been observed, it provides a reliable base for authorization testing.

## What to test (fast and high-signal)

### BOLA / IDOR on object access

Prioritize resolvers that fetch objects by identifier (e.g., `user(id:)`, `invoice(id:)`, `document(id:)`, `order(id:)`, `node(id:)`).

- IDs should be changed across users/tenants
- Error patterns should be compared (403 vs 404 vs empty object)
- Inconsistencies should be noted where responses return data but with redacted fields

### Over-fetching and hidden fields

Fields not displayed in the UI can be requested (e.g., `role`, `isAdmin`, `email`, `internalNotes`, `permissions`) and responses compared across different roles.

### Mutations (authz + ownership)

Mutations that update ownership or privileges should be identified (e.g., `updateUser`, `setRole`, `addMember`, `inviteUser`, `updateTenant`) and tested for:

- Missing object-level checks
- Trusting client-provided `userId` / `tenantId` / `ownerId`
- Weak “can edit self” checks that allow editing others

### Unsanitized arguments (injection/SSRF)

Resolvers often forward arguments directly to other systems without proper sanitization. Testing should include:

- **SQL/NoSQL injection**: String arguments passed to database queries
- **Command injection**: Arguments used in system commands or file operations
- **SSRF**: URL fields used in HTTP requests (`url`, `endpoint`, `webhook`)
- **Path traversal**: File/path-like arguments (`filename`, `path`, `file`)
- **Regex DoS**: Complex regex patterns in string filters
- **Pagination abuse**: Unbounded list sizes (`first`, `limit`, `offset`)

### DoS primitives (controlled testing)

> [!CAUTION]
> Deeply nested queries, large lists, and repeated fragments can overwhelm backends. Payloads should be kept controlled and testing should be coordinated when conducted in production environments.

## Useful tools

:::: tabs

=== InQL

[InQL](https://github.com/doyensec/inql) provides fast schema mapping and query generation directly within Burp.

=== GraphQLmap

[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) provides an alternative when Burp cannot be used.

=== GraphQL Cop

[GraphQL Cop](https://github.com/dolevf/GraphQL-Cop) runs common checks against a GraphQL endpoint.

```bash
python3 graphql-cop.py -t "http://$TARGET/graphql"
```

=== Graphw00f

[Graphw00f](https://github.com/dolevf/graphw00f) can fingerprint GraphQL implementations, which proves useful for identifying vendor-specific behavior.

```bash
python3 graphw00f.py -d -t "http://$TARGET/graphql"
```

::::

