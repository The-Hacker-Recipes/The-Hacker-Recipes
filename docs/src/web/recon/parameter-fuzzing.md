---
authors: ShutdownRepo, felixbillieres
category: web
---

# Parameter fuzzing

## Theory

Parameter fuzzing involves discovering hidden or undocumented HTTP parameters that may not appear in forms or API documentation but are accepted by the server. These parameters can reveal additional attack surface and lead to security vulnerabilities.

### What can be discovered

Hidden parameters may enable:
- **Unauthorized access**: Bypassing authentication or authorization checks
- **Information disclosure**: Revealing sensitive data or system information
- **Parameter pollution**: Manipulating application behavior through multiple parameter values
- **Business logic flaws**: Circumventing intended application workflows
- **Security control bypass**: Evading input validation or rate limiting

### Parameter locations

Parameters can exist in various HTTP components:
- **GET parameters**: URL query strings (`?param=value`)
- **POST data**: Form submissions, JSON payloads, XML data
- **HTTP headers**: Custom headers, cookies, and other header fields
- **Other locations**: URL paths, fragments, and non-standard fields

### Response analysis

Parameter discovery relies on comparing server responses to identify accepted parameters. Tools detect differences in:
- Response length and content
- HTTP status codes
- Response timing
- Content similarity scores

## Practice

### Automated tools

::: tabs

=== Arjun

[Arjun](https://github.com/s0md3v/Arjun) provides fast parameter discovery across GET, POST, JSON, and XML formats.

```bash
# Basic parameter discovery
arjun -u http://$TARGET/page

# Discover parameters with custom wordlist
arjun -u http://$TARGET/page -w /path/to/wordlist.txt

# Discover POST parameters
arjun -u http://$TARGET/page --data '{"existing":"param"}' -m POST

# Discover JSON parameters
arjun -u http://$TARGET/api -m POST -H 'Content-Type: application/json' --data '{}'

# Set delay between requests
arjun -u http://$TARGET/page -d 1

# Export results to file
arjun -u http://$TARGET/page -o results.json
```

=== ParamSpider

[ParamSpider](https://github.com/devanshbatham/ParamSpider) discovers parameters from web archives and crawler data.

```bash
# Discover parameters from Wayback Machine
python3 paramspider.py -d $TARGET

# Include subdomains
python3 paramspider.py -d $TARGET --subs

# Use custom output directory
python3 paramspider.py -d $TARGET -o /path/to/output/
```

=== ParamMiner

[ParamMiner](https://github.com/PortSwigger/param-miner) is a Burp Suite extension for comprehensive parameter discovery.

Installation occurs via Burp Suite's BApp Store. The extension can be used through the context menu or active scanning features.

=== x8

[x8](https://github.com/Sh1Yo/x8) provides fast parameter discovery with support for various HTTP methods.

```bash
# Discover parameters
x8 -u "http://$TARGET/page" -w /path/to/wordlist.txt

# Use custom HTTP method
x8 -u "http://$TARGET/api" -X POST -w /path/to/wordlist.txt

# Test JSON parameters
x8 -u "http://$TARGET/api" -X POST -H "Content-Type: application/json" -w /path/to/wordlist.txt
```

:::

### Wordlists

Effective parameter discovery requires comprehensive wordlists containing common parameter names and patterns.

- [SecLists](https://github.com/danielmiessler/SecLists) provides `Discovery/Web-Content/burp-parameter-names.txt`
- Technology-specific wordlists should be created based on framework documentation
- Custom wordlists can be built from observed application patterns

### Parameter locations testing

Parameters should be tested across different HTTP locations to maximize coverage.

#### GET parameters
```bash
arjun -u "http://$TARGET/page?existing=param" -m GET
```

#### POST data
```bash
arjun -u http://$TARGET/page -m POST --data "existing=param"
```

#### JSON payloads
```bash
arjun -u http://$TARGET/api -m POST \
  -H "Content-Type: application/json" \
  --data '{"existing":"param"}'
```

#### HTTP headers
```bash
# Test custom headers
curl -H "X-API-Key: test" http://$TARGET/api
curl -H "X-Admin: true" http://$TARGET/admin
```

### Common parameter patterns

Testing should focus on parameters that commonly indicate security-relevant functionality:

- **Debug modes**: `debug`, `test`, `dev`, `verbose`
- **Format control**: `format`, `output`, `callback`, `jsonp`
- **Access control**: `admin`, `role`, `privilege`, `access`
- **API keys**: `api_key`, `token`, `secret`, `auth`
- **Pagination**: `page`, `limit`, `offset`, `count`
- **Filtering**: `filter`, `search`, `q`, `query`

### Integration with other techniques

Parameter discovery should be combined with endpoint enumeration workflows.

```bash
# 1. Discover endpoints with directory fuzzing
ffuf -w wordlist.txt -u http://$TARGET/FUZZ

# 2. For each discovered endpoint, enumerate parameters
while IFS= read -r endpoint; do
    arjun -u "http://$TARGET$endpoint" -o "params_${endpoint//\//_}.json"
done < discovered_endpoints.txt
```

### Rate limiting considerations

Parameter fuzzing generates significant request volumes that may trigger security controls.

```bash
# Use delays to avoid detection
arjun -u http://$TARGET/page -d 0.5

# Passive discovery mode
arjun -u http://$TARGET/page --passive $TARGET
```

> [!TIP]
> Discovered parameters should be tested for actual vulnerabilities, not just their existence.

> [!CAUTION]
> Large request volumes can overwhelm servers or trigger security controls. Rate limiting should be implemented.

## Resources

### Tools
- [Arjun](https://github.com/s0md3v/Arjun) - Multi-format parameter discovery
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Archive-based parameter discovery
- [ParamMiner](https://github.com/PortSwigger/param-miner) - Burp Suite extension
- [x8](https://github.com/Sh1Yo/x8) - Fast parameter enumeration

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) - `Discovery/Web-Content/burp-parameter-names.txt`

### References
- [Parameter Discovery Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Methods)
