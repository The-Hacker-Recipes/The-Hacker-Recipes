---
authors: ShutdownRepo, felixbillieres
category: web
---

# Parameter fuzzing

Parameter fuzzing involves discovering hidden or undocumented HTTP parameters that may not appear in forms or API documentation but are accepted by the server. These parameters can lead to unauthorized access, information disclosure, parameter pollution, business logic flaws, and security control bypass.

Parameters can exist in GET queries, POST data, JSON bodies, HTTP headers, and cookies.

## Automated tools

::: tabs

=== Arjun

[Arjun](https://github.com/s0md3v/Arjun) (Python) is a fast HTTP parameter discovery suite that can find GET, POST, JSON, and XML parameters.

```bash
# Basic parameter discovery
arjun -u http://$TARGET/page

# Discover parameters with custom wordlist
arjun -u http://$TARGET/page -w /path/to/wordlist.txt

# Discover POST parameters
arjun -u http://$TARGET/page --data '{"existing":"param"}' -m POST

# Discover JSON parameters
arjun -u http://$TARGET/api -m POST -H 'Content-Type: application/json' --data '{}'

# Set delay between requests (useful for rate limiting)
arjun -u http://$TARGET/page -d 1

# Export results to file
arjun -u http://$TARGET/page -o results.json
```

=== ParamSpider

[ParamSpider](https://github.com/devanshbatham/ParamSpider) (Python) is a tool that finds parameters from web archive (Wayback Machine) and common crawlers.

```bash
# Discover parameters from Wayback Machine
python3 paramspider.py -d $TARGET

# Include subdomains
python3 paramspider.py -d $TARGET --subs

# Use custom output directory
python3 paramspider.py -d $TARGET -o /path/to/output/
```

=== ParamMiner

[ParamMiner](https://github.com/PortSwigger/param-miner) is a Burp Suite extension that can discover parameters through various techniques including Wayback Machine analysis, common parameter wordlists, and response comparison.

Install via Burp Suite's BApp Store and use through the context menu or active scan.

=== x8

[x8](https://github.com/Sh1Yo/x8) (Rust) is a fast parameter discovery tool that supports various HTTP methods and data formats.

```bash
# Discover parameters
x8 -u "http://$TARGET/page" -w /path/to/wordlist.txt

# Use custom HTTP method
x8 -u "http://$TARGET/api" -X POST -w /path/to/wordlist.txt

# Test JSON parameters
x8 -u "http://$TARGET/api" -X POST -H "Content-Type: application/json" -w /path/to/wordlist.txt
```

:::

## Wordlists

Parameter wordlists should include common patterns from [SecLists](https://github.com/danielmiessler/SecLists) (`Discovery/Web-Content/burp-parameter-names.txt`) and technology-specific terms.

Parameter discovery relies on response comparison. Tools automatically detect differences in response length, status codes, timing, and content similarity.

## Parameter locations

Parameters can be tested in different HTTP locations:

- **GET parameters**: Query string parameters
- **POST data**: Form data, JSON bodies, XML payloads
- **HTTP headers**: Custom headers like `X-API-Key`, `X-Admin`

Tools like Arjun and x8 support all these locations.

## Common parameter patterns

Common parameter patterns include:

- Debug modes: `debug`, `test`, `dev`, `verbose`
- Format control: `format`, `output`, `callback`, `jsonp`
- Access control: `admin`, `role`, `privilege`, `access`
- API keys: `api_key`, `token`, `secret`, `auth`
- Pagination: `page`, `limit`, `offset`, `count`
- Filtering: `filter`, `search`, `q`, `query`

## Integration with other tools

Parameter discovery should be combined with endpoint discovery techniques. For each discovered endpoint, parameters can be enumerated using tools like Arjun.

## Rate limiting considerations

Parameter fuzzing generates numerous requests. Delays should be used to avoid rate limiting, WAF detection, and server overload.

> [!TIP]
> Discovered parameters should be tested for actual vulnerabilities, not just existence.

> [!CAUTION]
> Large request volumes can overwhelm servers or trigger security controls. Rate limiting should be implemented.
