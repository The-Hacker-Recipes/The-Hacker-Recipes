---
authors: ShutdownRepo, felixbillieres
category: web
---

# Parameter fuzzing

Parameter fuzzing (also known as parameter discovery) is the process of finding hidden or undocumented HTTP parameters in web applications. These parameters may not be visible in the HTML forms or API documentation but can still be accepted by the server.

Hidden parameters can lead to unauthorized access to functionality, information disclosure, parameter pollution vulnerabilities, business logic flaws, and bypass of security controls. Parameters can be found in GET query strings (`?param=value`), POST form data, JSON request bodies, HTTP headers, and cookies.

## Manual testing

Start by identifying visible parameters and then test variations:

```bash
# Test common parameter names
curl "http://target.com/page?debug=true"
curl "http://target.com/page?test=1"
curl "http://target.com/page?admin=1"
curl "http://target.com/page?api_key=test"

# Test parameter variations
curl "http://target.com/page?id=1&format=json"
curl "http://target.com/page?id=1&callback=test"
curl "http://target.com/page?id=1&output=xml"
```

## Automated tools

::: tabs

=== Arjun

[Arjun](https://github.com/s0md3v/Arjun) (Python) is a fast HTTP parameter discovery suite that can find GET, POST, JSON, and XML parameters.

```bash
# Basic parameter discovery
arjun -u http://target.com/page

# Discover parameters with custom wordlist
arjun -u http://target.com/page -w /path/to/wordlist.txt

# Discover POST parameters
arjun -u http://target.com/page --data '{"existing":"param"}' -m POST

# Discover JSON parameters
arjun -u http://target.com/api -m POST -H 'Content-Type: application/json' --data '{}'

# Set delay between requests (useful for rate limiting)
arjun -u http://target.com/page -d 1

# Export results to file
arjun -u http://target.com/page -o results.json
```

=== ParamSpider

[ParamSpider](https://github.com/devanshbatham/ParamSpider) (Python) is a tool that finds parameters from web archive (Wayback Machine) and common crawlers.

```bash
# Discover parameters from Wayback Machine
python3 paramspider.py -d target.com

# Include subdomains
python3 paramspider.py -d target.com --subs

# Use custom output directory
python3 paramspider.py -d target.com -o /path/to/output/
```

=== ParamMiner

[ParamMiner](https://github.com/PortSwigger/param-miner) is a Burp Suite extension that can discover parameters through various techniques including Wayback Machine analysis, common parameter wordlists, and response comparison.

Install via Burp Suite's BApp Store and use through the context menu or active scan.

=== x8

[x8](https://github.com/Sh1Yo/x8) (Rust) is a fast parameter discovery tool that supports various HTTP methods and data formats.

```bash
# Discover parameters
x8 -u "http://target.com/page" -w /path/to/wordlist.txt

# Use custom HTTP method
x8 -u "http://target.com/api" -X POST -w /path/to/wordlist.txt

# Test JSON parameters
x8 -u "http://target.com/api" -X POST -H "Content-Type: application/json" -w /path/to/wordlist.txt
```

:::

## Wordlists

Common parameter wordlists can be found in:
* [SecLists](https://github.com/danielmiessler/SecLists) - `Discovery/Web-Content/burp-parameter-names.txt`
* [ParamMiner](https://github.com/PortSwigger/param-miner) - Check the repository for available wordlists
* Custom wordlists based on technology stack

```bash
# Use SecLists parameter wordlist
arjun -u http://target.com/page -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

## Response comparison

Parameter discovery relies on comparing responses. A parameter is considered "found" if the response differs from the baseline:

```bash
# Baseline request (no parameters)
curl http://target.com/page > baseline.html

# Test with parameter
curl "http://target.com/page?test=1" > test.html

# Compare responses
diff baseline.html test.html
```

Tools like Arjun automatically handle response comparison and can detect different response lengths, different status codes, different response times, and different content (using similarity algorithms).

## Testing different parameter locations

### GET parameters

```bash
arjun -u "http://target.com/page?existing=param" -m GET
```

### POST form data

```bash
arjun -u http://target.com/page -m POST --data "existing=param"
```

### JSON parameters

```bash
arjun -u http://target.com/api -m POST \
  -H "Content-Type: application/json" \
  --data '{"existing":"param"}'
```

### XML parameters

```bash
arjun -u http://target.com/api -m POST \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><root><existing>param</existing></root>'
```

### HTTP headers

Some applications accept parameters via custom headers:

```bash
# Test custom headers
curl -H "X-API-Key: test" http://target.com/api
curl -H "X-Admin: true" http://target.com/admin
```

## Common parameter patterns

Look for parameters that might indicate:
* Debug modes: `debug`, `test`, `dev`, `verbose`
* Format control: `format`, `output`, `callback`, `jsonp`
* Access control: `admin`, `role`, `privilege`, `access`
* API keys: `api_key`, `token`, `secret`, `auth`
* Pagination: `page`, `limit`, `offset`, `count`
* Filtering: `filter`, `search`, `q`, `query`

## Integration with other tools

Parameter discovery can be combined with other reconnaissance techniques:

```bash
# 1. Discover endpoints with directory fuzzing
ffuf -w wordlist.txt -u http://target.com/FUZZ

# 2. For each discovered endpoint, find parameters
for endpoint in $(cat discovered_endpoints.txt); do
    arjun -u "http://target.com$endpoint" -o "params_${endpoint//\//_}.json"
done
```

## Rate limiting considerations

Parameter fuzzing can generate many requests. Be mindful of rate limiting on the target, WAF detection and blocking, and server load.

```bash
# Use delays to avoid rate limiting
arjun -u http://target.com/page -d 0.5

# Passive mode with explicit scope
arjun -u http://target.com/page --passive target.com
```

> [!TIP]
> Parameter fuzzing is most effective when combined with other reconnaissance techniques. Always test discovered parameters for actual vulnerabilities, not just their existence.

> [!CAUTION]
> Parameter fuzzing can generate a large number of requests. Use rate limiting and delays to avoid overwhelming the target server or triggering security controls.
