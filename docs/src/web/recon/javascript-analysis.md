---
authors: ShutdownRepo, felixbillieres
category: web
---

# JavaScript analysis

## Theory

Modern web applications rely heavily on JavaScript for client-side functionality. JavaScript analysis during reconnaissance can reveal sensitive information that should not be accessible to end users.

### What can be discovered

JavaScript files may contain:
- **Hidden API endpoints**: REST APIs, GraphQL endpoints, internal services
- **Authentication tokens**: API keys, JWT tokens, session identifiers
- **Configuration data**: Database connections, service URLs, environment variables
- **Business logic**: Application workflows, validation rules, user roles
- **Third-party integrations**: External services, analytics, tracking systems
- **Sensitive comments**: Developer notes with passwords or system information

### Where to find JavaScript files

JavaScript code can be located in:
- **Dedicated directories**: `/js/`, `/javascript/`, `/assets/js/`, `/static/js/`
- **Inline scripts**: Embedded within HTML `<script>` tags
- **External files**: Referenced via `<script src="...">` tags
- **Bundled files**: Minified and concatenated application code
- **Source maps**: Development files that map minified code to original sources

## Practice

### Endpoint discovery

JavaScript files often contain API endpoints, [GraphQL](graphql.md) queries, and internal URLs that reveal the application's attack surface.

::: tabs

=== LinkFinder

[LinkFinder](https://github.com/GerbenJavado/LinkFinder) (Python) can be used to find endpoints and their parameters in JavaScript files.

```bash
# Analyze a single JavaScript file
python3 linkfinder.py -i http://$TARGET/app.js -o cli

# Analyze all JavaScript files from a page
python3 linkfinder.py -i http://$TARGET -o cli

# Save results to HTML file
python3 linkfinder.py -i http://$TARGET -o html -r . -b "http://$TARGET" > results.html
```

=== JSFinder

[JSFinder](https://github.com/Threezh1/JSFinder) (Python) can be used to extract URLs and subdomains from JavaScript files.

```bash
# Extract URLs from JavaScript
python3 JSFinder.py -u http://$TARGET -d -ou urls.txt -os subdomains.txt
```

:::

### Secret and API key discovery

JavaScript files may contain hardcoded API keys, tokens, and other secrets that can be extracted for further testing.

::: tabs

=== SecretFinder

[SecretFinder](https://github.com/m4ll0k/SecretFinder) (Python) can be used to search for API keys, tokens, and secrets in JavaScript files.

```bash
# Search for secrets in JavaScript files
python3 SecretFinder.py -i http://$TARGET -o cli

# Use custom regex patterns
python3 SecretFinder.py -i http://$TARGET -e -o cli
```

=== JSA

[JSA](https://github.com/w9w/JSA) (Python) can be used to analyze JavaScript files for endpoints, API keys, and sensitive data.

```bash
# Analyze JavaScript files
python3 jsa.py -u http://$TARGET
```

:::

### Downloading and analyzing JavaScript files

JavaScript files can be downloaded locally for comprehensive offline analysis.

```bash
# Download all JavaScript files
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off http://$TARGET/

# Alternative with getJS
getJS -url http://$TARGET -output js_files.txt
```

Once downloaded, files can be searched for sensitive patterns:

```bash
# Search for API keys, tokens, and secrets
grep -rEi "(api_key|apikey|secret|password|token|authorization)" *.js

# Search for endpoints and URLs
grep -rEi "(\/api\/|\/v[0-9]\/|\/graphql|fetch\(|axios\.|\.ajax)" *.js

# Search for configuration and environment data
grep -rEi "(config|\.env|database|mongodb|mysql|postgresql)" *.js
```

### Deobfuscation and beautification

Minified or obfuscated JavaScript files can be made readable for manual analysis.

```bash
# Using js-beautify
js-beautify obfuscated.js > beautified.js
```

Online tools like [deobfuscate.io](https://deobfuscate.io/) can handle complex obfuscation techniques.

### Automated scanning

::: tabs

=== JSScanner

[JSScanner](https://github.com/0x240x23elu/JSScanner) (Python) automatically downloads JavaScript files and searches for endpoints and secrets.

```bash
python3 jsscanner.py -u http://$TARGET
```

=== Burp Suite extensions

Burp Suite provides extensions for JavaScript analysis:
- **JS Link Finder**: finds endpoints in JavaScript files
- **Retire.js**: detects vulnerable JavaScript libraries

Extensions can be installed via Burp Suite's BApp Store.

:::

> [!TIP]
> JavaScript analysis can be combined with [parameter fuzzing](parameter-fuzzing.md) for comprehensive web application testing.

## Resources

[LinkFinder — endpoint and parameter discovery](https://github.com/GerbenJavado/LinkFinder)

[JSFinder — URL and subdomain extraction](https://github.com/Threezh1/JSFinder)

[SecretFinder — secret and API key discovery](https://github.com/m4ll0k/SecretFinder)

[JSA — JavaScript analyzer](https://github.com/w9w/JSA)

[JSScanner — automated JavaScript scanner](https://github.com/0x240x23elu/JSScanner)

[deobfuscate.io — JavaScript deobfuscation service](https://deobfuscate.io/)

[Retire.js — vulnerable JavaScript library detection](https://retirejs.github.io/retire.js/)

[OWASP — review webpage content for information leakage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)
