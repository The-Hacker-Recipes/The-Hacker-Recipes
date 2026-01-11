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

### Browser identification

Browser developer tools can identify loaded JavaScript files through the Network tab, filtering for JavaScript resources.

## Practice

### Endpoint discovery

JavaScript files often contain API endpoints, GraphQL queries, and internal URLs that reveal the application's attack surface.

::: tabs

=== LinkFinder

[LinkFinder](https://github.com/GerbenJavado/LinkFinder) finds endpoints and their parameters in JavaScript files.

```bash
# Analyze a single JavaScript file
python3 linkfinder.py -i http://$TARGET/app.js -o cli

# Analyze all JavaScript files from a page
python3 linkfinder.py -i http://$TARGET -o cli

# Save results to HTML file
python3 linkfinder.py -i http://$TARGET -o html -r . -b "http://$TARGET" > results.html
```

=== JSFinder

[JSFinder](https://github.com/Threezh1/JSFinder) extracts URLs and subdomains from JavaScript files.

```bash
# Extract URLs from JavaScript
python3 JSFinder.py -u http://$TARGET -d -ou urls.txt -os subdomains.txt
```

:::

### Secret and API key discovery

JavaScript files may contain hardcoded API keys, tokens, and other secrets that can be extracted for further testing.

::: tabs

=== SecretFinder

[SecretFinder](https://github.com/m4ll0k/SecretFinder) searches for API keys, tokens, and secrets in JavaScript files.

```bash
# Search for secrets in JavaScript files
python3 SecretFinder.py -i http://$TARGET -o cli

# Use custom regex patterns
python3 SecretFinder.py -i http://$TARGET -e -o cli
```

=== JSA

[JSA](https://github.com/w9w/JSA) analyzes JavaScript files to find endpoints, API keys, and sensitive data.

```bash
# Analyze JavaScript files
python3 jsa.py -u http://$TARGET
```

:::

### Downloading JavaScript files

For comprehensive offline analysis, JavaScript files should be downloaded locally.

```bash
# Download all JavaScript files
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off http://$TARGET/

# Alternative with getJS
getJS -url http://$TARGET -output js_files.txt
```

### GraphQL endpoint discovery

JavaScript files frequently contain GraphQL queries that reveal endpoint URLs and schema information. See [GraphQL analysis](graphql.md) for detailed techniques.

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

[JSScanner](https://github.com/0x240x23elu/JSScanner) automatically downloads JavaScript files and searches for endpoints and secrets.

```bash
# Original version (interactive mode)
python3 JSScanner.py

# Some forks support CLI flags
python3 jsscanner.py -u http://$TARGET
```

=== Burp Suite extensions

Burp Suite provides extensions for JavaScript analysis:
- **JS Link Finder**: Finds endpoints in JavaScript files
- **Retire.js**: Detects vulnerable JavaScript libraries

Extensions can be installed via Burp Suite's BApp Store.

:::

### Browser-based analysis

Modern browsers provide developer tools for interactive JavaScript analysis:

- **Sources tab**: View, debug, and format JavaScript files
- **Network tab**: Monitor JavaScript requests and responses
- **Console tab**: Execute JavaScript and inspect variables
- **Extensions**: Retire.js for vulnerable library detection, Wappalyzer for technology identification

### Common patterns to search for

JavaScript files should be analyzed for patterns indicating sensitive information:

- **API endpoints**: `/api/`, `/v1/`, `/v2/`, `/graphql`
- **Authentication tokens**: `token`, `apiKey`, `secret`, `password`, `auth`
- **URLs and domains**: `http://`, `https://`, `fetch(`, `axios.`, `$.ajax`
- **Configuration**: `config`, `settings`, `env`, `environment`
- **Sensitive functions**: `admin`, `delete`, `remove`, `update`, `create`

### Example workflow

1. Identify JavaScript files using browser developer tools
2. Download files for offline analysis using `wget` or `getJS`
3. Extract endpoints with LinkFinder or JSFinder
4. Search for secrets with SecretFinder or JSA
5. Check for GraphQL patterns and deobfuscate minified code
6. Manually review important files for business logic and sensitive comments

> [!TIP]
> JavaScript analysis frequently reveals sensitive information that should not be accessible through client-side code.

> [!SUCCESS]
> Integration with other techniques
>
> JavaScript analysis should be combined with [parameter fuzzing](parameter-fuzzing.md) and integrated with Burp Suite for comprehensive web application testing.

## Resources

### Tools
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - Endpoint and parameter discovery
- [JSFinder](https://github.com/Threezh1/JSFinder) - URL and subdomain extraction
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) - Secret and API key discovery
- [JSA](https://github.com/w9w/JSA) - JavaScript analyzer
- [JSScanner](https://github.com/0x240x23elu/JSScanner) - Automated JavaScript scanner

### Online tools
- [deobfuscate.io](https://deobfuscate.io/) - JavaScript deobfuscation service

### Browser extensions
- [Retire.js](https://retirejs.github.io/retire.js/) - Vulnerable JavaScript library detection
- [Wappalyzer](https://www.wappalyzer.com/) - Technology identification

### References
- [JavaScript Source Code Analysis](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)
- [Client-Side Data Storage](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/12-Testing_for_Client_Side_Resource_Manipulation)
