---
authors: ShutdownRepo, felixbillieres
category: web
---

# JavaScript analysis

## Theory

Modern web applications heavily rely on JavaScript for client-side functionality. Analyzing JavaScript files can reveal valuable information during reconnaissance:

* Hidden API endpoints and routes
* API keys and authentication tokens
* Sensitive configuration data
* Internal URLs and domains
* Function names and business logic
* Third-party service integrations
* Comments with sensitive information

JavaScript files are typically found in:
* `/js/`, `/javascript/`, `/assets/js/`
* Inline JavaScript within HTML pages
* External JavaScript libraries and frameworks
* Minified and obfuscated JavaScript files

## Practice

### Manual analysis

Start by identifying all JavaScript files loaded by the application:

```bash
# Extract JavaScript file URLs from HTML
curl -s http://target.com | grep -oP 'src="[^"]*\.js[^"]*"' | cut -d'"' -f2

# Or use browser developer tools (F12 > Network > JS filter)
```

### Endpoint discovery

JavaScript files often contain API endpoints, GraphQL queries, and internal URLs.

#### LinkFinder

[LinkFinder](https://github.com/GerbenJavado/LinkFinder) (Python) is a tool that finds endpoints and their parameters in JavaScript files.

```bash
# Analyze a single JavaScript file
python3 linkfinder.py -i http://target.com/app.js -o cli

# Analyze all JavaScript files from a page
python3 linkfinder.py -i http://target.com -o cli

# Save results to file
python3 linkfinder.py -i http://target.com -o cli -o results.txt
```

#### JSFinder

[JSFinder](https://github.com/Threezh1/JSFinder) (Python) is another tool for extracting URLs and subdomains from JavaScript files.

```bash
# Extract URLs from JavaScript
python3 JSFinder.py -u http://target.com -d -ou urls.txt -os subdomains.txt
```

### Secret and API key discovery

JavaScript files may contain hardcoded API keys, tokens, and other secrets.

#### SecretFinder

[SecretFinder](https://github.com/m4ll0k/SecretFinder) (Python) searches for API keys, tokens, and secrets in JavaScript files.

```bash
# Search for secrets in JavaScript files
python3 SecretFinder.py -i http://target.com -o cli

# Use custom regex patterns
python3 SecretFinder.py -i http://target.com -e -o cli
```

#### JSA (JavaScript Analyzer)

[JSA](https://github.com/w9w/JSA) is a tool for analyzing JavaScript files to find endpoints, API keys, and sensitive data.

```bash
# Analyze JavaScript files
python3 jsa.py -u http://target.com
```

### GraphQL endpoint discovery

JavaScript files often contain GraphQL queries that reveal endpoint URLs and schema information.

```bash
# Search for GraphQL endpoints in JavaScript
grep -r "graphql" downloaded_js_files/
grep -r "/graphql" downloaded_js_files/
grep -r "query.*{" downloaded_js_files/
```

### Downloading and analyzing JavaScript files

```bash
# Download all JavaScript files from a website
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off http://target.com/

# Or use a tool like getjs
getjs --url http://target.com --output js_files/
```

### Deobfuscation and beautification

Many JavaScript files are minified or obfuscated. Tools can help make them readable:

```bash
# Using js-beautify
js-beautify obfuscated.js > beautified.js
```

* [deobfuscate.io](https://deobfuscate.io/) is a powerful online JavaScript deobfuscator that can remove common obfuscation techniques including:
  * Array unpacking
  * Proxy function replacement
  * Expression simplification
  * Dead branch removal
  * String operation reversal
  * Property simplification

* Browser developer tools can also format JavaScript: Right-click in the Sources tab > Format

* Command-line tools like `js-beautify` can format minified code

### Automated scanning

#### JSScanner

[JSScanner](https://github.com/0x240x23elu/JSScanner) is an automated tool that downloads JavaScript files and searches for endpoints and secrets.

```bash
# Scan a website for JavaScript files
python3 jsscanner.py -u http://target.com
```

#### Burp Suite extensions

Burp Suite has extensions that can automatically analyze JavaScript:
* **JS Link Finder**: Finds endpoints in JavaScript files
* **Retire.js**: Detects vulnerable JavaScript libraries

### Common patterns to search for

When analyzing JavaScript files, look for these patterns:

```javascript
// API endpoints
/api/, /v1/, /v2/, /graphql

// Authentication tokens
token, apiKey, secret, password, auth

// URLs and domains
http://, https://, fetch(, axios., $.ajax

// Configuration
config, settings, env, environment

// Sensitive functions
admin, delete, remove, update, create
```

### Browser-based analysis

Modern browsers provide powerful tools for JavaScript analysis:

1. **Developer Tools (F12)**:
   * Sources tab: View all JavaScript files
   * Network tab: Monitor JavaScript requests
   * Console tab: Execute JavaScript and inspect variables

2. **Extensions**:
   * **Retire.js**: Detects vulnerable JavaScript libraries
   * **Wappalyzer**: Identifies technologies including JavaScript frameworks

### Example workflow

```bash
# 1. Download all JavaScript files
wget -r -l1 -H -t1 -nd -N -np -A.js -erobots=off http://target.com/

# 2. Extract endpoints
python3 linkfinder.py -i ./downloaded_js/*.js -o cli

# 3. Search for secrets
python3 SecretFinder.py -i ./downloaded_js/ -o cli

# 4. Search for GraphQL
grep -r "graphql" ./downloaded_js/

# 5. Analyze manually for business logic
cat important_file.js | less
```

## Resources

[https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)

[https://github.com/Threezh1/JSFinder](https://github.com/Threezh1/JSFinder)

[https://github.com/m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder)

[https://deobfuscate.io/](https://deobfuscate.io/)

