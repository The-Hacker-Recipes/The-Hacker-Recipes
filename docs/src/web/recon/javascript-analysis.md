---
authors: ShutdownRepo, felixbillieres
category: web
---

# JavaScript analysis

Modern web applications rely heavily on JavaScript for client-side functionality. JavaScript analysis during reconnaissance can reveal hidden API endpoints, authentication tokens, configuration data, internal URLs, business logic, third-party integrations, and sensitive comments.

JavaScript files are typically located in `/js/`, `/javascript/`, `/assets/js/`, or embedded within HTML pages. Browser developer tools can be used to identify loaded JavaScript files through the Network tab.

## Endpoint discovery

JavaScript files often contain API endpoints, GraphQL queries, and internal URLs.

::: tabs

=== LinkFinder

[LinkFinder](https://github.com/GerbenJavado/LinkFinder) (Python) is a tool that finds endpoints and their parameters in JavaScript files.

```bash
# Analyze a single JavaScript file (CLI output)
python3 linkfinder.py -i http://$TARGET/app.js -o cli

# Analyze all JavaScript files from a page (CLI output)
python3 linkfinder.py -i http://$TARGET -o cli

# Save results to HTML file (redirect output)
python3 linkfinder.py -i http://$TARGET -o html -r . -b "http://$TARGET" > results.html
```

=== JSFinder

[JSFinder](https://github.com/Threezh1/JSFinder) (Python) is another tool for extracting URLs and subdomains from JavaScript files.

```bash
# Extract URLs from JavaScript
python3 JSFinder.py -u http://$TARGET -d -ou urls.txt -os subdomains.txt
```

:::

## Secret and API key discovery

JavaScript files may contain hardcoded API keys, tokens, and other secrets.

::: tabs

=== SecretFinder

[SecretFinder](https://github.com/m4ll0k/SecretFinder) (Python) searches for API keys, tokens, and secrets in JavaScript files.

```bash
# Search for secrets in JavaScript files
python3 SecretFinder.py -i http://$TARGET -o cli

# Use custom regex patterns
python3 SecretFinder.py -i http://$TARGET -e -o cli
```

=== JSA

[JSA](https://github.com/w9w/JSA) (JavaScript Analyzer) is a tool for analyzing JavaScript files to find endpoints, API keys, and sensitive data.

```bash
# Analyze JavaScript files
python3 jsa.py -u http://$TARGET
```

:::

## Downloading JavaScript files

JavaScript files should be downloaded for offline analysis. Tools like `wget` or `getJS` can be used to retrieve all JavaScript files from a target website.

## GraphQL endpoint discovery

JavaScript files frequently contain GraphQL queries that reveal endpoint URLs and schema information. See [GraphQL analysis](graphql.md) for detailed techniques.

## Deobfuscation and beautification

Minified or obfuscated JavaScript files can be made readable using tools like `js-beautify` or [deobfuscate.io](https://deobfuscate.io/). Browser developer tools can also format JavaScript through the Sources tab.

## Automated scanning

::: tabs

=== JSScanner

[JSScanner](https://github.com/0x240x23elu/JSScanner) is an automated tool that downloads JavaScript files and searches for endpoints and secrets. The original version runs in interactive mode, while some forks add CLI flags.

```bash
# Original version (interactive mode)
python3 JSScanner.py

# Some forks support CLI flags
python3 jsscanner.py -u http://$TARGET
```

=== Burp Suite extensions

Burp Suite has extensions that can automatically analyze JavaScript:
* **JS Link Finder**: Finds endpoints in JavaScript files
* **Retire.js**: Detects vulnerable JavaScript libraries

Install via Burp Suite's BApp Store and use through the context menu or active scan.

:::

## Common patterns to search for

JavaScript files should be analyzed for patterns indicating sensitive information:

- API endpoints: `/api/`, `/v1/`, `/v2/`, `/graphql`
- Authentication tokens: `token`, `apiKey`, `secret`, `password`, `auth`
- URLs and domains: `http://`, `https://`, `fetch(`, `axios.`, `$.ajax`
- Configuration: `config`, `settings`, `env`, `environment`
- Sensitive functions: `admin`, `delete`, `remove`, `update`, `create`

## Browser-based analysis

Modern browsers provide developer tools for JavaScript analysis:

- **Sources tab**: View and debug JavaScript files
- **Network tab**: Monitor JavaScript requests and responses
- **Console tab**: Execute JavaScript and inspect variables
- **Extensions**: Retire.js for vulnerable library detection, Wappalyzer for technology identification

## Example workflow

1. Download JavaScript files using `wget` or `getJS`
2. Extract endpoints with LinkFinder or JSFinder
3. Search for secrets with SecretFinder or JSA
4. Check for GraphQL patterns
5. Manually review important files for business logic

> [!TIP]
> JavaScript analysis frequently reveals sensitive information that should not be accessible through client-side code.

JavaScript analysis should be combined with [parameter fuzzing](parameter-fuzzing.md) and integrated with Burp Suite for comprehensive web application testing.
