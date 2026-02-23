---
authors: ShutdownRepo, felixbillieres
category: web
---

# Site crawling

## Theory

Web applications contain links between pages, references to resources, and API endpoints embedded in HTML and JavaScript code. Crawling is a technique that recursively follows these links to build a comprehensive map of the application's structure. This map often reveals paths not visible through normal browsing: admin panels, API endpoints, forgotten pages, and development artifacts.

### JavaScript rendering

Modern web applications (SPAs built with React, Angular, Vue.js) load content dynamically through JavaScript. Traditional crawlers that only parse static HTML miss these dynamically generated links. JavaScript-aware crawlers use headless browsers to render pages and discover additional endpoints, at the cost of slower performance.

## Practice

### Crawling tools

::: tabs

=== katana

[katana](https://github.com/projectdiscovery/katana) (Go) can be used for comprehensive web crawling with JavaScript rendering support.

```bash
# Basic crawl
katana -u http://$TARGET -d 5

# JavaScript-aware crawling
katana -u http://$TARGET -d 5 -jc

# Headless browser crawling (renders JavaScript)
katana -u http://$TARGET -d 5 -hl

# Include known files (robots.txt, sitemap.xml)
katana -u http://$TARGET -d 5 -jc -kf all

# Output to file with rate limiting
katana -u http://$TARGET -d 5 -jc -o urls.txt -rl 100

# Crawl through a proxy (Burp Suite integration)
katana -u http://$TARGET -d 5 -proxy http://127.0.0.1:8080
```

=== hakrawler

[hakrawler](https://github.com/hakluke/hakrawler) (Go) can be used for fast, simple crawling via stdin.

```bash
# Basic crawl
echo "http://$TARGET" | hakrawler -d 3

# Include subdomains
echo "http://$TARGET" | hakrawler -d 3 -subs

# Show unique URLs only
echo "http://$TARGET" | hakrawler -d 3 -u
```

=== gospider

[gospider](https://github.com/jaeles-project/gospider) (Go) can be used for concurrent web crawling with JavaScript parsing.

```bash
# Basic crawl
gospider -s http://$TARGET -d 3

# With JavaScript parsing, sitemap, and robots.txt
gospider -s http://$TARGET -d 3 --js --sitemap --robots

# Concurrent crawling with output
gospider -s http://$TARGET -d 3 -c 10 -t 5 -o output/
```

:::

Burp Suite's built-in crawler provides an alternative through its graphical interface (`Dashboard > New scan (Crawl)` then `Target`).

> [!TIP]
> Headless crawling (`katana -hl`) is significantly slower but essential for JavaScript-heavy applications where traditional crawling misses dynamically loaded content.

> [!CAUTION]
> Aggressive crawling (high depth, no rate limiting) can overwhelm web servers or trigger security controls. Rate limiting should be configured for production targets.

Once the crawling is complete, the collected URLs should be inspected for admin paths, API endpoints, unusual redirections, and anything that could reveal additional attack surface.

## Resources

[katana — next-generation web crawling framework](https://github.com/projectdiscovery/katana)

[hakrawler — fast web crawler for gathering URLs](https://github.com/hakluke/hakrawler)

[gospider — concurrent web spider with JavaScript support](https://github.com/jaeles-project/gospider)
