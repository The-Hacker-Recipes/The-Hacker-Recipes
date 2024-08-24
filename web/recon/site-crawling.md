# Site crawling

## Theory

When requesting a web application, the server usually sends code (in HTML, CSS, Javascript, ...) in the response. This code is then rendered by the web browser. Each page contains links to other pages of the web app and resources needed by the browser to improve the render.

Crawling is a technique used to recursively follow those links and build the indexed website architecture. This architecture sometimes contains interesting links (admin log-in pages, API...) testers can focus on.

## Practice

Tools like [hakrawler](https://github.com/hakluke/hakrawler) (Go), [scrapy](https://scrapy.org/) (Python) and [spidy](https://github.com/rivermont/spidy) (Python), and many other tools can be used for that purpose.

<pre class="language-bash"><code class="lang-bash"><strong>echo $URL | hakrawler -d 10</strong></code></pre>

**Burp Suite**'s graphical interface is a great alternative (`Dashboard > New scan (Crawl)` then `Target`).

Once the crawling is over, testers need to inspect the website architecture and look for admin paths, unusual redirections and anything that could lead to a potential vulnerability.
