# 🛠️ Web technologies

## Theory

Web technologies are a set of components surrounding a web application. These components could be web servers, CMS, JS frameworks, etc.

The main goal is to find these components and their version. It can be taken advantage of to search for vulnerabilities to exploit.

Aside from using tools to uncover the specific technologies used, another way would be to check for error stack traces, error code, and so on. Applications \(web apps, web servers, databases, etc.\) would generate error pages that could disclose information about the technology used.

## Practice

### Tools

Recognizing web technologies with [WhatWeb](https://github.com/urbanadventurer/WhatWeb).

```bash
whatweb $URL
```

{% hint style="info" %}
It is possible with this tool to customize the aggression level or increase performance and stability.
{% endhint %}

Another way to find the web technologies used is [Wappalyzer](https://www.wappalyzer.com/) which can be used as an extension on Firefox, Chrome, Safari, etc.

### Error handling

In addition to the previous techniques \(using WhatWeb and Wappalyzer\), it is possible to check for error handling manually:

* Requesting a 404 error page can be done by requesting incorrect URLs.
* Requesting a 403 forbidden page.
* Trying to generate login errors using different methods:
  * Empty and wrong credentials.
  * SQL injection \(the database behind may send an error\).
* Check for other [HTTP error codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) \(4xx\).

