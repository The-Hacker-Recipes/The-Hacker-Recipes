---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# Other technologies

## Theory

A web application usually relies on multiple components which compose the attack surface among which the potential elements:

* the web server (e.g. Apache, Nginx, Microsoft IIS)
* a [Content Management System (CMS)](cms.md)
* JavaScript Frameworks
* ...

When conducting an audit of a web app, identifying those technologies and the versions in use is necessary to conduct a thorough reconnaissance and correctly map the attack surface.

## Practice

Those technologies can usually be identified from the different elements:

* Credits at the bottom or corner of pages
* HTTP headers
* Common files (e.g. `robots.txt`, `sitemap.xml`)
* Comments and metadata (HTML, CSS, JavaScript)
* Stack traces and verbose error messages

Automated scanning tools can also help identify which technologies are used.

* [WhatWeb](https://github.com/urbanadventurer/WhatWeb) (Ruby) recognizes web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1800 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
* [Wappalyzer](https://www.wappalyzer.com/) is a browser extension that can detect the use of certain software including CMS