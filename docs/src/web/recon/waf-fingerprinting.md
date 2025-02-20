---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# Web Application Firewall (WAF)

## Theory

Many web applications stand behind a WAF (Web Application Firewall) that aim the protecting app from different types of attacks ([XSS](../../web/inputs/xss.md), [SQLi](../../web/inputs/sqli.md), etc.) by monitoring and filtering requests. Identifying if a WAF is used, and if so what type it is, can help bypass known filters.

## Practice

This can be done with tools like [WAFW00F](https://github.com/EnableSecurity/wafw00f) (Python), [WhatWaf](https://github.com/Ekultek/WhatWaf) (Python) or [nmap](https://nmap.org) or sometimes by manually looking at cookies and HTTP response headers.

```bash
wafw00f $URL
whatwaf -u $URL
nmap -p $PORT --script=http-waf-fingerprint,http-waf-detect $URL
```