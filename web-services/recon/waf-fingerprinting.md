# 🛠️ WAF fingerprinting

## Theory

WAF stands for Web Application Firewall. Its goal is to protect the website behind it by filtering/monitoring the traffic. Fingerprinting is a method used to gather information \(about any WAF in this context\).

## Practice

### Tools

Detecting WAFs with [WAFW00F](https://github.com/EnableSecurity/wafw00f).

```bash
wafw00f $URL
```

Detecting WAFs with [WhatWaf](https://github.com/Ekultek/WhatWaf).

```bash
whatwaf -u $URL
```

Detecting WAFs with [nmap](https://nmap.org/).

```bash
nmap -p 80,443 --script=http-waf-fingerprint $URL
```

{% hint style="info" %}
We could also use another script called `http-waf-detect`. It detects IDS/IPS/WAF but doesn't give us information about the vendor, or version...
{% endhint %}

### Other examples

A manual testing workflow could be to check the cookies and response headers.

**Cookies**: some WAF can be identified by the cookie's name.  
**Response headers**: sometimes they are changed to apparently "confuse the attacker".

## References

{% embed url="https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html" %}

