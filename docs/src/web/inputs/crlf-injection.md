---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# 🛠️ CRLF injection

## Theory

CRLF represents termination of line:

* CR = Carriage Return (`\r`)
* LF = Line Feed (`\n`)

Windows and the protocol HTTP uses the CRLF however, Linux doesn't (it only uses LF). The CRLF injection is a type of attack where an attacker injects a termination of line into an application (via HTTP or URL) to provoke other types of vulnerability (HTTP Response Splitting, Log Injection...).

## Practice

### HTTP Response Splitting

#### Reconnaissance

Important: before even considering a CRLF injection, testers have to find any data that is sent in a request and reflected in the response (that follows the previous request). \
An example by [SecureFlag](https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/http_response_splitting_vulnerability.html) considers an application that in case of error (`/?error=Page+Not+found`), redirects the user using the `Location` HTTP header while reflecting the value of the `error` parameter:

```bash
# Response (due to an application error)
HTTP/1.1 301 Moved Permanently
Location: /index?error=Page+Not+Found
```

From cases similar to this one, testers have to find a place where CRLF injection is possible, such as:

* URL: `https://example.com/<CRLF_injection>`
* Query parameter: `https://example.com/lang=en<CRFL_injection>`

Upon using a CRLF injection, testers can inject arbitrary HTTP headers.

Filter bypass: one can [bypass filters](https://blog.innerht.ml/twitter-crlf-injection/) using UTF-8 encoding

* CRLF = %E5%98%8A%E5%98%8D

#### Session fixation

A good example of session fixation (with CRLF injection) comes from the CVE-2017-5868 and is explained in this [post](https://sysdream.com/news/lab/2017-05-05-cve-2017-5868-openvpn-access-server-crlf-injection-with-session-fixation/).

1. An attacker notice that the parameter `__session_start` in OpenVPN is vulnerable to CRLF injection.
2. The attacker crafts an URL by setting a cookie:

 ```
https://example.com/__session_start__/<CRLF_injection>Set-Cookie:<Cookie>[...]
 ```
3. The attacker sends this crafted URL to a victim.
4. The victim opens the URL and authenticates itself. Once authenticated, the cookie will be associated with its session.
5. The attacker can now use the cookie with the fixed session to access the victim's profile.

#### Cross-Site Scripting (XSS)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection) has an interesting payload to write a document, and therefore include an XSS.

Requested page:

```
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

HTTP response:

```
Set-Cookie:en
Content-Length: 0
​
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34
​
<html>You have been Phished</html>
```

## Resources

[https://www.acunetix.com/websitesecurity/crlf-injection/](https://www.acunetix.com/websitesecurity/crlf-injection/)

[https://www.netsparker.com/blog/web-security/crlf-http-header/](https://www.netsparker.com/blog/web-security/crlf-http-header/)

[https://owasp.org/www-community/vulnerabilities/CRLF_Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)

[https://www.srccodes.com/log-forging-by-crlf-log-injection-owasp-security-vulnerability-attacks-crlf//](https://www.srccodes.com/log-forging-by-crlf-log-injection-owasp-security-vulnerability-attacks-crlf//)

[https://sysdream.com/news/lab/2017-05-05-cve-2017-5868-openvpn-access-server-crlf-injection-with-session-fixation/](https://sysdream.com/news/lab/2017-05-05-cve-2017-5868-openvpn-access-server-crlf-injection-with-session-fixation/)

[https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/http_response_splitting_vulnerability.html](https://knowledge-base.secureflag.com/vulnerabilities/inadequate_input_validation/http_response_splitting_vulnerability.html)

[https://blog.innerht.ml/overflow-trilogy/](https://blog.innerht.ml/overflow-trilogy/)

[https://blog.innerht.ml/twitter-crlf-injection/](https://blog.innerht.ml/twitter-crlf-injection/)

[https://www.geeksforgeeks.org/crlf-injection-attack/](https://www.geeksforgeeks.org/crlf-injection-attack/)