---
authors: ShutdownRepo
category: web
---

# HTTP response splitting

## Theory

The HTTP protocol uses CRLF sequences to end headers, lines and so on. When input vectors are reflected in the HTTP responses, if attackers can inject CRLF sequences, they can craft an arbitrary HTTP response. For example, this could lead to reflected XSS as the attackers would have the ability to inject arbitrary HTML content in the response.

## Practice

Testers need to find input vectors that could be reflected in HTTP responses.

* GET or POST parameters (like `page`, `id`, `language`, `lang`...)
* Cookies

For example, in the following request line, the GET parameter `page` is not sanitized enough and a CRLF sequence (`%0D%0A`) can be injected.

```http
GET /index.php?question=answer%0D%0AInjection:%20Pwned%0D%0A HTTP/1.1
```

The `Injection` header is then reflected in the HTTP response, right after the legitimate `X-Custom-Question` header.

```http
HTTP/1.1 200 OK
[...]
X-Custom-Question: answer
Injection: Pwned
[...]
```

A CRLF injection vulnerable input vector can lead to HTTP response splitting that can in turn lead to

* Reflected XSS
* Redirection
* Sensitive Information Disclosure

> [!TIP]
> Headers are separated with the body by two CRLF sequences (`%0D%0A%0D%0A`).

### Reflected XSS

The following payload injects two headers and a `script` tag in the body.

```
?language=fr%0D%0AContent-Length:%2040%0D%0AContent-Type:%20text/html%0D%0A%0D%0A
```

## Resources

[https://www.netsparker.com/blog/web-security/crlf-http-header/](https://www.netsparker.com/blog/web-security/crlf-http-header/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CRLF%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CRLF%20Injection/README.md)