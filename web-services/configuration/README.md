# Configuration

## Theory

HTTP security headers are used to inform a client \(browser\), how to behave when handling a website's content. These headers are important in preventing the exploitation of vulnerabilities such as XSS, Man-in-the-Middle, Clickjacking, etc.

### Strict-Transport-Security \(STS\)

Websites can tell browsers to use HTTPS instead of HTTP. It ensures that when a user load a site using HTTP, an automatic redirection is made to HTTPS \(which protects the data transmitted with TLS\).

{% hint style="warning" %}
A simple redirection is not enough to prevent Man-in-the-Middle attacks, therefore STS should be used.
{% endhint %}

#### Directives

[MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security):

`max-age=<expire-time>`

> The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS.

Developers have to make sure to set the `max-age` to 1 year at least.

{% hint style="warning" %}
Before deciding on the max-age, developers have to make sure that enforcing the use of HTTPS won't cause an issue \(like blocking access to pages only accessible via HTTP\).
{% endhint %}

`includeSubDomains` \(optional\)

> If this optional parameter is specified, this rule applies to all of the site's subdomains as well.

If the subdomains use or will use HTTPS, this directive can be useful.

`preload`\(optional\)

> See [Preloading Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security#preloading_strict_transport_security) for details. Not part of the specification.

{% hint style="warning" %}
If the end goal is to use the `preload` directive, make sure to [read the recommendations](https://hstspreload.org/) first.
{% endhint %}

### X-Frame-Options \(XFO\)

Indicates a browser if it render a page using the following HTML elements: &lt;frame&gt;, &lt;iframe&gt;, &lt;embed&gt; and &lt;object&gt;. Using XFO mitigates click-jacking attacks.

#### Directives

[MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options):

`DENY`

> The page cannot be displayed in a frame, regardless of the site attempting to do so.

`SAMEORIGIN`

> The page can only be displayed in a frame on the same origin as the page itself. \[...\]

`ALLOW-FROM uri`

{% hint style="warning" %}
This directive is obsolete and no longer works on modern browsers.
{% endhint %}

### X-Content-Type-Options

Mime sniffing can be prevented using this header by forcing the browser to follow the value from the `Content-Type` header.

#### Directive

[MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options):

`nosniff`

> Blocks a request if the request destination is of type `style` and the MIME type is not `text/css`, or of type `script` and the MIME type is not a [JavaScript MIME type](https://html.spec.whatwg.org/multipage/scripting.html#javascript-mime-type).

### Cross-Origin Resource Sharing \(CORS\)

When loading resources from another origin, CORS helps in applying different protection measures.

Misconfigurations are common with CORS, check the following page for more information.

### Content-Security-Policy \(CSP\)

CSP prevents XSS and click-jacking attacks by controlling which resources a user-agent is allowed to load.

#### Directives

A plethora of directives exist for CSP, not all of them will be covered here. It's important to use them with care and with a purpose in mind. Some important configurations/misconfigurations will be listed below.

`default-src`

This directive acts as a [fallback](https://content-security-policy.com/default-src/) for the other CSP fetch directives. If it's not present, CSP will permit loading resources of any origins.

`unsafe-inline`

This directive allows the execution of third-party JavaScript inline.

`unsafe-eval`

Allows unsafe evaluation code such as `eval()` for JavaScript.

### X-XSS-Protection

This header is now deprecated, only old browsers may use it. It's [debated](https://github.com/OWASP/CheatSheetSeries/issues/376) whether it's actually safe or not to use it. More harm can be done using X-XSS-Protection. Other methods can be used to prevent XSS attacks \(escaping, sanitization...\).

X-XSS-Protection should not be used or set to 0.

## Practice

Manual checking can be done using `curl`.

```text
curl --head $WEBSITE
```

### Tools

#### Cross-Origin Resource Sharing \(CORS\)️

[CORScanner](https://github.com/chenjj/CORScanner) gives you information about CORS misconfigurations.

#### Content-Security-Policy \(CSP\)

[csp-evaluator](https://csp-evaluator.withgoogle.com/) is a quick and easy-to-use tool \(on browsers\). Past in the CSP configuration you want to check, and it will evaluate it. 

{% hint style="info" %}
A list of CSP bypass can be found [here](https://0xn3va.gitbook.io/cheat-sheets/web-application/content-security-policy#allowed-data-scheme).
{% endhint %}

## References

{% embed url="https://github.com/koenbuyens/securityheaders\#http-strict-transport-security" %}

{% embed url="https://cheatsheetseries.owasp.org/" %}

{% embed url="https://developer.mozilla.org/en-US/" %}

