# 🛠️ CSP (Content Security Policy)

## Theory

Content-Security-Policy (CSP) is the name of a HTTP response header that modern browsers use to enhance the security of the document (or web page). The Content-Security-Policy header allows you to restrict how resources such as JavaScript, CSS, or pretty much anything that the browser loads. It can be set as an HTTP response header or using a `<meta>` html tag. It is mainly used to protect against [Cross Site Scripting (XSS)](https://www.thehacker.recipes/web-services/attacks-on-inputs/xss-cross-site-scripting), Click Jacking attacks and Code Injection attacks.

The Content-Security-Policy if made up of directives, separated with a semicolon `;`. Here is an example :

```
content-security-policy :
    default-src 'none'
    frame-ancestors 'none'
    img-src 'self'
    script-src github.githubassets.com
    style-src 'unsafe-inline'
```

You can find the detail of these directives as well as their browser compatibilities here : [https://content-security-policy.com/](https://content-security-policy.com/)

## Practice

The CSP can be audited with Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/).

If the CSP is weak, there are a few techniques to bypass it.

### Dangling markup injection

Dangling markup injection is a technique that can be used to capture data cross-domain in situations where a full [Cross Site Scripting (XSS)](https://www.thehacker.recipes/web-services/attacks-on-inputs/xss-cross-site-scripting) exploit is not possible, due to input filters or other defenses. It can often be exploited to capture sensitive information that is visible to other users, including CSRF tokens that can be used to perform unauthorized actions on behalf of the user.

A lot of useful payloads can be found here :

* [https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)
* [https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)

### JS/JSON/JSONP injections

JSONP hijacking or unexploitable injection of content into JavaScript or JSON and can also help. For example, if there is no function name validation in JSONP, you can replace the called function with arbitrary JS code.

Here is a list of various JSONP endpoints that can be used to perform code injections :

* [https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/jsonp\_endpoint.txt](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/jsonp\_endpoint.txt)
