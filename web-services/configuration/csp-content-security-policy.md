# 🛠️ CSP \(Content Security Policy\)

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

