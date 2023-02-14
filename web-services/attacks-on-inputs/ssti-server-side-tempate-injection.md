# 🛠️ SSTI (Server-Side Template Injection)

## Theory

Some web applications rely on template engines to offer dynamic content. When user inputs are embedded in templates, without proper sensitization, the web apps can be vulnerable to SSTIs (Server-Side Template Injections). This is a critical vulnerability that can sometimes lead to Sensitive Information Disclosure, Local File Disclosure and even RCE (Remote Code Execution).

## 🛠️ Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that might be embedded in templates.

The following payload is used for testing [SQL injections](../../web/inputs/sqli.md), [XSS (Cross-Site Scripting)](../../web/inputs/xss.md) and SSTI (Server-Side Template Injection). The `{{7*7}}` should be interpreted and changed to `49` by Jinja2 and Twig engines.

```
'"<svg/onload=prompt(5);>{{7*7}}
```

The following injection methodology can be used to identify the template engine. Is the content modified?

Depending on the template engine in use, testers will be able to fully exploit the SSTI vulnerability.

{% hint style="info" %}
Many template engines offer a sandboxed mode for intentional template injection (to offer rich functionalities). A server-side template injection can sometimes be a feature and not a vulnerability.
{% endhint %}

🛠️ Add some examples ?

## Examples

### SSTI in jinja2 templates





## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" %}

{% embed url="https://portswigger.net/research/server-side-template-injection" %}
