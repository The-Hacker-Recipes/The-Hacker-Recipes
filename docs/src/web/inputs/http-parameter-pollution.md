---
authors: KenjiEndo15, ShutdownRepo, Fantabc
category: web
---

# HTTP parameter pollution

## Theory

A query parameter allows a client to refine researches on a website. It is composed of a key (the parameter name) and a value (what we are requesting).

With parameter pollution, we enter a query parameter with the same key multiple times. For example, we could have `$URL?username=X&username=Y`, but which one does a web server choose?\
In fact, each web servers adopt different behaviors: some of them choose the first parameter, the second parameter, or every parameter.

This attack could allow an attacker to bypass input validation and WAFs rules, manipulate, access, or retrieve hidden information.

## Practice

### Before the attack

[Arjun](https://github.com/s0md3v/Arjun) can be used to find HTTP parameters in a website.

```bash
arjun -u $URL/endpoint
```

> [!TIP]
> It's possible to specify a delay between requests and handle rate limits.\
> Check out the [GitHub page](https://github.com/s0md3v/Arjun/wiki/Usage#scan-a-single-url).

After discovering a few HTTP parameters, one should know the server's behavior when presented with the same key multiple times.

1. When presented with a query string in a URL, check the response the server gives with one key.
    
    `http://example.com/search=result1`

2. Repeat the first step with another value (make sure to check the response).
    
    `http://example.com/search=result2`

3. Once you are able to identify what kind of response the server returns for each value, try to combine both and see which one is used.
    
    `http://example.com/page?search=result1&search=result2`

*The result could be a combination of both, giving a new response.

The payload that would be used to conduct a HPP will depend on the browser's behavior (found previously).

### Server parameter handling order

Depending on the web server, a parameter may not be processed in the same way. Here's a list of the parameters used by some web servers.

| Server                | Parameter             |
|-----------------------|-----------------------|
| ASP.NET / IIS         | All (array of values) |
| ASP / IIS             | All (array of values) |
| PHP / Apache          | Last                  |
| JSP, Servlet / Tomcat | First                 |
| Perl CGI / Apache     | First                 |
| Python Flask          | First                 |
| Python Django         | Last                  |
| NodeJS                | All (array of values) |
| Ruby on Rails         | Last                  |

### Example

::: details Google CTF Challenge

From the **Under Construction** web challenge of the 2023 Google CTF.

This challenge had 2 web servers : a **Flask** one and a **PHP (Apache)** one. When reaching the main page, a register form asked to choose a username, a password and a tier. The goal was to get the **"Gold tier"**. When registering, the first web server (Flask) checked the tier wasn't the "Gold tier" that only the CEO had access to. If the check passed, it then forwarded the HTTP request to the PHP server that stored the registration in the database.

To bypass the check, the user had to abuse a parameter pollution. As seen in the table above, Python Flask performs the check on the first parameter but PHP (Apache) stores the last parameter. This was the URL to trigger to get the much-desired **Gold tier** :

> ```
> http://<url>/signup?username=X&password=Y&tier=blue&tier=gold
> ```

:::

## Resources

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution)