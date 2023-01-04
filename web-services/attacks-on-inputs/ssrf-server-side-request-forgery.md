# SSRF (Server-Side Request Forgery)

## Theory

A Server-Side Request Forgery (a.k.a. SSRF) is a web vulnerability allowing attackers to make the server-side application do certain requests. This vulnerability can lead to unauthorized actions, Sensitive Information Disclosure and even RCE (Remote Code Execution).

{% hint style="info" %}
SSRF is very similar to [file inclusion](../../web/inputs/file-inclusion/) since both vulnerabilities can be exploited to access external or internal content. The difference resides in the fact that file inclusion vulnerabilities rely on code inclusion functions (e.g. `include()` in PHP) while SSRF ones on functions that only handle data (e.g. `fopen()` in PHP). RFI vulnerabilities will lead to RCE much more often and easily that SSRF ones.
{% endhint %}

## Practice

Testers need to find input vectors and fields that could be used for publishing or importing data from a URL (e.g. GET and POST parameters).

With `http://some.website/index.php?url=https://someother.website/index.php`, and `url` being the vulnerable parameter, the following basic payloads can help a tester fetch content of files, scan ports, access filtered resources and so on.

```
file://PATH/TO/FILE
http://127.0.0.1:80
http://127.0.0.1:22
```

[SSRFMap](https://github.com/swisskyrepo/SSRFmap) (Python) is a tool used to ease the exploitation of SSRFs. [Gopherus](https://github.com/tarunkant/Gopherus) (Python) can be used to gain RCE (Remote Code Execution) by generating Gopher payloads.

## References

{% embed url="https://portswigger.net/web-security/ssrf" %}

{% embed url="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery" %}
