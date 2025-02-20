---
authors: ShutdownRepo
category: web
---

# Subdomain & vhost fuzzing

## Theory

A web server can host multiple websites for multiple domain names (websites). In order to choose what website to show for what domain, many use what is called "virtual hosting". Virtual hosting can be based on a name, an IP, or a port ([read more](https://en.wikipedia.org/wiki/Virtual_hosting#Name-based)). 

Two main mechanisms can be used to access a website on a virtual host:

* HTTP: the use of the `Host` request header. The client uses the `` directive to connect to the domain name of the server. Optionally, it can use the `` directive to specify a TCP port number on which the server is listening.
* HTTPS: the use of the Server Name Indication (SNI) extension with TLS. The client indicates the hostname it wants to connect to at the start of the handshake process.

When having a domain name as scope, operating virtual host (a.k.a. vhost) fuzzing is recommended to possibly find alternate domain names of subdomains that point to a virtual host, and thus have a better knowledge of the attack surface. This technique relies on the attacker using a dictionary/wordlist. A request is made for every line of the wordlist to differentiate pages that exist and pages that don't

> [!WARNING]
> This technique is not to be confused with [DNS bruteforcing](domains-enumeration.md#dns-bruteforcing). Vhost fuzzing/bruteforcing requests are made over HTTP and rely on the virtual hosting feature that many web app profit from. [DNS bruteforcing](domains-enumeration.md#dns-bruteforcing) relies on domain name resolution requests made over DNS to a DNS server.

## Practice



Tools like [gobuster](https://github.com/OJ/gobuster) (Go), [wfuzz](https://github.com/xmendez/wfuzz) (Python) and [ffuf](https://github.com/ffuf/ffuf) (Go) can do vhost fuzzing/bruteforcing. Burp Suite can do it too. Depending on the web application, one will be better suited than another and additional options will be needed.

Vhost fuzzing needs to be slowed down when testing production instances as it could lead to an unintended denial of service.


```bash
gobuster vhost --useragent "PENTEST" --wordlist "/path/to/wordlist.txt" --url $URL
```



```bash
wfuzz -H "Host: FUZZ.something.com" --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/path/to/wordlist.txt" $URL
```



```bash
ffuf -H "Host: FUZZ.$DOMAIN" -H "User-Agent: PENTEST" -c -w "/path/to/wordlist.txt" -u $URL
```


Some applications don't allow vhost fuzzing like showcased above. The command below can be attempted.


```bash
ffuf -c -r -w "/path/to/wordlist.txt" -u "http://FUZZ.$TARGET/"
```


> [!TIP]
> Virtual host fuzzing is not the only technique to find subdomains. There are others means to that end: see [subdomains enumeration](domains-enumeration.md).

## Resources

[https://www.ssl.com/article/sni-virtual-hosting-for-https/](https://www.ssl.com/article/sni-virtual-hosting-for-https/)

[https://en.wikipedia.org/wiki/Server_Name_Indication#cite_note-rfc3546-1](https://en.wikipedia.org/wiki/Server_Name_Indication#cite_note-rfc3546-1)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host)

[https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/](https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/)