# Virtual host fuzzing

## Theory

A web server can host multiple websites for multiple domain names (websites). In order to choose what website to show for what domain, many use what is called "virtual hosting". Virtual hosting can be [based on](https://en.wikipedia.org/wiki/Virtual\_hosting#Name-based) a name, an IP, or a port.&#x20;

Two main mechanisms can be used to access a website on a virtual host:

* HTTP: the use of the `Host` request header. The client uses the `<host>` directive to connect to the domain name of the server. Optionally, it can use the `<port>` directive to specify a TCP port number on which the server is listening.
* HTTPS: the use of the Server Name Indication (SNI) extension with TLS. The client indicates the hostname it wants to connect to at the start of the handshake process.

When having a domain name as scope, operating virtual host (a.k.a. vhost) fuzzing is recommended to possibly find alternate domain names of subdomains that point to a virtual host, and thus have a better knowledge of the attack surface. This technique relies on the attacker using a dictionary/wordlist. A request is made for every line of the wordlist to differentiate pages that exist and pages that don't

{% hint style="warning" %}
This technique is not to be confused with DNS bruteforcing. Vhost fuzzing/bruteforcing requests are made over HTTP and rely on the virtual hosting feature that many web app profit from. DNS bruteforcing relies on domain name resolution requests made over DNS to a DNS server.
{% endhint %}

## Practice



Tools like [gobuster](https://github.com/OJ/gobuster) (Go), [wfuzz](https://github.com/xmendez/wfuzz) (Python) and [ffuf](https://github.com/ffuf/ffuf) (Go) can do vhost fuzzing/bruteforcing. Burp Suite can do it too. Depending on the web application, one will be better suited than another and additional options will be needed.

Vhost fuzzing needs to be slowed down when testing production instances as it could lead to an unintended denial of service.

```bash
gobuster vhost --useragent "PENTEST" -w "/path/to/wordlist.txt" -u $URL
```

```bash
wfuzz -H "Host: FUZZ.something.com" --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/path/to/wordlist.txt" $URL
```

```bash
ffuf -H "Host: FUZZ.$DOMAIN" -H "User-Agent: PENTEST" -c -w "/path/to/wordlist.txt" -u $URL
```

## Resources

{% embed url="https://www.ssl.com/article/sni-virtual-hosting-for-https/" %}

{% embed url="https://en.wikipedia.org/wiki/Server_Name_Indication#cite_note-rfc3546-1" %}

{% embed url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host" %}

{% embed url="https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/" %}
