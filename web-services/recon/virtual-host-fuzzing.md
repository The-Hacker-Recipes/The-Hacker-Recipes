# 🛠️ Virtual host fuzzing

## Theory

A web server can host multiple domain names (websites). This is called virtual hosting. Two main mechanisms are used for a client to access a website on a virtual host:

* **HTTP**: the use of the `Host` request header. The client uses the **\<host>** directive to connect to the domain name of the server. Optionally, it can use the **\<port>** directive to specify a TCP port number on which the server is listening.
* **HTTPS**: the use of the Server Name Indication (SNI) extension with TLS. The client indicates the hostname it wants to connect to at the start of the handshake process.

Virtual hosting can be [based on](https://en.wikipedia.org/wiki/Virtual_hosting#Name-based) a name, an IP, or a port.

## Practice

### Tools

Fuzzing with [ffuf](https://github.com/ffuf/ffuf).

```bash
# Example with a subdomain FUZZ.$URL
ffuf -w $wordlist -u $URL -H "Host: FUZZ.$URL"
```

{% hint style="info" %}
It is possible to filter the responses with a specific size using `-fs $size`.\
An example can be found [here](https://asciinema.org/a/211360) and more tips [here](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html).
{% endhint %}

Fuzzing with [Gobuster](https://github.com/OJ/gobuster).

```bash
gobuster vhost -u $URL -w $wordlist
```

{% hint style="warning" %}
This [blog post](https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/) highlights the fact that, if a website is behind Cloudflare, results given by Gobuster could be wrong. 
{% endhint %}

Finding domains with [Findomain](https://github.com/Findomain/Findomain).

```bash
findomain -t $URL
```

### Manual testing

Using Google Dorks.

```
site:<url> -www
```

With `-www`, the response avoids printing searches related to our main domain so it is easier to focus on interesting subdomains.

## Resources

{% embed url="https://www.ssl.com/article/sni-virtual-hosting-for-https/" %}

{% embed url="https://en.wikipedia.org/wiki/Server_Name_Indication#cite_note-rfc3546-1" %}

{% embed url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host" %}

{% embed url="https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/" %}
