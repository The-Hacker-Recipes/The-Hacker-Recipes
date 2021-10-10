# Open redirect

## Theory

Many web applications make redirections based on parameters that users can easily control, like GET parameters. When the application fails to properly check and filter these inputs, they can be vulnerable to Open Redirect where attacker can redirect users to a malicious website. Open Redirect vulnerabilities are exploited in phishing attacks to redirect users from a trusted website to an attacker-controlled one. In well executed attacks, most of the users would not notice it without carefully looking at the URL to see the difference.

Open Redirect vulnerabilities are usually found when browsing a page, being asked to log in, and then being redirected to the original page when logged in. These mechanisms greatly improve the UX (user experience) but when they are badly implemented, they can lead to vulnerabilities from low to medium severity.

## Practice

Testers need to find inputs vectors used by the website for redirections. They usually are GET parameters with string values that are sometimes base64 encoded like:

* [http://some.website/login?redirect=\*\*http://some.website/products\*\*](http://some.website/login?redirect=\*\*http://some.website/products\*\*)
* [http://some.website/login?redirect=\*\*aHR0cDovL3NvbWUud2Vic2l0ZS9wcm9kdWN0cw%3D%3D\*\*](http://some.website/login?redirect=\*\*aHR0cDovL3NvbWUud2Vic2l0ZS9wcm9kdWN0cw%3D%3D\*\*)

Testers can then try to replace those values with different URLs and analyze de redirection.

Some bugbounty tools like [waybackurls](https://github.com/tomnomnom/waybackurls) (Go), [hakrawler](https://github.com/hakluke/hakrawler) (Go) and [gf](https://github.com/tomnomnom/gf) (Go) can help find vulnerable endpoints.

```bash
cat subdomains | waybackurls | tee -a urls
cat subdomains | hakrawler -depth 3 -plain | tee -a urls
gf redirect urls
```

Using `redirect.json` with gf like:

```javascript
{
    "flags" : "-HanrE",
    "pattern" : "url=|rt=|cgi-bin/redirect.cgi|continue=|dest=|destination=|go=|out=|redir=|redirect_uri=|redirect_url=|return=|return_path=|returnTo=|rurl=|target=|view=|from_url=|load_url=|file_url=|page_url=|file_name=|page=|folder=|folder_url=|login_url=|img_url=|return_url=|return_to=|next=|redirect=|redirect_to=|logout=|checkout=|checkout_url=|goto=|next_page=|file=|load_file="
}
```

{% hint style="info" %}
Redirections can be header based (`location` header sent from the server), or Javascript based (will not work fro server-side functions, but could redirect to `javascript:something()` and cause an XSS).
{% endhint %}

{% hint style="warning" %}
The impact of this vulnerability is debated. Open redirects can help in phishing attacks but in some cases, it could help exploit an XSS, a SSRF or a CSRF, hence increasing the impact.
{% endhint %}

## References

{% embed url="https://s0cket7.com/open-redirect-vulnerability/" %}

{% embed url="https://portswigger.net/kb/issues/00500100_open-redirection-reflected" %}

{% embed url="https://portswigger.net/kb/issues/00500101_open-redirection-stored" %}

{% embed url="https://portswigger.net/web-security/dom-based/open-redirection" %}

{% embed url="https://0x00sec.org/t/open-redirection-guide/21118" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect" %}
