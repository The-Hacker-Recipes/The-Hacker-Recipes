# 🛠️ MIME sniffing

## Theory

MIME sniffing represents the action that the browser does in retrieving a content type on its own \(even if the `Content-Type` header is present\).

The simplest example involves a client sending a `file.jpg` containing malicious HTML code and the attacker uploading it on the server \(some websites would allow users to only upload `.jpg` extension files\). If the browser does MIME sniffing, it may render the `file.jpg` as a HTML MIME type \(allowing the attacker to execute an XSS for example\).

{% hint style="info" %}
Each browser has different behavior, check the browsers' specifications for more details.
{% endhint %}

### Mitigation

Two steps to follow for the mitigation:

1. Include a valid `Content-Type` header.
2. Include a `X-Content-Type-Options` with the directive `nosniff`. 

## References

{% embed url="https://www.keycdn.com/support/what-is-mime-sniffing" %}

{% embed url="https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/" %}

{% embed url="https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/" %}

{% embed url="https://mimesniff.spec.whatwg.org/" %}

