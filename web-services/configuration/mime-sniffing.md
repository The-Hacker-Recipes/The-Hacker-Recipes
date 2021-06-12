# 🛠️ MIME sniffing

## Theory

MIME sniffing represents the action that the browser does in retrieving a content type on its own \(even if the `Content-Type` header is present\).

The simplest example involves a client sending an `html.jpg` containing malicious JavaScript code and the server uploading it on the website. If the browser does MIME sniffing, it may render the `html.jpg` as JavaScript MIME type \(which will be executed later on\).

{% hint style="info" %}
Each browser has different behavior, check the browsers' specifications for more details.
{% endhint %}

## Practice

TODO.

## Mitigation

Two steps to follow for the mitigation:

1. Include a valid `Content-Type` header.
2. Include a `X-Content-Type-Options` with the directive `nosniff`.

## References

{% embed url="https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/" %}

{% embed url="https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/" %}

{% embed url="https://mimesniff.spec.whatwg.org/" %}

