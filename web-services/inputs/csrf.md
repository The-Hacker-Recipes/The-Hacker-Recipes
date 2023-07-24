# CSRF (Cross-Site Request Forgery)

## Theory

A Cross-Site Request Forgery (a.k.a. CSRF, pronounced "C surf"', a.k.a. XSRF) allows an attacker to force a user make HTTP requests in order to execute unwanted actions like:

* **Regular users**: transferring funds, changing the email address and other actions that could leak to account takeover (ATO)
* **Administrators**: administrative actions on the web site that could lead to a full takeover

Victims can be triggered when browsing:

* a malicious website containing client-side code making the browser send the requests
* a legitimate website altered by an attacker (XSS vulnerable inputs, unrestricted file upload or any other attack allowing an attacker to add or edit a website content)

People tend to mix up [XSS](xss.md) and CSRF attacks. XSS make user's browser **execute client-side code** (e.g. JavaScript) whereas CSRF make user's browser **send HTTP requests**.

## Practice

### Verifying inputs

First of all, testers need to find insecure input vectors that allow client-side code (like JS) injection, just like XSS. This part will not be further detailed as it already is in the following page.

{% content-ref url="xss.md" %}
[xss.md](xss.md)
{% endcontent-ref %}

### Verifying actions

One of the most efficient and common CSRF protection is the usage of an **anti-CSRF token**. It works like this:

1. A user logs in a website and gets a session cookie
2. While browsing he decides to transfer funds and goes the transfer page
3. The page contains a form where the user indicates the amount and beneficiary of the transfer
4. The form also contains a hidden random token, that only the user browsing the page can know
5. This token is sent along with the other values of the form when submitting
6. The server can verify the authenticity of the token and proceeds to execute the action requested

With this protection, CSRF attacks attempts would fail since the attacker would have no way of knowing the unique and random token needed along with the action request.

Another protection is asking users to **confirm** when asking for any action. This can be done with a CAPTCHA.

Testers need to make sure that actions are protected with an anti-CSRF token, a CAPTCHA, or any other efficient mitigation.

{% hint style="info" %}
Secret cookies, using POST instead of GET and URL rewriting are not efficient mitigations.
{% endhint %}

The tool [XSRFProbe](https://github.com/0xInfection/XSRFProbe) (Python) is an advanced audit and exploitation toolkit that can help testers find and exploit CSRFs.

## References

{% embed url="https://owasp.org/www-community/attacks/csrf" %}

{% embed url="https://openclassrooms.com/fr/courses/2091901-protegez-vous-efficacement-contre-les-failles-web/2863569-la-csrf" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection" %}
