# 🛠️ Password change

## Theory

Websites that manage user accounts have a forgot password mechanism, for users that have forgotten their password. This attack vector may not be considered as serious, but in some cases, it can lead to account takeover.

## Practice

#### Denial of Service \(DOS\)

Some applications don't prevent individuals from requesting a new password via the forgot password mechanism. This could lead to a denial of service if the requests are not limited \(by a CAPTCHA, rate-limit or, other controls\).

If the application locks a user-associated password upon requesting a new password, this can also lead to a denial of service since a user won't be able to connect to the application anymore.

#### Security questions

[Security questions](https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html) can be used for resetting passwords. Sometimes the questions used are too easily guessable \(thanks to social engineering or OSINT\).

#### Clear-text password

In some applications, the password will be reset by providing the user with a new one. The new password is send using its email however when the communication is not encrypted \(TLS\), the password can be stolen.

#### Password Reset Poisoning

To provide the user with a link to reset its password, some implementations use the result of input headers such as the `Host` header. This helps in constructing a resetting password link by keeping the origin \(`example.com`\). By manually changing the `Host` header and using a malicious origin \(`malicious.com`\), the user is redirected to malicious.com when clicking the link.

This vulnerability is easy to test.

1. Send a request to a forget password mechanism using your own email.
2. Change the Host header between the requests
3. Check the resetting password link you received via email. If the value of the `Host` header is reflected in the origin in the link \(`https://www.malicious.com/reset-link.php?token=$TOKEN_VALUE`, then it's vulnerable

#### User enumeration

Check for user enumeration by triggering the forgot password mechanism using arbitrary emails.

{% hint style="warning" %}
Be careful when enumerating users in a pentest engagement. Submitting forget password requests will involve users in the test, which is not advised.
{% endhint %}

#### Token leak via Referer header

The `Referer` header contains information about the previous web page from which a request has been made. It `example1.com` has a link pointing to `example2.com`, when clicking on that link, the `Referer` header will be set to `example1.com`. The `Referer` header will print out the whole URL, containing query parameters and so on, not just the origin.

{% hint style="info" %}
Using the `Referrer-Policy` with the directive `no-referrer` mitigates the issue.
{% endhint %}

To test for token leakage:

1. The forgot password mechanism has to be used with a valid email address.
2. After clicking on the reset password link \(received by email\), the password shouldn't be changed.
3. Upon clicking on the reset password link, it's important to click on another link from another origin.
4. By intercepting the request, one can check if the `Referer` header \(if set\), contains the token.

{% hint style="info" %}
In a real-world situation, the "other" origin should be vulnerable for an attacker to intercept the token \(from the `Referer` header\).
{% endhint %}

#### Manipulation of parameters

When clicking on a reset password button, a request can be sent with a parameter such as `email=$EMAIL`. By modifying this parameter, multiple tests can be done to take over the account requesting a reset password.

Based on CyPH3R's [blog post](https://anugrahsr.github.io/posts/10-Password-reset-flaws/#2-account-takeover-through-password-reset-poisoning):

```text
email=victim@email.com&email=attacker@email.com
```

```text
email=victim@email.com%20email=attacker@email.com
```

```text
email=victim@email.com|email=attacker@email.com
```

```text
email="victim@mail.tld%0a%0dcc:attacker@mail.tld"
```

```text
email="victim@mail.tld%0a%0dbcc:attacker@mail.tld"
```

```text
email="victim@mail.tld",email="attacker@mail.tld"
```

```text
{"email":["victim@mail.tld","atracker@mail.tld"]}
```

The same can be done when the request uses an API:

```text
("form": {"email":"victim@email.tld","password":"12345678"})
```

#### Token recommendations

[Owasp Cheat Series](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html#url-tokens):

> **Ensure that generated tokens or codes are:**
>
> * Randomly generated using a cryptographically safe algorithm.
> * Sufficiently long to protect against brute-force attacks.
> * Stored securely.
> * Single use and expire after an appropriate period.

## References

{% embed url="https://www.paladion.net/blogs/common-flaws-in-forgot-password-implementation" %}

{% embed url="https://www.acunetix.com/blog/articles/password-reset-poisoning/" %}

{% embed url="https://anugrahsr.github.io/posts/10-Password-reset-flaws/" %}

{% embed url="https://cheatsheetseries.owasp.org/cheatsheets/Forgot\_Password\_Cheat\_Sheet.html" %}

{% embed url="https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning" %}

{% embed url="https://security.stackexchange.com/questions/213975/how-to-properly-create-a-password-reset-token" %}

