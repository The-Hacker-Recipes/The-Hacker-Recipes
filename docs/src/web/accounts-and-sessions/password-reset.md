---
authors: ShutdownRepo
category: web
---

# 🛠️ Password reset

## Theory

Websites that manage user accounts usually have a "forgot password" or "reset password" feature. This offers attackers an interesting vector as it could potentially lead to Account Takeover (ATO).

## Practice 

When this feature is present on a website, there a a few things to check.

* Is there a captcha, rate-limit or any other anti-DoS mitigation?
* Is there any kind of validation, from the user, that the password must be reset? This could lead to a kind of DoS on user accounts if there isn't.
* Is the feature relying on security questions that could be easily answered from OSINT or Social Engineering?
* Is the previous password sent in clear-text to the user, indicating that the passwords are not stored in a hashed format?
* If a one-time password (OTP) is sent to proceed with the password reset, is it sent on a secure channel (e.g. mitigating MitM)?
* Can the feature be used by attackers to enumerate users (e.g. error message when trying to proceed with a user that doesn't exist)?
* Is there a password reset link sent? If so:
    * Is it still valid after a reset?
    * Does it have an expiry date? If so, is it still valid after that period of time?
    * Is the link fully random or is there any guessable format that can be reproduced to takeover other accounts?
* Is "password reset" link sent to an email indicated in a parameter that is not correctly filtered? --> [Paramater manipulation](password-reset.md#manipulation-of-parameters)



///// WIP below 





### Password Reset Poisoning

To provide the user with a link to reset its password, some implementations use the result of input headers such as the `Host` header. This helps in constructing a resetting password link by keeping the origin (`example.com`). By manually changing the `Host` header and using a malicious origin (`malicious.com`), the user is redirected to malicious.com when clicking the link.

This vulnerability is easy to test.

1. Send a request to a forget password mechanism using your own email.
2. Change the Host header between the requests
3. Check the resetting password link you received via email. If the value of the `Host` header is reflected in the origin in the link (`https://www.malicious.com/reset-link.php?token=$TOKEN_VALUE`, then it's vulnerable

### Token leak via Referer header

The `Referer` header contains information about the previous web page from which a request has been made. It `example1.com` has a link pointing to `example2.com`, when clicking on that link, the `Referer` header will be set to `example1.com`. The `Referer` header will print out the whole URL, containing query parameters and so on, not just the origin.

> [!TIP]
> Using the `Referrer-Policy` with the directive `no-referrer` mitigates the issue.

To test for token leakage:

1. The forgot password mechanism has to be used with a valid email address.
2. After clicking on the reset password link (received by email), the password shouldn't be changed.
3. Upon clicking on the reset password link, it's important to click on another link from another origin.
4. By intercepting the request, one can check if the `Referer` header (if set), contains the token.

> [!TIP]
> In a real-world situation, the "other" origin should be vulnerable for an attacker to intercept the token (from the `Referer` header).

### Paramater manipulation

When clicking on a reset password button, a request can be sent with a parameter such as `email=$EMAIL`. By modifying this parameter, multiple tests can be done to take over the account requesting a reset password.

Based on CyPH3R's [blog post](https://anugrahsr.github.io/posts/10-Password-reset-flaws/#2-account-takeover-through-password-reset-poisoning):

```
email=victim@email.com&email=attacker@email.com
email=victim@email.com%20email=attacker@email.com
email=victim@email.com|email=attacker@email.com
email="victim@mail.tld%0a%0dcc:attacker@mail.tld"
email="victim@mail.tld%0a%0dbcc:attacker@mail.tld"
email="victim@mail.tld",email="attacker@mail.tld"
{"email":["victim@mail.tld","atracker@mail.tld"]}
```

The same can be done when the request uses an API:

```
("form": {"email":"victim@email.tld","password":"12345678"})
```