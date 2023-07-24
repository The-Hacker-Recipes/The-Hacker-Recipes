# 🛠️ Logging in

## Theory

link default passwords

Authentication issues are important to take into consideration. A login page can be the beginning of serious issues regarding accounts takeover.

or bruteforce

## Practice

or authentication bypass

### Brute-force

Brute-forcing can have 2 interesting purposes during a pentest engagement:

1. Verifying that the web application implements security measures against brute-forcing.
2. Taking over an account by guessing its credentials.

One has to check whether a defense mechanism is used (account locking, blocking IP, CAPTCHA, etc.)

{% hint style="warning" %}
Account locking can lead to a denial of service and allow user enumeration. Check the [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Authentication\_Cheat\_Sheet.html#account-lockout) on how it should be implemented.
{% endhint %}

### User enumeration

User enumeration can be made possible depending on the:

* Status code (is the status code retrieved, always the same?)
* Error messages (does the error messages give a hint on whether the account exists?)
* Response time (is the response time always the same?)

### JSON Web Tokens (JWS) / OAuth 2.0

Check the following pages for issues regarding [JWS](https://www.thehacker.recipes/web/inputs/insecure-json-web-tokens) and [OAuth 2.0](https://www.thehacker.recipes/web/configuration/oauth-2.0).

### SQL injection

The tool [sqlmap](https://sqlmap.org/) can unveil SQL injections on log-in forms.

```
sqlmap -r $REQUEST_FILE -p $LOGIN_PARAM,$PWD_PARAM
```

{% hint style="warning" %}
Use the `--level` and `--delay` options in pentest engagements to avoid issues (aggressive payloads and denial of service)
{% endhint %}

For manual testing: [SQL injection (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

### 🛠️ NoSQL injection

For manual testing: [NoSQL injection (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)

### 🛠️ LDAP injection

For manual testing: [LDAP injection (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)

### Encrypted requests

Some web applications don't use TLS to encrypt login requests, this can lead to account takeover via a Man-in-the-Middle attack.

## References

{% embed url="https://portswigger.net/web-security/authentication/password-based" %}

{% embed url="https://portswigger.net/web-security/authentication/securing" %}

{% embed url="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" %}

{% embed url="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" %}

{% embed url="https://auth0.com/blog/what-is-broken-authentication/" %}

{% embed url="https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/login-bypass" %}

\
