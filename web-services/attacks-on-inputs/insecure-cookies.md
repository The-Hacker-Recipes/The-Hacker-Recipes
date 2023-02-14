# Insecure Cookies

## Theory

Most web applications use cookies for stateful authentication and access control. Some implementations are insecure and allow attackers to bypass controls, impersonate users, or retrieve secrets.

The browser makes a POST request to the server that contains the user’s identification and password. The server responds with a cookie, which is set on the user’s browser using the HTTP header `Set-Cookie`, and includes a session ID to identify the user. On every subsequent request, the server needs to find that session and deserialize it, because user data is stored on the server ([source](https://blog.imaginea.com/stateless-authentication-using-jwt-2/)).

## Practice

### Cookies creation and usage

First of all, testers need to analyze the cookies used by the application. Instead of using random values, some implementations encode intelligible values like usernames, roles, secrets and so on. Since cookies are stored in the browser, attackers could decode them, encode different values and try to impersonate roles or users.

The following tests can help identify **insecure cookies (lacking security)**.

* Trying to decode cookies and forging new ones based on the values decoded (encoding usually is base64 or hex)
* Logging out and being able to use the same session-cookie to log in
* Creating several accounts with almost the same username, and noticing similarities in the session-cookies value
* Changing password and realizing the old session cookies is still valid and hasn't been revoked

In some cases, cookies can be used for SQL queries or for dynamic content. Testers should make sure the cookies are not vulnerable to [SQL injections](../../web/inputs/sqli.md) or [XSS](../../web/inputs/xss.md).

### Security attributes

Cookies have a key/value pair along with attributes too. The attributes tell the browser how to handle the cookies. Some security attributes help protect the cookies. Testers need to make sure that sensitive cookies make use of these attributes. If they don't, they are considered as **unsecured cookies (lacking protection)**.

* **HTTPonly**: cookies can't be retrieved by client-side scripts like JavaScript, hence protecting them from XSS (Cross-Site Scripting) cookie-stealing attacks
* **Secure**: cookies can only be sent through HTTPS sessions, hence mitigating MITM (Man In The Middle) attacks allowing attackers to eavesdrop on unencrypted communications and stealing cookies
* **SameSite**: cookies can only be sent with requests initiated from the same registrable domain, hence mitigating the risk of CSRF (Cross-Site Request Forgery) and Information leakage attacks.

## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies" %}

{% embed url="https://medium.com/@muratkaraoz/web-app-pentest-cheat-sheet-c17394af773" %}

{% embed url="https://blog.imaginea.com/stateless-authentication-using-jwt-2/" %}

{% embed url="https://web.dev/samesite-cookies-explained/" %}
