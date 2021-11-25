# IDOR (Insecure Direct Object Reference)

## Theory

When web applications badly implement access objects directly (files, database objetcs) with user-supplied inputs, they can be vulnerable to Insecure Direct Object Reference (IDOR) allowing attackers to access unauthorized resources.

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that could be used for direct object reference like:

* [http://some.website/account?id=\*\*13984\*\*](http://some.website/account?id=\*\*13984\*\*)
* [http://some.website/assets/\*\*c29tZXBkZi5wZGY%3D\*\*](http://some.website/assets/\*\*c29tZXBkZi5wZGY%3D\*\*)

In order to test IDOR vulnerabilities, testers can follow two methodologies that depend on the context:

* **Testers can have accounts on the web app**:&#x20;
  * access different objects from two accounts
  * then save the values
  * then try to access an user's object from another user
* **They can't have accounts on the web app**: try to access other user's objects by
  * randomly changing the parameters
  * identifyinf integer values that increment/decrement depending on the referenced object
  * identifying string values that are encoded (hex, base64) depending on the referenced object

### IDOR to self-XSS

While self-XSS are usually out-of-scope in bug bounty programs, and considered impactless in pentest engagements, combining an IDOR to a self-XSS can be impactful when triggering a self-XSS on another user. That is possible when there is an IDOR vulnerability when editing user's non-public info that can trigger an XSS.

## References

{% embed url="https://enciphers.com/insecure-direct-object-reference-a-modern-age-sqli/" %}

{% embed url="https://portswigger.net/web-security/access-control/idor" %}

{% embed url="https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/" %}
