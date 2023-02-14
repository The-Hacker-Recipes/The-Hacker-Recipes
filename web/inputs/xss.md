# XSS (Cross-Site Scripting)

## Theory

Many web applications have input vectors that users can interact with. When those inputs are reflected in the content of a page and not sanitized or filtered enough, attackers can try to inject malicious code to alter that page. The most common attacks that exploit such vulnerabilities are XSS (Cross-Site Scripting) and defacement attacks. While this kind of defacement only alters the visual appearance of a website, an XSS can allow attackers to inject code/scripts (JavaScript for example) that will be executed by victims browsers, hence causing much more trouble to the users.

Executing arbitrary code on a victim's browser can allow an attacker to perform **Cookie theft** (when the cookies are not secured, attackers can steal them and use them to authenticate as the victims without having to know their password), **Keylogging** (attackers can spy on the victims and recover their keystrokes) or **Phishing** (attackers can change the site appearance and behavior and trick victims into sending sensitive information to the attackers servers).

There are three major types of XSS:

* **Stored**: the user input is stored on the website. It usually happens on user profiles, forums, chats and so on were the user content is permanently (or temporarily) stored. Attackers can inject malicious payloads and every user browsing the infected page will be affected. This is one of the most dangerous forms of XSS because exploitation requires no phishing and it can affect many users. XSS on pages that only the attacker's user has the right to browse (e.g. user settings page) are called self-XSS and are considered to have a close to 0 impact since it's theoretically can't affect other users.  &#x20;
* **Reflected**: the user input is reflected but not stored. It usually happens on search forms, login pages and pages that reflect content for one response only. When the reflected vulnerable input is in the URI (`http://www.target.com/search.php?keyword=INJECTION`) attackers can craft a malicious URI and send it to the victims hoping they will browse it. This form of XSS usually requires phishing and attackers can be limited in the length of the malicious payload (cf. [this](https://serpstat.com/blog/how-long-should-be-the-page-url-length-for-seo/)).&#x20;
* **DOM-based**: while stored and reflected XSS attacks exploit vulnerabilities in the server-side code, a DOM-based XSS exploits client-side ones (e.g. JavaScript used to help dynamically render a page). DOM-based XSS usually affect user inputs that are temporarily reflected, just like reflected XSS attacks.

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that are stored or reflected.

* URI parameters for reflected and DOM-based XSS
* Other user inputs in forums, chats, comments, posts, and other stored content for stored XSS
* HTTP headers like Cookies (and even User-Agents in some cases)

One of the most famous payloads is `<script>alert('XSS');</script>` opening a pop-up window echoing "XSS". However, exploiting XSS is like playing "cat and mouse". Inputs can be filtered and filters can be bypassed. Here are some basic examples of XSS payloads.

```markup
<script>alert('XSS');</script>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG onmouseover="alert('XSS')">
<<SCRIPT>alert("XSS");//<</SCRIPT>
```

The following [website](https://transformations.jobertabma.nl/) ([GitHub project](https://github.com/jobertabma/transformations)) can help identify transformations applied to user inputs. This can help bypass filters and transformations to exploit XSS attacks.

The following payload is used for testing [SQL injections](sqli.md), XSS (Cross-Site Scripting) and [SSTI (Server-Side Template Injection)](../../web-services/attacks-on-inputs/ssti-server-side-tempate-injection.md).

```
'"<svg/onload=prompt(5);>{{7*7}}
```

Tools like [XSStrike](https://github.com/s0md3v/XSStrike) (Python) and [XSSer](https://github.com/epsylon/xsser) (Python) can also help in finding and exploiting XSS vulnerable input vectors by fuzzing them with unique payloads and then searching for unique patterns in the responses.

## References

{% embed url="https://xss-game.appspot.com/" %}

{% embed url="https://excess-xss.com/" %}

{% embed url="https://owasp.org/www-community/attacks/DOM_Based_XSS" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection" %}
