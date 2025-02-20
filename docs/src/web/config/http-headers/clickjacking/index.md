---
authors: ShutdownRepo
category: web
---

# Clickjacking

## Theory

Lots of websites allow to browsers to render them in a [`<frame>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/frame), [`<iframe>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe), [`<embed>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/embed) or [`<object>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object). This allows attackers to "load" the website in a transparent layer and trick users into thinking they are browsing the legitimate website. This allows attackers to "hijack" their clicks and make them do something else ([Twitter worm](https://shiflett.org/blog/2009/twitter-dont-click-exploit), [Facebook likes](https://www.netsparker.com/blog/web-security/clickjacking-attack-on-facebook-how-tiny-attribute-save-corporation/)).

[HTTP security headers](./) like XFO (`X-Frame-Options`) and CSP (`Content-Security-Policy`) mitigate clickjacking attacks.

## Practice

![](<./assets/Clickjacking example.png>)
(left) vulnerable | not vulnerable (right){.caption}

The following HTML code can be used in a browser to attempt a clickjacking on a target URL.


```
<html>
    <head>
        <title>Clickjacking / framing test</title>
    ​</head>
    <body>
        <h1>Test a page for clickjacking/framing vulnerability</h1>
        <p>Enter the URL to frame:</p>
        <input id="url" type="text" value="http://TARGET.com"></input>
        <button id="submit-test" onclick='document.getElementById("iframe").src=document.getElementById("url").value'>Test it!</button>
        <br />
        <br />
        <hr>
        <br />
        <iframe src="about:blank" id="iframe" width="100%" height="75%"></iframe>
    </body>
</html>
```

## Resources

[https://owasp.org/www-community/attacks/Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)