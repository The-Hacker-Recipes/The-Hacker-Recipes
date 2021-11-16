# Clickjacking

## Theory

Lots of websites allow to browsers to render them in a [`<frame>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/frame), [`<iframe>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe), [`<embed>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/embed) or [`<object>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object). This allows attackers to "load" the website in a transparent layer and trick users into thinking they are browsing the legitimate website. This allows attackers to "hijack" their clicks and make them do something else ([Twitter worm](https://shiflett.org/blog/2009/twitter-dont-click-exploit), [Facebook likes](https://www.netsparker.com/blog/web-security/clickjacking-attack-on-facebook-how-tiny-attribute-save-corporation/)).

[HTTP security headers](./) like XFO (`X-Frame-Options`) and CSP (`Content-Security-Policy`) mitigate clickjacking attacks.

## Practice

![(left) vulnerable | not vulnerable (right)](<../../../.gitbook/assets/image (5).png>)

The following HTML code can be used in a browser to attempt a clickjacking on a target URL.

{% code title="clickjacking.html" %}
```markup
<html>
    <head>
        <title>Clickjacking / framing test</title>
        <script type="text/javascript">function frameIt() {
           var url = document.getElementById("url").value;
           var iframe = document.getElementById("iframe");
           iframe.src = url;
        }

document.addEventListener('DOMContentLoaded', function () {
   document.getElementById('submit-test').addEventListener('click',
       function() {
           frameIt();
   });
});

</script>
    </head>
    <body>
        <h1>Test a page for clickjacking/framing vulnerability</h1>
        <p>Enter the URL to frame:</p>
        <input id="url" type="text" value="http://TARGET.com"></input>
        <button id="submit-test">Test it!</button>
        <br />
        <iframe src="about:blank" id="iframe" width="800px" height="600px"></iframe>
    </body>
</html>
```
{% endcode %}

## Resources

{% embed url="https://owasp.org/www-community/attacks/Clickjacking" %}
