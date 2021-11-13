# 🛠️ Clickjacking

## Theory



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
