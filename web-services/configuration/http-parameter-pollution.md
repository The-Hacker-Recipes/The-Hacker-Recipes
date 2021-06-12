# 🛠️ HTTP parameter pollution

## Theory

A query parameter allows a client to refine researches on a website. It is composed of a key \(the parameter name\) and a value \(what we are requesting\).

With parameter pollution, we enter a query parameter with the same key multiple times. For example, we could have `$URL?username=X&username=Y`, but which one does a web server choose?  
In fact, each web servers adopt different behaviors: some of them choose the first parameter, the second parameter, or every parameter.

This attack could allow an attacker to bypass input validation and WAFs rules, manipulate, access, or retrieve hidden information.

## Practice

### Before the test

We can use [Arjun](https://github.com/s0md3v/Arjun) to find HTTP parameters in a website.

```bash
arjun -u $URL/endpoint
```

{% hint style="info" %}
We can specify a delay between requests and handle rate limits.  
Check out the [GitHub page](https://github.com/s0md3v/Arjun/wiki/Usage#scan-a-single-url).
{% endhint %}

### Manual testing

TODO.

