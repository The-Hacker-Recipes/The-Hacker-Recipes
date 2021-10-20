# Certificate templates

## Theory

> AD CS Enterprise CAs issue certificates with settings defined by AD objects known as certificate templates. These templates are collections of enrollment policies and predefined certificate settings and contain things like “_How long is this certificate valid for?_”, _“What is the certificate used for?”,_ “_How is the subject specified?_”, _“Who is allowed to request a certificate?”_, and a myriad of other settings
>
> \[...]
>
> There is a specific set of settings for certificate templates that makes them extremely vulnerable. As in regular-domain-user-to-domain-admin vulnerable.
>
> ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found multiple vectors of domain escalation based on certificate template misconfigurations (dubbed [ESC1](https://posts.specterops.io/certified-pre-owned-d95910965cd2#180f), [ESC2](https://posts.specterops.io/certified-pre-owned-d95910965cd2#dfa4) and [ESC3](https://posts.specterops.io/certified-pre-owned-d95910965cd2#c08e)).

![Vulnerable configurations for ESC1, ESC2 and ESC3](<../../../.gitbook/assets/AD CS cert templates vuln confs.png>)

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC1 and ESC2 scenarios. At the time of writing (October 20th, 2021), ESC3 doesn't seem to be fully supported.

```python
certipy 'domain.local'/'user':'password'@'domaincontroller' find -vulnerable
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
Certify.exe find /vulnerable
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}
