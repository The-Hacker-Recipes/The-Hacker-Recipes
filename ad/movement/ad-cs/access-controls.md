# Access controls

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found multiple vectors of domain escalation based on access control misconfigurations (dubbed [ESC4](https://posts.specterops.io/certified-pre-owned-d95910965cd2#7c4b), [ESC5](https://posts.specterops.io/certified-pre-owned-d95910965cd2#0a38) and [ESC7](https://posts.specterops.io/certified-pre-owned-d95910965cd2#fdbf)).&#x20;

Active Directory Certificate Services add multiple objects to AD, including securable ones which principals can have permissions over. This includes:

* **Certificate templates (ESC4)**: powerful rights over these objects can allow attackers to _"push a misconfiguration to a template that is not otherwise vulnerable (e.g., by enabling the `mspki-certificate-name-flag` flag for a template that allows for domain authentication) this results in the same domain compromise scenario \[...]" (_[_specterops.io_](https://posts.specterops.io/certified-pre-owned-d95910965cd2)_)_ as the one based on misconfigured certificate templates where low-privs users can specify an arbitrary SAN (`subjectAltName`) and authenticate as anyone else. &#x20;
* **The Certificate Authority (ESC7)**: _"The two main rights here are the `ManageCA` right and the `ManageCertificates` right, which translate to the “CA administrator” and “Certificate Manager” (sometimes known as a CA officer) respectively. known as Officer rights)" (_[_specterops.io_](https://posts.specterops.io/certified-pre-owned-d95910965cd2)_)_.&#x20;
  * If an attacker gains control over a principal that has the ManageCA right over the CA, he can remotely flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit to allow SAN specification in any template (c.f. [CA misconfiguration](ca-configuration.md)).
  * If an attacker gains control over a principal that has the ManageCertificates right over the CA, he can remotely approve pending certificate requests, subvertnig the "CA certificate manager approval" protection (referred to as PREVENT4 in [the research whitepaper](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)).
* **Several other objects (ESC5): **abuse standard [AD access control abuse](../access-controls/) over regulard AD objects.
  * The CA server’s AD computer object (i.e., compromise through [RBCD abuse](../kerberos/delegations/rbcd.md), [Shadow Credentials](../kerberos/shadow-credentials.md), [UnPAC-the-hash](../kerberos/unpac-the-hash.md), ...).
  * The CA server’s RPC/DCOM server
  * Any descendant AD object or container in the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=DOMAIN,DC=LOCAL` (e.g., the Certificate Templates container, Certification Authorities container, the `NTAuthCertificates` object, the `Enrollment Services` Container, etc.) If a low-privileged attacker can gain control over any of these, the attack can likely compromise the PKI system.
  * ...

## Practice

### Certificate templates (ESC4)

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate these sensitive access control entries.

```python
certipy 'domain.local'/'user':'password'@'domaincontroller' find
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate these sensitive access control entries. At the time of writing (October 21st, 2021) [BloodHound](../../recon/bloodhound.md) doesn't support (yet) enumeration of these access controls.

```batch
Certify.exe find
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
If sensitive access entries are identified, creativity will be the best ally. Not much public research or tooling is available at the time of writing (October 21st, 2021).

Currently, the best resource for abusing this is [https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates](https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates)
{% endhint %}

### Certificate Authority (ESC7)

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate access rights over the CA object.

```python
certipy 'domain.local'/'user':'password'@'domaincontroller' find
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}

{% hint style="warning" %}
If sensitive rights are identified, switch to Windows because at the time of writing (October 21st, 2021), I don't know how to easily conduct the ESC7 abuse from UNIX.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate info about the CAs, including access rights over the CA object.

```batch
Certify.exe cas
```

{% hint style="warning" %}
If sensitive rights are identified, follow the ~~white rabbit~~ [whitepaper](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) for practical exploitation.
{% endhint %}
{% endtab %}
{% endtabs %}

### Other objects (ESC5)

This can be enumerated and abused like regulard AD access control abuses. Once control over an AD-CS-related is gained, creativity will be the attacker's best ally.

{% content-ref url="../access-controls/" %}
[access-controls](../access-controls/)
{% endcontent-ref %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://github.com/daem0nc0re/Abusing_Weak_ACL_on_Certificate_Templates" %}
