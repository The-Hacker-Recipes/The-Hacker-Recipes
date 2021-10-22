# Certificate Services (AD-CS)

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) shared their research on AD CS and identified multiple theft, escalation and persistence vectors.

* Credential theft
* Account persistence
* Domain escalation
  * based on [misconfigured certificate templates](certificate-templates.md)
  * based on [dangerous CA configuration](ca-configuration.md)
  * related to [access control vulnerabilities](access-controls.md)
  * based on an NTLM relay vulnerability related to the [web endpoints of AD CS](web-endpoints.md)
* Domain persistence
  * by [forging certificates with a stolen CA certificates](../../persistence/ca-shadow.md)
  * by trusting rogue CA certificates
  * by [maliciously creating vulnerable access controls](../../persistence/access-controls.md)

## Practice

### Terminology

> * **PKI** (Public Key Infrastructure) — a system to manage certificates/public key encryption
> * **AD CS** (Active Directory Certificate Services) — Microsoft’s PKI implementation
> * **CA **(Certificate Authority) — PKI server that issues certificates
> * **Enterprise CA** — CA integrated with AD (as opposed to a standalone CA), offers certificate templates
> * **Certificate Template** — a collection of settings and policies that defines the contents of a certificate issued by an enterprise CA
> * **CSR** (Certificate Signing Request) — a message sent to a CA to request a signed certificate
> * **EKU** (Extended/Enhanced Key Usage) — one or more object identifiers (OIDs) that define how a certificate can be used
>
> ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

### Recon

While AD CS offers attackers a wide range of exploitation and persistence scenarios, this set of services is not always installed, and when it is, it is a requirement to identify its different parts in the domain.

An initial indicator is the "Cert Publishers" built-in group whose members usually are the servers where AD CS is installed (i.e. PKI/CA).

* From UNIX-like systems: `rpc net group members "Cert Publishers" -U "DOMAIN"/"User"%"Password" -S "DomainController"`
* From Windows systems: `net group "Cert Publishers" /domain`

Alternatively, information like the PKI's CA and DNS names can be gathered through LDAP.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the [Certipy](https://github.com/ly4k/Certipy) (Python) tool can be used to operate multiple attacks and enumeration operations.

```bash
certipy 'domain.local'/'user':'password'@'domaincontroller' find
```



{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to operate multiple attacks and enumeration operations.

```batch
Certify.exe cas
```
{% endtab %}
{% endtabs %}

### Abuse

The different domain escalation scenarios are detailed in the following parts.

{% content-ref url="certificate-templates.md" %}
[certificate-templates.md](certificate-templates.md)
{% endcontent-ref %}

{% content-ref url="ca-configuration.md" %}
[ca-configuration.md](ca-configuration.md)
{% endcontent-ref %}

{% content-ref url="../../persistence/access-controls.md" %}
[access-controls.md](../../persistence/access-controls.md)
{% endcontent-ref %}

{% content-ref url="web-endpoints.md" %}
[web-endpoints.md](web-endpoints.md)
{% endcontent-ref %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment" %}

{% embed url="https://http418infosec.com/ad-cs-what-can-be-misconfigured" %}

{% embed url="https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks" %}
