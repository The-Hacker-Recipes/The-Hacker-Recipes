# Certificate Services (AD-CS)

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [that blogpost](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) shared their research on AD CS and identified multiple theft, escalation and persistence vectors.

* Credential theft (THEFT1 to THEFT5)
* Account persistence (PERSIST1 to PERSIST3)
* Domain escalation (ESC1 to ESC8)
  * based on [misconfigured certificate templates](certificate-templates.md) (ESC1, ESC2 and ESC3)
  * based on [vulnerable configuration data](configuration-data.md) (ESC6)
  * related to [access control vulnerabilities](access-controls.md) (ESC4, ESC5 and ESC7)
  * based on an NTLM relay vulnerability related to the [web endpoints of AD CS](web-endpoints.md) (ESC8)
* Domain persistence (DPERSIST1 to DPERSIST3)
  * by [forging certificates with a stolen CA certificates](../../persistence/ca-shadow.md) (DPERSIST1)
  * by trusting rogue CA certificates (DPERSIST2)
  * by [maliciously creating vulnerable access controls](../../persistence/access-controls.md) (DPERSIST3)

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

An initial indicator is the "Cert Publishers" built-in group whose members usually are the CA/servers where AD CS is installed.

* From UNIX-like systems: `rpc net group members "Cert Publishers" -U "DOMAIN"/"User"%"Password" -S "DomainController"`
* From Windows systems: `net group "Cert Publishers" /domain`

From a domain-joined Windows system, the `certutil.exe` executable can also be used to quickly identify the Certificate Authority/PKI Server: `.\certutil.exe`.

### Abuse

The different domain escalation scenarios are detailed in the following parts.

{% content-ref url="certificate-templates.md" %}
[certificate-templates.md](certificate-templates.md)
{% endcontent-ref %}

{% content-ref url="configuration-data.md" %}
[configuration-data.md](configuration-data.md)
{% endcontent-ref %}

{% content-ref url="../access-controls/" %}
[access-controls](../access-controls/)
{% endcontent-ref %}

{% content-ref url="web-endpoints.md" %}
[web-endpoints.md](web-endpoints.md)
{% endcontent-ref %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment" %}
