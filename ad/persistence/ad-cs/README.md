# Certificate Services (AD-CS)

{% hint style="info" %}
See [AD > Movement > Certificate Services (AD-CS)](../../movement/ad-cs/) to know more about it.
{% endhint %}

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) shared their research on AD CS and identified multiple theft, escalation and persistence vectors.

* **Credential theft** (dubbed THEFT1 to THEFT5)
* **Account persistence** (dubbed PERSIST1 to PERSIST3)
* **Domain escalation** (dubbed ESC1 to ESC8)
  * based on [misconfigured certificate templates](../../movement/ad-cs/certificate-templates.md)
  * based on [dangerous CA configuration](../../movement/ad-cs/certificate-authority.md)
  * related to [access control vulnerabilities](../../movement/ad-cs/access-controls.md)
  * based on an NTLM relay vulnerability related to the [web endpoints of AD CS](../../movement/ad-cs/web-endpoints.md)
* **Domain persistence** (dubbed DPERSIST1 to DPERSIST3)
  * by [forging certificates with a stolen CA certificates](certificate-authority.md#stolen-ca)
  * by [trusting rogue CA certificates](certificate-authority.md#rogue-ca)
  * by [maliciously creating vulnerable access controls](access-controls.md)
