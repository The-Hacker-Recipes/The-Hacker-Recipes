---
authors: ShutdownRepo
category: ad
---

# Certificate Services (AD-CS)

> [!TIP]
> See [AD > Movement > Certificate Services (AD-CS)](../../movement/adcs/index) to know more about it.

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) shared their research on AD CS and identified multiple theft, escalation and persistence vectors.

* Credential theft (dubbed THEFT1 to THEFT5)
* Account persistence (dubbed PERSIST1 to PERSIST3)
* Domain escalation (dubbed ESC1 to ESC14)
    * based on [misconfigured certificate templates](../../movement/adcs/certificate-templates.md)
    * based on [dangerous CA configuration](../../movement/adcs/certificate-authority.md)
    * related to [access control vulnerabilities](../../movement/adcs/access-controls.md)
    * based on an NTLM relay vulnerability related to the [unsigned endpoints of AD CS](../../movement/adcs/unsigned-endpoints.md)
* Domain persistence (dubbed DPERSIST1 to DPERSIST3)
    * by [forging certificates with a stolen CA certificates](certificate-authority.md#stolen-ca)
    * by [trusting rogue CA certificates](certificate-authority.md#rogue-ca)
    * by [maliciously creating vulnerable access controls](access-controls.md)