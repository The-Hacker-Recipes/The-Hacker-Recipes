# 🛠️ Certificate Services (AD-CS)

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

Many types of vulns

* Misconfigured Certificate Templates: ESC1, ESC2
* Enrollment Agent Templates: ESC3
* Certificate Template Access Control (ACE abuse): ESC4
* PKI Object Access Control (ACE abuse): ESC5
* Configuration data: The EDITF\_ATTRIBUTESUBJECTALTNAME2 flag: ESC6
* Certificate Authority Access Control: ESC7
* HTTP endpoints (NTLM relay): ESC8

Talk about how to find if AD CS is installed and so on, where is it&#x20;

Talk about the Cert Publishers built-in group that contains the PKI

## Practice

//WIP

## Resources

[https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)\
[https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)\
[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

\
