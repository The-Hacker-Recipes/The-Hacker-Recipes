---
authors: ShutdownRepo
category: ad
---

# Certificate Services (AD-CS)

## Theory

> AD CS is Microsoft’s PKI implementation that provides everything from encrypting file systems, to digital signatures, to user authentication (a large focus of our research), and more. While AD CS is not installed by default for Active Directory environments, from our experience in enterprise environments it is widely deployed, and the security ramifications of misconfigured certificate service instances are enormous. ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) shared their research on AD CS and identified multiple theft, escalation and persistence vectors.

* Credential theft (dubbed THEFT1 to THEFT5)
* Account persistence (dubbed PERSIST1 to PERSIST3)
* Domain escalation (dubbed ESC1 to ESC14)
 * based on [misconfigured certificate templates](certificate-templates.md)
 * based on [dangerous CA configuration](certificate-authority.md)
 * related to [access control vulnerabilities](access-controls.md)
 * based on an NTLM relay vulnerability related to the [web and RPC endpoints of AD CS](unsigned-endpoints.md)
* Domain persistence (dubbed DPERSIST1 to DPERSIST3)
 * by [forging certificates with a stolen CA certificates](certificate-authority.md#stolen-ca)
 * by trusting rogue CA certificates
 * by [maliciously creating vulnerable access controls](../../persistence/dacl)

## Practice

### Escalation techniques

- [ESC1 "template-allows-san"](certificate-templates.md#template-allows-san-esc1)
- [ESC2  "any-purpose-eku"](certificate-templates.md#any-purpose-eku-esc2)
- [ESC3  "certificate-agent-eku"](certificate-templates.md#certificate-agent-eku-esc3)
- [ESC4  "certificate-templates"](access-controls.md#certificate-templates-esc4)
- [ESC5  "other-objects"](access-controls.md#other-objects-esc5)
- [ESC6  "editf_attributesubjectaltname2"](certificate-authority.md#editf_attributesubjectaltname2-esc6)
- [ESC7  "certificate-authority"](access-controls.md#certificate-authority-esc7)
- [ESC8  "web-endpoint-esc8](unsigned-endpoints.md#web-endpoint-esc8)
- [ESC9  "no-security-extension"](certificate-templates.md#no-security-extension-esc9)
- [ESC10  "weak-certificate-mapping"](certificate-templates.md#weak-certificate-mapping-esc10)
- [ESC11  "rpc-endpoint"](unsigned-endpoints.md#rpc-endpoint-esc11)
- [ESC12  "shell-access-to-adcs-ca-with-yubihsm"](certificate-authority.md#shell-access-to-adcs-ca-with-yubihsm-esc12)
- [ESC13  "issuance-policiy-with-privileged-group-linked"](certificate-templates.md#esc13-issuance-policiy-with-privileged-group-linked)
- [ESC14  "weak-explicit-mapping"](certificate-templates.md#esc14-weak-explicit-mapping)
- [ESC15  "arbitrary application policy"](certificate-templates.md#esc15-CVE-2024-49019-arbitrary-application-policy)
- [Certifried.md](certifried.md)

### Terminology

> * PKI (Public Key Infrastructure) — a system to manage certificates/public key encryption
> * AD CS (Active Directory Certificate Services) — Microsoft’s PKI implementation
> * CA (Certificate Authority) — PKI server that issues certificates
> * Enterprise CA — CA integrated with AD (as opposed to a standalone CA), offers certificate templates
> * Certificate Template — a collection of settings and policies that defines the contents of a certificate issued by an enterprise CA
> * CSR (Certificate Signing Request) — a message sent to a CA to request a signed certificate
> * EKU (Extended/Enhanced Key Usage) — one or more object identifiers (OIDs) that define how a certificate can be used
> * Application Policy — this does the same thing as EKUs, but with a few more options. Specific to Windows environments
>
> ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

### Recon

While AD CS offers attackers a wide range of exploitation and persistence scenarios, this set of services is not always installed, and when it is, it is a requirement to identify its different parts in the domain.

#### Cert Publishers

An initial indicator is the "Cert Publishers" built-in group whose members usually are the servers where AD CS is installed (i.e. PKI/CA).

* From UNIX-like systems: `net rpc group members "Cert Publishers" -U "DOMAIN"/"User"%"Password" -S "DomainController"`
* From Windows systems: `net group "Cert Publishers" /domain`

#### `pKIEnrollmentService` objects

Alternatively, information like the PKI's CA and DNS names can be gathered through LDAP.

::: tabs

=== netexec

[netexec](https://github.com/Pennyw0rth/NetExec)'s [adcs](https://github.com/Pennyw0rth/NetExec/blob/master/cme/modules/adcs.py) module (Python) can be used to find PKI enrollment services in AD.

```bash
netexec ldap 'domaincontroller' -d 'domain' -u 'user' -p 'password' -M adcs
```


=== windapsearch

[windapsearch ](https://github.com/ropnop/windapsearch)(Python) can be used to manually to the LDAP query.

```bash
windapsearch -m custom --filter '(objectCategory=pKIEnrollmentService)' --base 'CN=Configuration,DC=domain,DC=local' --attrs dn,dnshostname --dc 'domaincontroller' -d 'domain.local' -u 'user' -p 'password'
```


=== ntlmrelayx

With [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python), thanks to [SAERXCIT](https://twitter.com/saerxcit) ([PR#1214](https://github.com/SecureAuthCorp/impacket/pull/1214)), it is possible to gather information regarding ADCS like the name and host of the CA, the certificate templates enrollment rights for those allowing client authentication and not requiring manager approval, etc. With ntlmrelayx, these information can be gathered through a relayed LDAP session.

```bash
ntlmrelayx -t "ldap://domaincontroller" --dump-adcs
```

:::


#### Attack paths

> [!TIP]
> [Certipy](https://github.com/ly4k/Certipy) (Python) and [Certify](https://github.com/GhostPack/Certify) (C#) can also identify the PKI enrollment services and potential attack paths.

::: tabs

=== UNIX-like

From UNIX-like systems, the [Certipy](https://github.com/ly4k/Certipy) (Python) tool can be used to operate multiple attacks and enumeration operations.

```python
# enumerate and save text, json and bloodhound (original) outputs
certipy find -u 'user@domain.local' -p 'password' -dc-ip 'DC_IP' -old-bloodhound

# quickly spot vulnerable elements
certipy find -u 'user@domain.local' -p 'password' -dc-ip 'DC_IP' -vulnerable -stdout
```

Certipy also supports BloodHound. With the `-old-bloodhound` option, the data will be exported for the original version of [BloodHound](https://github.com/BloodHoundAD/BloodHound). With the `-bloodhound` option, the data will be exported for the modified version of BloodHound, [forked](https://github.com/ly4k/BloodHound/) by Certipy's [author](https://twitter.com/ly4k_) (default output when no flag is set).

The tool also supports multiple output types (text, json, stdout).

> [!TIP]
> By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.

=== Windows

From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to operate multiple attacks and enumeration operations.

```powershell
Certify.exe cas
```

:::


### Abuse

The different domain escalation scenarios are detailed in the following parts.

- ESC1 to ESC3, ESC9, ESC10, ESC13, ESC14 and ESC15: [Certificate Templates](certificate-templates.md)
- ESC6 and ESC12: [Certificate Authority](certificate-authority.md)
- ESC4, ESC5 & ESC7: [Access Controls](access-controls.md)
- ESC8, ESC11: [Unsigned Endpoints](unsigned-endpoints.md)


## Resources

[https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

[https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment)

[https://http418infosec.com/ad-cs-what-can-be-misconfigured](https://http418infosec.com/ad-cs-what-can-be-misconfigured)

[https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks](https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks)

[https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)

[https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
