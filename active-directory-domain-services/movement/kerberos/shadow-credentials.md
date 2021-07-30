# 🛠️ Shadow Credentials

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A TGS \(Ticket Granting Service\) can be obtained by presenting a TGT \(Ticket Granting Ticket\). That prior TGT can only be obtained by validating a first step named "pre-authentication". The pre-authentication can be validated symmetrically \(with a DES, RC4, AES128 or AES256 key\) or asymmetrically \(with certificates\). The asymmetrical way of pre-authenticating is called PKINIT. 

> The client has a public-private key pair, and encrypts the pre-authentication data with their private key, and the KDC decrypts it with the client’s public key. The KDC also has a public-private key pair, allowing for the exchange of a session key. \([specterops.io](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)\)

Active Directory user and computer objects have an attribute called `msDS-KeyCredentialLink` where raw RSA public keys can be set. When trying to pre-authenticate with PKINIT, a timestamp will be encrypted with the matching private key, the KDC will try to decrypt it to check that the authenticating user has knowledge of the private key, and a TGT will be sent if there is a match.

There are multiple scenarios where an attacker can have control over an account that has the ability to edit the `msDS-KeyCredentialLink` attribute of other objects \(e.g. member of a [special group](../privileged-groups.md), has [powerful ACEs](../access-control-entries/), etc.\). This enables attackers to create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target object \(can be a user or a computer\).

## Practice

In order to exploit that technique, the attacker has to 

1. be in a domain with a Domain Functional Level of Windows Server 2016 or above
2. be in a domain with at least one Domain Controller running Windows Server 2016 or above
3. be in a domain where the Domain Controller\(s\) has its own key pair \(for the session key exchange\) \(e.g. happens when AD CS is enabled or when a CA is in place\).
4. have control over an account that can edit the target object's `msDs-KeyCredentialLink` attribute.

If those per-requisites are met, an attacker can

1. create an RSA key pair
2. create an X509 certificate configured with the public key
3. create a [KeyCredential](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af) structure featuring the raw public key and add it to the `msDs-KeyCredentialLink` attribute
4. authenticate using PKINIT and the certificate and private key

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like, the `msDs-KeyCredentialLink` attribute of a user or computer target can be manipulated with the [pyWhisker](https://github.com/ShutdownRepo/pywhisker) tool.

```bash

```
{% endtab %}

{% tab title="Windows" %}
From UNIX-like, the `msDs-KeyCredentialLink` attribute of a user or computer target can be manipulated with the [Whisker](https://github.com/eladshamir/Whisker) tool.

```bash
Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
```

Rubeus

```bash

```
{% endtab %}
{% endtabs %}



## Resources

{% embed url="https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" %}





For WriteProperty at least ?

For special members of groups like Enterprise Key Admins and Key Admins

[https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

[https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)

