# Shadow Credentials

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. An ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can only be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to [ASREProast](asreproast.md)). The pre-authentication can be validated symmetrically (with a DES, RC4, AES128 or AES256 key) or asymmetrically (with certificates). The asymmetrical way of pre-authenticating is called PKINIT.&#x20;

> The client has a public-private key pair, and encrypts the pre-authentication data with their private key, and the KDC decrypts it with the client’s public key. The KDC also has a public-private key pair, allowing for the exchange of a session key. ([specterops.io](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab))

Active Directory user and computer objects have an attribute called `msDS-KeyCredentialLink` where raw public keys can be set. When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

There are multiple scenarios where an attacker can have control over an account that has the ability to edit the `msDS-KeyCredentialLink` (a.k.a. "kcl") attribute of other objects (e.g. member of a [special group](../domain-settings/builtin-groups.md), has [powerful ACEs](../dacl/), etc.). This allows attackers to create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target object (can be a user or a computer).

## Practice

In order to exploit that technique, the attacker needs to:

1. be in a domain that supports PKINIT and containing at least one Domain Controller running Windows Server 2016 or above.&#x20;
2. be in a domain where the Domain Controller(s) has its own key pair (for the session key exchange) (e.g. happens when AD CS is enabled or when a certificate authority (CA) is in place).
3. have control over an account that can edit the target object's `msDs-KeyCredentialLink` attribute.

{% hint style="info" %}
The `msDS-KeyCredentialLink` feature was introduced with Windows Server 2016. However, this is not to be confused with PKINIT which was already present in Windows 2000. The `msDS-KeyCredentialLink` feature allows to link an X509 certificate to a domain object, that's all.
{% endhint %}

If those per-requisites are met, an attacker can

1. create an RSA key pair
2. create an X509 certificate configured with the public key
3. create a [KeyCredential](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af) structure featuring the raw public key and add it to the `msDs-KeyCredentialLink` attribute
4. authenticate using PKINIT and the certificate and private key

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the `msDs-KeyCredentialLink` attribute of a user or computer target can be manipulated with the [pyWhisker](https://github.com/ShutdownRepo/pywhisker) tool.

```bash
pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
```

{% hint style="info" %}
The "add" action from pywhisker is featured in ntlmrelayx.

```bash
ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'
```
{% endhint %}

When the public key has been set in the `msDs-KeyCredentialLink` of the target, the certificate generated can be used with [Pass-the-Certificate](pass-the-certificate.md) to obtain a TGT and further access.
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the `msDs-KeyCredentialLink` attribute of a target user or computer can be manipulated with the [Whisker](https://github.com/eladshamir/Whisker) tool.

```bash
Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
```

When the public key has been set in the `msDs-KeyCredentialLink` of the target, the certificate generated can be used with [Pass-the-Certificate](pass-the-certificate.md) to obtain a TGT and further access.
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Nota bene**

User objects can't edit their own `msDS-KeyCredentialLink` attribute while computer objects can. This means the following scenario could work: [trigger an NTLM authentication](../mitm-and-coerced-authentications/) from DC01, [relay it](../ntlm/relay.md) to DC02, make pywhisker edit DC01's attribute to create a Kerberos PKINIT pre-authentication backdoor on it, and have persistent access to DC01 with PKINIT and [pass-the-cache](ptc.md).

Computer objects can only edit their own `msDS-KeyCredentialLink` attribute if KeyCredential is not set already.
{% endhint %}

## Resources

{% embed url="https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" %}

{% embed url="https://github.com/eladshamir/Whisker" %}

{% embed url="https://github.com/ShutdownRepo/pywhisker" %}
