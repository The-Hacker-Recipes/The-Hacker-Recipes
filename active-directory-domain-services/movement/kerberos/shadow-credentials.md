# 🛠️ Shadow Credentials

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A TGS \(Ticket Granting Service\) can be obtained by presenting a TGT \(Ticket Granting Ticket\). That prior TGT can only be obtained by validating a first step named "pre-authentication". The pre-authentication can be validated symmetrically \(with a DES, RC4, AES128 or AES256 key\) or asymmetrically \(with certificates\). The asymmetrical way of pre-authenticating is called PKINIT. 

> The client has a public-private key pair, and encrypts the pre-authentication data with their private key, and the KDC decrypts it with the client’s public key. The KDC also has a public-private key pair, allowing for the exchange of a session key. \([specterops.io](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)\)

//TODO

## Practice

//TODO

{% tabs %}
{% tab title="UNIX-like" %}
The `msDs-KeyCredentialLink` attribute of a user or computer target can be manipulated with the pyWhisker tool.

```bash

```
{% endtab %}

{% tab title="Windows" %}

{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" %}





For WriteProperty at least ?

For special members of groups like Enterprise Key Admins and Key Admins

[https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

[https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)

