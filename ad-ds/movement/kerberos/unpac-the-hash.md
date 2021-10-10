# UnPAC-the-hash

## Theory

When using PKINIT to obtain a TGT (Ticket Granting Ticket), the KDC (Key Distribution Center) includes in the ticket a `PAC_CREDENTIAL_INFO` structure containing the NTLM keys (i.e. LM and NT hashes) of the authenticating user. This feature allows users to switch to NTLM authentications when remote servers don't support Kerberos, while still relying on an asymmetric Kerberos pre-authentication verification mechanism (i.e. PKINIT).

The NTLM keys will then be recoverable after a TGS-REQ (U2U) which is a Service Ticket request made to the KDC where the user asks to authenticate to itself (User to User).

The following protocol diagram demonstrates how UnPAC-the-hash works. It allows attackers that know a user's private key, or attackers able to conduct a [Shadow Credentials](shadow-credentials.md) attacks, to recover the user's LM and NT hashes.

![](../../../.gitbook/assets/UnPAC-the-hash.png)

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, this attack can be conducted with [PKINITtools](https://github.com/dirkjanm/PKINITtools) (Python).

The first step consists in obtaining a TGT by validating a PKINIT pre-authentication first.

```python
gettgtpkinit.py -cert-pfx "PATH_TO_CERTIFICATE" -pfx-pass "CERTIFICATE_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
```

Once the TGT is obtained, and the session key extracted (printed by gettgtpkinit.py), the getnthash.py script can be used to recover the NT hash.

```bash
export KRB5CCNAME="TGT_CCACHE_FILE"
getnthash.py -key 'AS-REP encryption key' 'FQDN_DOMAIN'/'TARGET_SAMNAME'
```

The NT hash can be used for [pass-the-hash](../ntlm/pass-the-hash.md), [silver ticket](forged-tickets.md#silver-ticket), or [Kerberos delegations](delegations/) abuse.
{% endtab %}

{% tab title="Windows" %}
//Work in progress (use tools like Rubeus or kekeo)
{% endtab %}
{% endtabs %}

## Resource

{% embed url="https://shenaniganslabs.io/2021/06/21/Shadow-Credentials.html" %}

{% embed url="https://www.sstic.org/2014/presentation/secrets_dauthentification_pisode_ii__kerberos_contre-attaque/" %}

