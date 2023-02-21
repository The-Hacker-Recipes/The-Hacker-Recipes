# Web endpoints

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found a domain escalation vector based on web endpoints vulnerable to [NTLM relay attacks](../ntlm/relay.md). The escalation vector was dubbed [ESC8](https://posts.specterops.io/certified-pre-owned-d95910965cd2#48bd).

> AD CS supports several HTTP-based enrollment methods via additional server roles that administrators can optionally install \[(The certificate enrollment web interface, Certificate Enrollment Service (CES), Network Device Enrollment Service (NDES)).]
>
> \[...]
>
> These HTTP-based certificate enrollment interfaces are all vulnerable to NTLM relay attacks. Using NTLM relay, an attacker can impersonate an inbound-NTLM-authenticating victim user. While impersonating the victim user, an attacker could access these web interfaces and request a client authentication certificate based on the "User" or "Machine" certificate templates.
>
> ([specterops.io](https://posts.specterops.io/certified-pre-owned-d95910965cd2#5c3c))

This attack, like all [NTLM relay attacks](../ntlm/relay.md), requires a victim account to authenticate to an attacker-controlled machine. An attacker can coerce authentication by many means, see [MITM and coerced authentication coercion techniques](../mitm-and-coerced-authentications/). Once the incoming authentication is received by the attacker, it can be relayed to an AD CS web endpoint.

Once the relayed session is obtained, the attacker poses as the relayed account and can request a client authentication certificate. The certificate template used needs to be configured for authentication (i.e. EKUs like Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose (`OID 2.5.29.37.0`), or no EKU (`SubCA`)) and allowing low-priv users to enroll can be abused to authenticate as any other user/machine/admin.

{% hint style="success" %}
The default **User** and **Machine/Computer** templates match those criteria and are very often enabled.
{% endhint %}

This allows for lateral movement, account persistence, and in some cases privilege escalation if the relayed user had powerful privileges (e.g., domain controllers or Exchange servers, domain admins etc.).

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
**1 - Setting up the relay servers** :tools:****

From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python) can be used to conduct the ESC8 escalation scenario.

```python
ntlmrelayx -t "http://CA/certsrv/certfnsh.asp" --adcs --template "Template name"
```

{% hint style="info" %}
The certificate template flag (i.e. `--template`) can either be left blank (default to **Machine** at the time of writing, October 20th 2012) or chosen among the certificate templates that fill the requirements.&#x20;
{% endhint %}

[Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate information regarding the certificate templates (EKUs allowing for authentication, allowing low-priv users to enroll, etc.) ([how to enumerate](./#attack-paths)).

<pre class="language-python"><code class="lang-python"><strong># find ESC8-vulnerable CAs
</strong><strong>certipy find -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -stdout | grep -B20 ESC8
</strong><strong>
</strong><strong># find and look through enabled templates for ones that could be used for authentication
</strong>certipy find -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -stdout -enabled
</code></pre>

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}

**2 - Authentication coercion** :chains:****

Just like any other NTLM relay attack, once the relay servers are running and waiting for incoming NTLM authentications, authentication coercion techniques can be used (e.g. [PrinterBug](../mitm-and-coerced-authentications/ms-rprn.md), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr.md), [PrivExchange](../mitm-and-coerced-authentications/pushsubscription-abuse.md)) to force accounts/machines to authenticate to the relay servers.

{% content-ref url="../mitm-and-coerced-authentications/" %}
[mitm-and-coerced-authentications](../mitm-and-coerced-authentications/)
{% endcontent-ref %}

**3 - Loot** :tada:

Once incoming NTLM authentications are relayed and authenticated sessions abused, base64-encoded PFX certificates will be obtained and usable with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate enabled web endpoints (both HTTP and HTTPS).

```batch
Certify.exe cas
```

{% hint style="warning" %}
If web endpoints are enabled, switch to UNIX because at the time of writing (October 20th, 2021), I don't know how to easily conduct the ESC8 abuse from Windows.
{% endhint %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide" %}

{% embed url="https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services" %}

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}
