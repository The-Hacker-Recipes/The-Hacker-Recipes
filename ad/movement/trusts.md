# Trusts

## Theory

### Forest, domains & trusts

An Active Directory **domain** is a collection of computers, users, and other resources that are all managed together. A domain has its own security database, which is used to authenticate users and computers when they log in or access resources within the domain.

A **forest** is a collection of one or more Active Directory domains that share a common schema, configuration, and global catalog. The schema defines the kinds of objects that can be created within the forest, and the global catalog is a centralized database that contains a searchable, partial replica of every domain in the forest.

**Trust relationships** between domains allow users in one domain to access resources in another domain. There are several types of trust relationships that can be established, including one-way trusts, two-way trusts, external trusts, etc.

Once a trust relationship is established between a **trusting domain** (A) and **trusted domain** (B), users from the trusted domain can authenticate to the trusting domain's resources. In other -more technical- terms, trusts extend the security boundary of a domain or forest.

{% hint style="info" %}
Simply establishing a trust relationship does not automatically grant access to resources. In order to access a "trusting" resource, a "trusted" user must have the appropriate permissions to that resource. These permissions can be granted by adding the user to a group that has access to the resource, or by giving the user explicit permissions to the resource.

A trust relationship allows users in one domain to **authenticate** to the other domain's resources, but it does not automatically grant access to them. Access to resources is controlled by permissions, which must be granted explicitly to the user in order for them to access the resources.
{% endhint %}

### Trust types

1. **Parent-Child**: this type of trust relationship exists between a parent domain and a child domain in the same forest. The parent domain trusts the child domain, and the child domain trusts the parent domain. This type of trust is automatically created when a new child domain is created in a forest.
2. **Tree-Root**: exists between the root domain of a tree and the root domain of another tree in the same forest. This type of trust is automatically created when a new tree is created in a forest.
3. **Shortcut (a.k.a. cross-link)**: exists between two child domains of different tree (i.e. different parent domains) within the same forest. This type of trust relationship is used to reduce the number of authentication hops between distant domains. It is a one-way or two-way transitive trust.
4. **External**: exists between a domain in one forest and a domain in a different forest. It allows users in one domain to access resources in the other domain. It's usually set up when accessing resources in a forest without trust relationships established.
5. **Forest**: exists between two forests (i.e. between two root domains in their respective forest). It allows users in one forest to access resources in the other forest.
6. **Realm**: exists between a Windows domain and a non-Windows domain, such as a Kerberos realm. It allows users in the Windows domain to access resources in the non-Windows domain.

| Trust type                   | Transitivity   | Direction | Auth. mechanisms |
| ---------------------------- | -------------- | --------- | ---------------- |
| Parent-Child                 | Transitive     | Two-way   | Either           |
| Tree-Root                    | Transitive     | Two-way   | Either           |
| Shortcut (a.k.a. cross-link) | Transitive     | Either    | Either           |
| Realm                        | Either         | Either    | Kerberos V5 only |
| Forest                       | Transitive     | Either    | Either           |
| External                     | Non-transitive | One-way   | NTLM only        |

### Transitivity

In Active Directory, a transitive trust is a type of trust relationship that allows access to resources to be passed from one domain to another. When a transitive trust is established between two domains, any trusts that have been established with the first domain are automatically extended to the second domain. This means that if Domain A trusts Domain B and Domain B trusts Domain C, then Domain A automatically trusts Domain C, even if there is no direct trust relationship between Domain A and Domain C. Transitive trusts are useful in large, complex networks where multiple trust relationships have been established between many different domains. They help to simplify the process of accessing resources and reduce the number of authentication hops that may be required.

{% hint style="info" %}
The transitivity status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the `TRUST_ATTRIBUTE_NON_TRANSITIVE (0x00000001)` flag is set then the transitivity is **disabled**.&#x20;
> * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set then the transitivity is **enabled**.&#x20;
> * If the `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008)` flag is set then the transitivity is **enabled**.
>
> In any other case the transitivity is **disabled**.
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
{% endhint %}

### SID filtering

According to Microsoft, the security boundary in Active Directory is the forest, not the domain. The forest defines the boundaries of trust and controls access to resources within the forest.

The domain is a unit within a forest and represents a logical grouping of users, computers, and other resources. Users within a domain can access resources within their own domain and can also access resources in other domains within the same forest, as long as they have the appropriate permissions. Users cannot access resources in other forests unless a trust relationship has been established between the forests.

Technically, the security boundary is mainly enforced with SID filtering (and other security settings). This mechanism makes sure "only SIDs from the trusted domain will be accepted for authorization data returned during authentication. SIDs from other domains will be removed" (`netdom` cmdlet output). By default, SID filtering is disabled for intra-forest trusts, and enabled for inter-forest trusts. Section [4.1.2.2](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) of \[MS-PAC] specifies what is filtered when.

Nota bene, there are two kinds of inter-forest trusts: "Forest", and "External" (see [trust types](trusts.md#trust-types)). Microsoft says "[cross-forest trusts are more stringently filtered than external trusts](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab?redirectedfrom=MSDN)", meaning that in External trusts, SID filtering only filters out RID < 1000.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p>[MS-PAC] section 4.1.2.2</p></figcaption></figure>

{% hint style="info" %}
The SID filtering status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4) as well as the type of trust.&#x20;

> * If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then only SIDs from the trusted domain are allowed (all others are filtered --> I'm not sure about that. I need to test what happens in case the TATE flag is added on top of TAQD).
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_

Above are some key, usually valid, elements. But as [Carsten Sandker](https://twitter.com/0xcsandker) puts it: "the logic that sits behind this might be too complex to put it in text". To really know the behavior of SID filtering for a trust, refer to the lookup tables [here](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/OC-b4We5WFiXhTirzI\_Dyw.png) (for default configs) and [there](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/99icUS7SKCscWq6VzW0o5g.png) (for custom configs).

.

.

.

make sure below

.

`(0x00000040) TREAT_AS_EXTERNAL`: "the trust is to be treated as external \[...]. If this bit is set, then a cross-forest trust to a domain is to be treated as an external trust for the purposes of SID Filtering. Cross-forest trusts are more stringently filtered than external trusts. This attribute relaxes those cross-forest trusts to be equivalent to external trusts." ([Microsoft](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN))

If this flag is set, it means a inter-forest ticket spoofing an RID >1000 can be forged. This can usually lead to the trusting domain compromise. See [SID filtering](trusts.md#sid-filtering), and notes on [SID history](trusts.md#sid-history).
{% endhint %}

### SID history

This characteristic of trusts is a bit special, since it's not really one. Many resources across the Internet, including Microsoft's docs and tools, state that SID history can be enabled across a trust. This is not 100% true.

The **SID (Security Identifier)** is a unique identifier that is assigned to each security principal (e.g. user, group, computer). It is used to identify the principal within the domain and is used to control access to resources.

The **SID history** is a property of a user or group object that allows the object to retain its SID when it is migrated from one domain to another as part of a domain consolidation or restructuring. When an object is migrated to a new domain, it is assigned a new SID in the target domain. The SID history allows the object to retain its original SID, so that access to resources in the source domain is not lost.

When authenticating across trusts using Kerberos, it is assumed that the extra SID field of the ticket's PAC (Privileged Attribute Certificate) reflects the SID history attribute of the authenticating user. With [SID filtering](trusts.md#sid-filtering) enabled in a trust, the SIDs contained in that field are filtered, effectively preventing SID history from doing its job. There are certain scenarios where some SIDs are not filtered, allowing for example SIDs with a RID >1000. Some call it "enabling SID history", I'd call it "partial SID filtering", or "unencumbered SID history". [Dirk-jan Mollema](https://twitter.com/\_dirkjan) calls that "[SID filtering relaxation](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/#sid-filtering-relaxation)".

// A similar process is conducted when using NTLM. \<TODO> how is SID filtering enforced when using NTLM ? Change this section and [NTLM authentication](trusts.md#ntlm-authentication) accordingly.

### Authentication level

Inter-forest trusts ("External" and "Forest" trusts) can be configured with different levels of authentication:

* **Forest-wide authentication**: allows unrestricted authentication from the trusted forest's principals to the trusting forest's resources. This is the least secure level, it completely opens one forest to another (authentication-wise though, not access-wise).
* **Domain-wide authentication**: allows unrestricted authentication from the trusted domain's principals to the trusting domain's resources. This is more secure than forest-wide authentication because it only allows users in a specific (trusted) domain to access resources in another (trusting). // TODO need to check that :warning:
* **Selective authentication**: allows only specific users in the trusting domain to access resources in the trusted domain. This is the most secure type of trust because it allows administrators to tightly control access to resources in the trusted domain.

It's worth noting that selective authentication is less used by the general public due to complexity of maintenance. In most cases domain wide authentication is used for most organizations.

// selective auth : target object's DACL must include extended right allowed to authenticate 68b1d179-0d15-4d4f-ab71-46152e79a7bc. For everything else, authentication will be blocked.

{% hint style="info" %}
The authentication level of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set then **Forest-Wide Authentication** is used.&#x20;
> * If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x00000010)` flag is set then **Selective Authentication** is used.
>
> In any other case **Forest-Wide Authentication** is used.
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
{% endhint %}

### TGT delegation

// Kerberos delegation, KUD works by delegating TGT in the ticket. TGT delegation prevention block unconstrained delegation accross trusts, if that mechanism is enabled.

{% hint style="info" %}
The TGT delegation status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4).

> * If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x00000200)` flag is set, then TGT Delegation is **disabled**.&#x20;
> * If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then TGT Delegation is **disabled**.
> * If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x00000800)`flag is set, then TGT Delegation is **enabled**.&#x20;
> * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set, then TGT Delegation is **enabled**.
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
{% endhint %}

### Kerberos authentication

Understanding how Kerberos works is required here: [the Kerberos protocol](kerberos/).

> In order for a Kerberos authentication to occur across a domain trust, the kerberos key distribution centers (KDCs) in two domains must have a shared secret, called an inter-realm key. This key is [derived from a shared password](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378170\(v=vs.85\).aspx), and rotates approximately every 30 days. Parent-child domains share an inter-realm key implicitly.
>
> When a user in domain A tries to authenticate or access a resource in domain B that he has established access to, he presents his ticket-granting-ticket (TGT) and request for a service ticket to the KDC for domain A. The KDC for A determines that the resource is not in its realm, and issues the user a referral ticket.
>
> This referral ticket is a ticket-granting-ticket (TGT) encrypted with the inter-realm key shared by domain A and B. The user presents this referral ticket to the KDC for domain B, which decrypts it with the inter-realm key, checks if the user in the ticket has access to the requested resource, and issues a service ticket. This process is described in detail in [Microsoft’s documentation](https://technet.microsoft.com/en-us/library/cc772815\(v=ws.10\).aspx#w2k3tr\_kerb\_how\_pzvx) in the **Simple Cross-Realm Authentication and Examples** section.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/)_)_

From an offensive point of view, just like a [golden ticket](kerberos/forged-tickets/golden.md), a referral ticket could be forged. Forging a referral ticket using the inter-realm key, instead of relying on the krbtgt keys for a golden ticket, is a nice alternative for organizations that choose to roll their krbtgt keys, as they should. This technique is [a little bit trickier](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#do-you-need-to-use-inter-realm-tickets) though, as it requires to [use the correct key](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#which-keys-do-i-need-for-inter-realm-tickets).

Depending on the trust characteristics, ticket forgery can also be combined with [SID history](trusts.md#sid-history) spoofing for a direct privilege escalation from a child to a parent domain.

When using Kerberos authentication across trusts, the trusting domain's domain controller does

* [SID filtering](trusts.md#sid-filtering) during [PAC validation](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
* [TGT delegation](trusts.md#tgt-delegation) verification, and [Selective Authentication](trusts.md#authentication-level) limitation during the [TGS (Ticket Granting Service) exchange](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3) (when asked for a Service Ticket for a service configured for unconstrained delegation).&#x20;

### NTLM authentication

// [https://www.rebeladmin.com/tag/sid/](https://www.rebeladmin.com/tag/sid/) pass through authentication [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178\(v=ws.10\)?redirectedfrom=MSDN)

// selective auth : [https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72)

## Practice

### Enumeration

Several tools can be used to enumerate trust relationships. The following major characteristic must be looked for, some of which are directly readable from the [TDO (Trusted Domain Object)](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4) attributes and others need a little bit of logic.

* **Trust partner**: trusting domain for outbound trusts, trusted domain for inbound trusts. Bidirectional trusts are two one-way trusts. Retrieved from the TDO attribute `trustPartner` value.
* **Trust direction**: inbound, outbound, or bidirectional. Retrieved from the TDO attribute `trustDirection` integer value.
* **Trust type**: Parent-Child, Tree-Root, Shortcut (a.k.a. "Cross-Link"), Forest, External, or Realm (a.k.a. "Kerberos").
* **Trust authentication level, transitivity, TGT delegation and SID filtering**: Retrieved from a set of flags in the TDO's `trustAttributes` attribute, combined with the type of trust (see [authentication level](trusts.md#authentication-level), [transitivity](trusts.md#transitivity), [TGT delegation](trusts.md#tgt-delegation) and [SID filtering](trusts.md#sid-filtering)).

{% hint style="info" %}
> Keep in mind that there is a TDO \[([Trusted Domain Object](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f2ceef4e-999b-4276-84cd-2e2829de5fc4))] for each side of the Trust relationship so always analyze both TDOs for each trust. \[...]
>
> It's important to check both ends of the trust (because the characteristics could differ). \[...]
>
> All the trust relationship information are fetched via LDAP and preferably (if that server is operational) from the Global Catalog server. As the Global catalog contains information about every object in the forest it might also contain information about trust entities that you can't reach (e.g. due to network segmentation or because they are offline).
>
> _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, tools like [ldeep](https://github.com/franc-pentest/ldeep) (Python), [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) (Python), [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) (Python) and [ldapsearch](https://git.openldap.org/openldap/openldap) (C) can be used to enumerate trusts.

<pre class="language-bash"><code class="lang-bash"><strong># ldeep supports cleartext, pass-the-hash, pass-the-ticket, etc.
</strong><strong>ldeep ldap -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -s ldap://"$DC_IP" trusts
</strong>
# ldapdomaindump will store HTML, JSON and Greppable output
ldapdomaindump --user 'DOMAIN\USER' --password "$PASSWORD" --outdir "ldapdomaindump" "$DC_HOST"

# ldapsearch-ad
ldapsearch-ad --server "$DC_HOST" --domain "$DOMAIN" --username "$USER" --password "$PASSWORD" --type trusts

# ldapsearch
ldapsearch -h ldap://"$DC_IP" -b "CN=SYSTEM,DC=$DOMAIN" "(objectclass=trustedDomain)"
</code></pre>

[BloodHound](../recon/bloodhound.md) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.
{% endtab %}

{% tab title="Windows" %}
From Windows systems, many tools like can be used to enumerate trusts. "[A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts)" by [Will Schroeder](https://twitter.com/harmj0y) provides more in-depth guidance on how to enumerate and visually map domain trusts (in the "Visualizing Domain Trusts" section), as well as identify potential attack paths ("Foreign Relationship Enumeration" section).

### netdom

From domain-joined hosts, the `netdom` cmdlet can be used.

```batch
netdom trust /domain:DOMAIN.LOCAL
```

### PowerView

Alternatively, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) supports multiple commands for various purposes.

| Command                                                   | Alias                                                                                                  | Description |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- |
| <pre><code><strong>Get-DomainTrust
</strong></code></pre> |                                                                                                        |             |
|                                                           | <pre><code><strong>Get-NetDomainTrust
</strong></code></pre>                                           |             |
|                                                           | gets all trusts for the current user's domain                                                          |             |
| <pre><code>Get-ForestTrust
</code></pre>                  |                                                                                                        |             |
|                                                           | <pre><code>Get-NetForestTrust
</code></pre>                                                            |             |
|                                                           | gets all trusts for the forest associated with the current user's domain                               |             |
| <pre><code>Get-DomainForeignUser
</code></pre>            |                                                                                                        |             |
|                                                           | <pre><code>Find-ForeignUser
</code></pre>                                                              |             |
|                                                           | enumerates users who are in groups outside of their principal domain                                   |             |
| <pre><code>Get-DomainForeignGroupMember
</code></pre>     |                                                                                                        |             |
|                                                           | <pre><code>Find-ForeignGroup
</code></pre>                                                             |             |
|                                                           | enumerates all the members of a domain's groups and finds users that are outside of the queried domain |             |
| <pre><code>Get-DomainTrustMapping
</code></pre>           |                                                                                                        |             |
|                                                           | <pre><code>Invoke-MapDomainTrust
</code></pre>                                                         |             |
|                                                           | try to build a relational mapping of all domain trusts                                                 |             |

> The [global catalog is a partial copy of all objects](https://technet.microsoft.com/en-us/library/cc728188\(v=ws.10\).aspx) in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. Trusted domain objects are replicated in the global catalog, so we can enumerate every single internal and external trust that all domains in our current forest have extremely quickly, and only with traffic to our current PDC.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)_)_

```powershell
Get-DomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)"
```

The global catalog can be found in many ways, including a simple DNS query (see [DNS recon](../recon/dns.md#finding-domain-controllers)).

### BloodHound

[BloodHound](../recon/bloodhound.md) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.
{% endtab %}
{% endtabs %}

### Forging tickets

When forging a [referral ticket](trusts.md#referral-tickets), or a [golden ticket](kerberos/forged-tickets/golden.md), additional security identifiers (SIDs) can be added as "extra SID" and be considered as part of the user's [SID history](trusts.md#sid-history) when authenticating. Alternatively, the SID could be added beforehand, directly in the SID history attribute, with mimikatz [`sid:add`](https://tools.thehacker.recipes/mimikatz/modules/sid/add) command, but that's a topic for another day.

If an SID in the form of `S-1-5-21-<RootDomain>-519` ("Enterprise Admins" group of the forest root domain) was added as "extra SID" in a forged ticket, it would allow for a direct privilege escalation from any compromised domain to it's forest root, and by extension, all the forest, since Enterprise Admins can access all domains' domain controllers as admin.

This technique works for any trust relationship without SID filtering. This technique would also work with an RID > 1000 for External trusts (e.g. `extraSid = S-1-5-21-<RootDomain>-10420`). See SID filtering.

#### SID filtering disabled

If SID filtering is disabled in the targeted trust relationship (see [SID filtering](trusts.md#sid-filtering) and [Enumeration](trusts.md#enumeration)), a ticket (inter-realm/referral ticket, or golden ticket) can be forged with an extra SID that contains the root domain and the RID of the "Enterprise Admins" group. The ticket can then be used to access the forest root domain controller and conduct a [DCSync](credentials/dumping/dcsync.md) attack.

In the case of an inter-realm ticket forgery, a service ticket request must be conducted before trying to access the domain controller. In the case of a golden ticket, the target domain controller will do that hard work. Once the last ticket is obtained, it can be used with [pass-the-ticket](kerberos/ptt.md) for the [DCSync](credentials/dumping/dcsync.md) (or any other operation).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/fortra/impacket) scripts (Python) can be used for that purpose.

* ticketer.py to forge tickets
* getST.py to request service tickets
* lookupsid.py to retrieve the domains' SIDs

<pre class="language-bash" data-title="Referral ticket" data-overflow="wrap"><code class="lang-bash"><strong># 1. forge the ticket
</strong>ticketer.py -nthash "inter-realm key" -domain-sid "child_domain_SID" -domain "child_domain_FQDN" -extra-sid "&#x3C;root_domain_SID>-519" -spn "krbtgt/root_domain_fqdn" "someusername"
 
# 2. use it to request a service ticket
KRB5CCNAME="someusername.ccache" getST.py -k -no-pass -debug -spn "CIFS/domain_controller" "root_domain_fqdn/someusername@root_domain_fqdn"
</code></pre>

{% code title="Golden ticket" overflow="wrap" %}
```bash
ticketer.py -nthash "child_domain_krbtgt_NT_hash" -domain-sid "child_domain_SID" -domain "child_domain_FQDN" -extra-sid "<root_domain_SID>-519" "someusername"
```
{% endcode %}

Impacket's [raiseChild.py](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py) script can also be used to conduct the golden ticket technique automatically (retrieving the SIDs, dumping the child krbtgt, forging the ticket, dumping the forest root keys, etc.).

```bash
raiseChild.py "child_domain"/"child_domain_admin":"$PASSWORD" 
```
{% endtab %}

{% tab title="Windows" %}
```
```
{% endtab %}
{% endtabs %}

#### SID filtering partially enabled / SID history enabled

If SID filtering is partially enabled (a.k.a. [SID history enabled](trusts.md#sid-history)), effectively only filtering out RID <1000, a ticket can be forged with an extra SID that contains the target domain and the RID of any group, with RID >1000). The ticket can then be used to conduct more attacks depending on the group privileges. In that case, the commands are the same as for [SID filtering disabled](trusts.md#sid-filtering-disabled), but the RID `519` ("Entreprise Admins" group) must be replaced with another RID >1000 of a powerful group.

{% hint style="info" %}
> For example the Exchange security groups, which allow for a [privilege escalation to DA](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) in many setups all have RIDs larger than 1000. Also many organisations will have custom groups for workstation admins or helpdesks that are given local Administrator privileges on workstations or servers.
>
> _(by_ [_Dirk-jan Mollema_](https://twitter.com/\_dirkjan) _on_ [_dirkjanm.io_](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)_)_
{% endhint %}

#### SID filtering enabled

If SID filtering is fully enabled (trusts with the `QUARANTINED_DOMAIN` attribute), the techniques presented above will not work since all SID that differ from the trusted domain will be filtered out. This is usually the case with standard inter-forest trusts. Attackers must then fallback to other methods like abusing permissions and group memberships to move laterally from a forest to another.



### Explicit permissions

#### Unconstrained delegation abuse

// TODO

{% content-ref url="kerberos/delegations/unconstrained.md" %}
[unconstrained.md](kerberos/delegations/unconstrained.md)
{% endcontent-ref %}

#### ADCS abuse

When an ADCS is installed and configured in an Active Directory environment, a CA is available for the whole forest. Every usual ADCS attack can be executed through intra-forest trusts. [ESC8](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints) and [ESC11](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/) in particular can be used to pivot to any domain within the forest associated to the CA.

#### DACL abuse

TODO // How a domain admin of forest A could administrate a domain in forest B ? [https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS](https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS)

TODO // Regular permissions, ACE, and whatnot abuses, but now between foreign principals, BloodHound comes in handy.

#### Group memberships

// group scoping

## Resources

{% embed url="https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-1-the-mechanics/" %}

{% embed url="https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/" %}

{% embed url="https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/" %}

{% embed url="https://mayfly277.github.io/posts/GOADv2-pwning-part12" %}

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736874(v=ws.10)" %}

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://blogs.msmvps.com/acefekay/tag/active-directory-trusts/" %}

{% embed url="https://adsecurity.org/?p=282" %}

{% embed url="https://adsecurity.org/?p=1640" %}

{% embed url="https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/" %}

{% embed url="https://blog.harmj0y.net/redteaming/the-trustpocalypse/" %}

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent" %}

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}

{% embed url="https://nored0x.github.io/red-teaming/active-directory-Trust-enumeration/" %}

{% embed url="https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d" %}

{% embed url="https://adsecurity.org/?p=425" %}

{% embed url="https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1" %}

{% hint style="info" %}
Parts of this page were written with the help of the [ChatGPT](https://openai.com/blog/chatgpt/) AI model.
{% endhint %}
