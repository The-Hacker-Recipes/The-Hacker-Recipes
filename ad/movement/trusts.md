# Trusts

## Theory

### Forest, domains & trusts

An Active Directory **domain** is a collection of computers, users, and other resources that are all managed together. A domain has its own security database, which is used to authenticate users and computers when they log in or access resources within the domain.

A **forest** is a collection of one or more Active Directory domains that share a common schema, configuration, and global catalog. The schema defines the kinds of objects that can be created within the forest, and the global catalog is a centralized database that contains a searchable, partial replica of every domain in the forest.

**Trust relationships** between domains allow users in one domain to access resources in another domain. There are several types of trust relationships that can be established, including one-way trusts, two-way trusts, external trusts, etc.&#x20;

Once a trust relationship is established between a **trusting domain** (A) and **trusted domain** (B), users from the trusted domain can authenticate to the trusting domain's resources. In other -more technical- terms, trusts extend the security boundary of a domain or forest.

### Trust types

1. **Parent-Child**: this type of trust relationship exists between a parent domain and a child domain in the same forest. The parent domain trusts the child domain, and the child domain trusts the parent domain. This type of trust is automatically created when a new child domain is created in a forest.
2. **Tree-Root**: exists between the root domain of a tree and the root domain of another tree in the same forest. This type of trust is automatically created when a new tree is created in a forest.
3. **Cross-link**: exists between two child domains of different parent domains within the same forest. It allows users in one child domain to access resources in the other child domain.
4. **External**: exists between a domain in one forest and a domain in a different forest. It allows users in one domain to access resources in the other domain. It's usually set up when accessing resources in a forest without trust relationships established.
5. **Forest**: exists between two forests (i.e. between two root domains in their respective forest). It allows users in one forest to access resources in the other forest.
6. **Realm**: exists between a Windows domain and a non-Windows domain, such as a Kerberos realm. It allows users in the Windows domain to access resources in the non-Windows domain.
7. **Shortcut**: this type of trust relationship is used to reduce the number of authentication hops required when accessing resources in a remote domain. It is a one-way, transitive trust that can be created between two domains in the same forest or between a domain in one forest and a domain in another forest.

| Trust type   | Transitivity   | Direction | Auth. mechanisms |
| ------------ | -------------- | --------- | ---------------- |
| Parent-Child | Transitive     | Two-way   | Either           |
| Tree-Root    | Transitive     | Two-way   | Either           |
| Shortcut     | Transitive     | Either    | Either           |
| Forest       | Transitive     | Either    | Either           |
| External     | Non-transitive | One-way   | NTLM only        |
| Realm        | Either         | Either    | Kerberos V5 only |

### Transitivity

In Active Directory, a transitive trust is a type of trust relationship that allows access to resources to be passed from one domain to another. When a transitive trust is established between two domains, any trusts that have been established with the first domain are automatically extended to the second domain. This means that if Domain A trusts Domain B and Domain B trusts Domain C, then Domain A automatically trusts Domain C, even if there is no direct trust relationship between Domain A and Domain C. Transitive trusts are useful in large, complex networks where multiple trust relationships have been established between many different domains. They help to simplify the process of accessing resources and reduce the number of authentication hops that may be required.

### Security boundary

According to Microsoft, the security boundary in Active Directory is the forest, not the domain. The forest defines the boundaries of trust and controls access to resources within the forest.

The domain is a unit within a forest and represents a logical grouping of users, computers, and other resources. Users within a domain can access resources within their own domain and can also access resources in other domains within the same forest, as long as they have the appropriate permissions. Users cannot access resources in other forests unless a trust relationship has been established between the forests.

### Authentication vs. access

Simply establishing a trust relationship does not automatically grant access to resources. In order to access a "trusting" resource, a "trusted" user must have the appropriate permissions to that resource. These permissions can be granted by adding the user to a group that has access to the resource, or by giving the user explicit permissions to the resource.

A trust relationship allows users in one domain to **authenticate** to the other domain's resources, but it does not automatically grant access to them. Access to resources is controlled by permissions, which must be granted explicitly to the user in order for them to access the resources.

## Practice

### Enumerating

Several tools can be used to enumerate trust relationships. Depending on the output, trust types and flags can be shown (see Microsoft's documentation on [trustType](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e?redirectedfrom=MSDN) or [trustAttributes](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN) to understand what each value implies). Among those types and flags, the following major ones must be looked for:

*   `TREAT_AS_EXTERNAL (0x00000040)`: "the trust is to be treated as external \[...]. If this bit is set, then a cross-forest trust to a domain is to be treated as an external trust for the purposes of SID Filtering. Cross-forest trusts are more stringently filtered than external trusts. This attribute relaxes those cross-forest trusts to be equivalent to external trusts." ([Microsoft](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN))

    If this flag is set, it means **SID history is enabled in that trust**, and a cross-forest ticket spoofing an RID >1000 can be forged. This can usually lead to the trusting domain compromise.
* `QUARANTINED_DOMAIN (0x00000004)`: SID filtering is enabled in that trust

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
{% endtab %}

{% tab title="Windows" %}
From UNIX-like systems, many tools like can be used to enumerate trusts.

From domain-joined hosts, the `netdom` cmdlet can be used.

```batch
netdom trust /domain:DOMAIN.LOCAL
```

Alternatively, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) supports multiple commands for various purposes.

| Command                                                   | Alias                                                        | Description                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| <pre><code><strong>Get-DomainTrust
</strong></code></pre> | <pre><code><strong>Get-NetDomainTrust
</strong></code></pre> | gets all trusts for the current user's domain                                                          |
| <pre><code>Get-ForestTrust
</code></pre>                  | <pre><code>Get-NetForestTrust
</code></pre>                  | gets all trusts for the forest associated with the current user's domain                               |
| <pre><code>Get-DomainForeignUser
</code></pre>            | <pre><code>Find-ForeignUser
</code></pre>                    | enumerates users who are in groups outside of their principal domain                                   |
| <pre><code>Get-DomainForeignGroupMember
</code></pre>     | <pre><code>Find-ForeignGroup
</code></pre>                   | enumerates all the members of a domain's groups and finds users that are outside of the queried domain |
| <pre><code>Get-DomainTrustMapping
</code></pre>           | <pre><code>Invoke-MapDomainTrust
</code></pre>               | try to build a relational mapping of all domain trusts                                                 |
{% endtab %}
{% endtabs %}

### Ticket forging

TODO // Trust ticket forging [https://adsecurity.org/?p=1588](https://adsecurity.org/?p=1588), especially useful for moving through domain trusts

TODO // Golden ticket with extra SID [https://adsecurity.org/?p=1640](https://adsecurity.org/?p=1640), same, but can also be useful for forest trusts that have sid history enabled. "you can **spoof any RID >1000** group if SID history is enabled across a Forest trust! In most environments, this will allow an attacker to compromise the forest. For example the Exchange security groups, which allow for a [privilege escalation to DA](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) in many setups all have RIDs larger than 1000. Also many organisations will have custom groups for workstation admins or helpdesks that are given local Administrator privileges on workstations or servers." ([https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/))

### Permissions abuse

TODO // How a domain admin of forest A could administrate a domain in forest B ? [https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS](https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS)

TODO // Regular permissions, ACE, and whatnot abuses, but now between foreign principals, BloodHound comes in handy.

## Resources

### Understand

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736874(v=ws.10)" %}

{% embed url="https://blogs.msmvps.com/acefekay/tag/active-directory-trusts/" %}

### Attack

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent" %}

{% embed url="https://adsecurity.org/?p=282" %}

{% embed url="https://adsecurity.org/?p=1640" %}

{% embed url="https://blog.harmj0y.net/redteaming/the-trustpocalypse/" %}

{% embed url="https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/" %}

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}

{% embed url="https://nored0x.github.io/red-teaming/active-directory-Trust-enumeration/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/" %}

{% embed url="https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/" %}

{% embed url="https://mayfly277.github.io/posts/GOADv2-pwning-part12" %}

{% hint style="info" %}
Parts of this page were written with the help of the [ChatGPT](https://openai.com/blog/chatgpt/) AI model.
{% endhint %}
