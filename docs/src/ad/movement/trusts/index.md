---
authors: ShutdownRepo, WodenSec
---

# Trusts

## Theory

> [!WARNING]
> Attacking Active Directory trust relationships requires a good understanding of a lot of concepts (what forests and domains are, how trusts work, what security mechanisms are involved and how they work, ...). Consequently, this page is lengthy, especially in the [theory](index#theory) and [resources](index#resources) parts, but I did my best to include all the necessary info here.
>
> **Pro tip**: use the page outline on the right panel, to browse it more easily.


### Forest, domains & trusts

An Active Directory domain is a collection of computers, users, and other resources that are all managed together. A domain has its own security database, which is used to authenticate users and computers when they log in or access resources within the domain.

A forest is a collection of one or more Active Directory domains that share a common schema, configuration, and global catalog. The schema defines the kinds of objects that can be created within the forest, and the global catalog is a centralized database that contains a searchable, partial replica of every domain in the forest.

Trust relationships between domains allow users in one domain to access resources in another domain. There are several types of trust relationships that can be established, including one-way trusts, two-way trusts, external trusts, etc.

Once a trust relationship is established between a trusting domain (A) and trusted domain (B), users from the trusted domain can authenticate to the trusting domain's resources. In other -more technical- terms, trusts extend the security boundary of a domain or forest.

> [!TIP]
>Simply establishing a trust relationship does not automatically grant access to resources. In order to access a "trusting" resource, a "trusted" user must have the appropriate permissions to that resource. These permissions can be granted by adding the user to a group that has access to the resource, or by giving the user explicit permissions to the resource.
>
>A trust relationship allows users in one domain to authenticate to the other domain's resources, but it does not automatically grant access to them. Access to resources is controlled by permissions, which must be granted explicitly to the user in order for them to access the resources.


### Global Catalog

The global catalog is a partial copy of all objects in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. One of the Global Catalog's purposes is to facilitate quick object searching and conflict resolution without the necessity of referring to other domains [(more information here)](https://technet.microsoft.com/en-us/library/cc978012.aspx).

The initial global catalog is generated on the first domain controller created in the first domain in the forest. The first domain controller for each new child domain is also set as a global catalog by default, but others can be added.

The GC allows both users and applications to find information about any objects in ANY domain in the forest. The Global Catalog performs the following functions:

* Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
* Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)

### Trust types

The `trustType` attribute of a TDO specifies the type of trust that is established. Here are the different trust types (section [6.1.6.7.15 "trustType"](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e) of \[MS-ADTS]):

1. Downlevel: a trust with a domain that is running a version of Windows NT 4.0 or earlier.
2. Uplevel: a trust with a domain that is running Windows 2000 or later.
3. MIT: a trust with a non-Windows Kerberos realm, typically used for interoperability with UNIX-based systems running MIT Kerberos.
4. DCE: not used in Windows. Would refer to trusts with a domain running [DCE](http://www.opengroup.org/dce/info/).
5. AAD: the trusted domain is in Azure Active Directory.

### Trust flavor

The trust "flavor", on the other hand, represents the nature of the trust relationship between domains or forests. It is not a direct attribute but is identified based on other TDO attributes (see ["How Domain and Forest Trusts Work > Trust Types"](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)#trust-types)).

1. Parent-Child: this type of trust relationship exists between a parent domain and a child domain in the same forest. The parent domain trusts the child domain, and the child domain trusts the parent domain. This type of trust is automatically created when a new child domain is created in a forest.
2. Tree-Root: exists between the root domain of a tree and the root domain of another tree in the same forest. This type of trust is automatically created when a new tree is created in a forest.
3. Shortcut (a.k.a. cross-link): exists between two child domains of different tree (i.e. different parent domains) within the same forest. This type of trust relationship is used to reduce the number of authentication hops between distant domains. It is a one-way or two-way transitive trust.
4. External: exists between a domain in one forest and a domain in a different forest. It allows users in one domain to access resources in the other domain. It's usually set up when accessing resources in a forest without trust relationships established.
5. Forest: exists between two forests (i.e. between two root domains in their respective forest). It allows users in one forest to access resources in the other forest.
6. Realm: exists between a Windows domain and a non-Windows domain, such as a Kerberos realm. It allows users in the Windows domain to access resources in the non-Windows domain.



| Trust type | Transitivity | Direction | Auth. mechanisms | Creation mode |
| --- | --- | --- | --- | --- |
| Parent-Child | Transitive | Two-way | Either | Automatic |
| Tree-Root | Transitive | Two-way | Either | Automatic |
| Shortcut (a.k.a. cross-link) | Transitive | Either | Either | Manual |
| Realm | Either | Either | Kerberos V5 only | Manual |
| Forest | Transitive | Either | Either | Manual |
| External | Non-transitive | One-way | NTLM only | Manual |



### Transitivity

In Active Directory, a transitive trust is a type of trust relationship that allows access to resources to be passed from one domain to another. When a transitive trust is established between two domains, any trusts that have been established with the first domain are automatically extended to the second domain. This means that if Domain A trusts Domain B and Domain B trusts Domain C, then Domain A automatically trusts Domain C, even if there is no direct trust relationship between Domain A and Domain C. Transitive trusts are useful in large, complex networks where multiple trust relationships have been established between many different domains. They help to simplify the process of accessing resources and reduce the number of authentication hops that may be required.

> [!TIP]
> The transitivity status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).
>
> > * If the `TRUST_ATTRIBUTE_NON_TRANSITIVE (0x00000001)` flag is set then the transitivity is disabled.
> > * If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set then the transitivity is enabled.
> > * If the `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008)` flag is set then the transitivity is enabled.
> >
> > In any other case the transitivity is disabled.
> >
> > _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_


### SID filtering

According to Microsoft, the security boundary in Active Directory is the forest, not the domain. The forest defines the boundaries of trust and controls access to resources within the forest.

The domain is a unit within a forest and represents a logical grouping of users, computers, and other resources. Users within a domain can access resources within their own domain and can also access resources in other domains within the same forest, as long as they have the appropriate permissions. Users cannot access resources in other forests unless a trust relationship has been established between the forests.

SID filtering plays an important role in the security boundary by making sure "only SIDs from the trusted domain will be accepted for authorization data returned during authentication. SIDs from other domains will be removed" (`netdom` cmdlet output). By default, SID filtering is disabled for intra-forest trusts, and enabled for inter-forest trusts.

![](<./assets/SID filtering default configs.png>)

Default configurations (source: [securesystems.de](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)){.caption}


![](<./assets/SID filtering custom configs.png>)

Custom configurations (source: [securesystems.de](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)){.caption}


Section [4.1.2.2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) of \[MS-PAC] specifies what is filtered and when. There are three important things to remember from this documentation:

* if SID filtering is fully enabled, all SIDs that differ from the trusted domain will be filtered out
* even if it's enabled, a few SIDs will (almost) never be filtered: "Enterprise Domain Controllers" (S-1-5-9) SID and those described by the [trusted domain object (TDO)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4), as well as seven well-known SIDs (see [MS-PAC doc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280), and [improsec's blogpost](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained#yui_3_17_2_1_1673614140169_543)).
* there are two kinds of inter-forest trusts: "Forest", and "External" (see [trust types](index#trust-types)). Microsoft says "[cross-forest trusts are more stringently filtered than external trusts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab?redirectedfrom=MSDN)", meaning that in External trusts, SID filtering only filters out RID < 1000.

![](<./assets/MS PAC section 4.1.2.2.png>)

[MS-PAC] section 4.1.2.2{.caption}


> [!TIP]
> The SID filtering status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4) as well as the type of trust.
> 
> > * If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then only SIDs from the trusted domain are allowed (all others are filtered
> >
> > _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_
> >
> > * If the `TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x00000040)` flag is set, then inter-forest ticket can be forged, spoofing an RID >= 1000. Of course, this doesn't apply if TAQD (`TRUST_ATTRIBUTE_QUARANTINED_DOMAIN`) is set.
> >
> > _(sources: section_ [_6.1.6.7.9_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN) _of \[MS-ADTS], and section_ [_4.1.2.2_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) _of \[MS-PAC])._
>
> Above are some key, usually valid, elements. But as [Carsten Sandker](https://twitter.com/0xcsandker) puts it: "the logic that sits behind this might be too complex to put it in text". To really know the behavior of SID filtering for a trust, refer to the lookup tables [here](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/OC-b4We5WFiXhTirzI_Dyw.png) (for default trusts setups) and [there](https://www.securesystems.de/images/blog/active-directory-spotlight-trusts-part-2-operational-guidance/99icUS7SKCscWq6VzW0o5g.png) (for custom configs).


> [!TIP]
> SID filtering is not unique to trusts. It occurs "[whenever a service ticket is accepted](https://twitter.com/SteveSyfuhs/status/1329148611305693185)" either by the KDC or by a local service and behaves differently depending on the contect in which the ticket was produced.
>
> Also, SID filtering works the same way for NTLM and Kerberos. It's a separate mechanism invoked after user logon info are unpacked (more details in [NTLM](index#ntlm-authentication) and [Kerberos](index#kerberos-authentication) chapters).


### SID history

The SID (Security Identifier) is a unique identifier that is assigned to each security principal (e.g. user, group, computer). It is used to identify the principal within the domain and is used to control access to resources.

The SID history is a property of a user or group object that allows the object to retain its SID when it is migrated from one domain to another as part of a domain consolidation or restructuring. When an object is migrated to a new domain, it is assigned a new SID in the target domain. The SID history allows the object to retain its original SID, so that access to resources in the source domain is not lost.

Many resources across the Internet, including Microsoft's docs and tools, state that SID history can be enabled across a trust. This is not 100% true. SID history is not a feature that can be toggled on or off per say.

When authenticating across trusts [using Kerberos](index#kerberos-authentication), it is assumed that the extra SID field of the ticket's PAC (Privileged Attribute Certificate) reflects the SID history attribute of the authenticating user. With [SID filtering](index#sid-filtering) enabled in a trust, the SIDs contained in that field are filtered, effectively preventing SID history from doing its job. There are certain scenarios where some SIDs are not filtered, allowing for example SIDs with a RID >= 1000. Some, including Microsoft, call it "enabling SID history", but in fact, SID history is not toggled on or off here, it's the behavior of SID filtering that is adjusted. I'd call that "partial SID filtering", or "unencumbered SID history". [Dirk-jan Mollema](https://twitter.com/_dirkjan) calls that "[SID filtering relaxation](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/#sid-filtering-relaxation)".

When authenticating with NTLM, the process is highly similar, see the [NTLM authentication](index#ntlm-authentication) theory chapter for more information.

### Authentication level

Inter-forest trusts ("External" and "Forest" trusts) can be configured with different levels of authentication:

* Forest-wide authentication: allows unrestricted authentication from the trusted forest's principals to the trusting forest's resources. This is the least secure level, it completely opens one forest to another (authentication-wise though, not access-wise). This level is specific to intra-forest trusts.
* Domain-wide authentication: allows unrestricted authentication from the trusted domain's principals to the trusting domain's resources. This is more secure than forest-wide authentication because it only allows users in a specific (trusted) domain to access resources in another (trusting).
* Selective authentication: allows only specific users in the trusted domain to access resources in the trusting domain. This is the most secure type of trust because it allows administrators to tightly control access to resources in the trusted domain. In order to allow a "trusted user" to access a "trusting resource", the resource's DACL must include an ACE in which the trusted user has the "`Allowed-To-Authenticate`" extended right (GUID: `68b1d179-0d15-4d4f-ab71-46152e79a7bc`).

It's worth noting that selective authentication is less used by the general public due to its complexity, but it's definitely the most restrictive, hence secure, choice.

> [!TIP]
> The authentication level of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).
> 
> > * If the trust relationship is made within a forest boundary (aka if the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set), then Forest-Wide Authentication will always be used.
> >* f the trust relationship crosses a forest boundary and the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION (0x00000010)` flag is set then Selective Authentication is used.
> >* If the trust relationship crosses a forest boundary, but the trust is marked as transitive (aka if the `TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008)` flag is set), then Forest-Wide Authentication will be used.
> >
> >In any other case Domain-Wide Authentication is used.
> >
> >_Interesting to note: Trusts within a Forest always use Forest-Wide Authentication (and this can not be disabled)._
> >
> > _(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_


### TGT delegation

Kerberos unconstrained delegation (KUD) allows a service configured for it to impersonate (almost) any user on any other service. This is a dangerous feature to configure, that won't be explained into many details here as the [Kerberos](../kerberos/index#delegations), [Kerberos delegations](../kerberos/delegations/index) and [Kerberos unconstrained delegations](../kerberos/delegations/unconstrained) pages already cover it.

Kerberos unconstrained delegations could be abused across trusts to take control over any resource of the trusting domain, including the domain controller, as long as the trusted domain is compromised. This relies on the delegation of TGT across trusts, which can be disabled.

If TGT delegation is disabled in a trust, attackers won't be able to [escalate from one domain to another by abusing unconstrained delegation](index#unconstrained-delegation-abuse). On a side note, the other types of delegations are not affected by this as they don't rely on the delegation of tickets, but on S4U extensions instead.

> [!TIP]
> The TGT delegation status of a trust depends on the [trustAttributes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c) flags of a [TDO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4).
>
> >* If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x00000200)` flag is set, then TGT Delegation is disabled.
> >* If the `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x00000004)` flag is set, then TGT Delegation is disabled.
> >* If the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x00000800)`flag is set, then TGT Delegation is enabled.
> >* If the `TRUST_ATTRIBUTE_WITHIN_FOREST (0x00000020)` flag is set, then TGT Delegation is enabled.
> >
> >_(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_


### Kerberos authentication

Understanding how Kerberos works is required here: [the Kerberos protocol](../kerberos/index).

> For a Kerberos authentication to occur across a domain trust, the Kerberos key distribution centers (KDCs) in two domains must have a shared secret, called an inter-realm key. This key is [derived from a shared password](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378170(v=vs.85).aspx), and rotates approximately every 30 days. Parent-child domains share an inter-realm key implicitly.
>
> When a user in domain A tries to authenticate or access a resource in domain B that he has established access to, he presents his ticket-granting-ticket (TGT) and request for a service ticket to the KDC for domain A. The KDC for A determines that the resource is not in its realm, and issues the user a referral ticket.
>
> This referral ticket is a ticket-granting-ticket (TGT) encrypted with the inter-realm key shared by domain A and B. The user presents this referral ticket to the KDC for domain B, which decrypts it with the inter-realm key, checks if the user in the ticket has access to the requested resource, and issues a service ticket. This process is described in detail in [Microsoft’s documentation](https://technet.microsoft.com/en-us/library/cc772815(v=ws.10).aspx#w2k3tr_kerb_how_pzvx) in the Simple Cross-Realm Authentication and Examples section.
>
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/)_)_

From an offensive point of view, just like a [golden ticket](../kerberos/forged-tickets/golden), a referral ticket could be forged. Forging a referral ticket using the inter-realm key, instead of relying on the krbtgt keys for a golden ticket, is a nice alternative for organizations that choose to roll their krbtgt keys, as they should. This technique is [a little bit trickier](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#do-you-need-to-use-inter-realm-tickets) though, as it requires to [use the correct key](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/#which-keys-do-i-need-for-inter-realm-tickets).

Depending on the trust characteristics, ticket forgery can also be combined with [SID history](index#sid-history) spoofing for a direct privilege escalation from a child to a parent domain.

When doing Kerberos authentications across trusts, the trusting domain's domain controller [checks a few things](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3) before handing out service tickets to trusted users: [SID filtering](index#sid-filtering) during [PAC validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) (looking in the `ExtraSids` attribute from the [`KERB_VALIDATION_INFO`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73) structure in the PAC), [TGT delegation](index#tgt-delegation) verification (when asked for a Service Ticket for a service configured for unconstrained delegation), and [Selective Authentication](index#authentication-level) limitation.

### NTLM authentication

In an NTLM authentication sequence, a user authenticates to a resource by sending an NTLM Negotiate message, receiving an NTLM Challenge, and then sending back an NTLM Authenticate. The server then passes the logon request through to the Domain Controller, using the Netlogon Remote Protocol.

> This mechanism of delegating the authentication request to a DC is called pass-through authentication.
>
> Upon successful validation of the user credentials on the DC, the Netlogon Remote Protocol delivers the user authorization attributes (referred to as user validation information) back to the server over the secure channel.
>
> _(_[_Microsoft.com_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/70697480-f285-4836-9ca7-7bb52f18c6af)_)_

When using NTLM across trust relationships, the process is very similar.

When a trusted domain's user wants to access a resource from a trusting domain, the user and the resource engage in the standard 3-way NTLM handshake. Upon receiving the NTLM Authenticate message, the resource forwards it to its own domain controller through a Netlogon "[workstation secure channel](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/08b36439-331a-4e20-89a5-12f3fab33dfc)". The trusting DC forwards it as well to the trusted domain's DC through a Netlogon "[trusted domain secure channel](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/08b36439-331a-4e20-89a5-12f3fab33dfc)".

The trusted domain's DC does the usual checks and passes the result to the trusting DC, which in turn passes it to the resource. The resource then accepts or rejects the authentication based on the decision passed through the DCs.

When doing NTLM authentications across trusts, the trusting domain's domain controller checks a few things from the user info structure supplied by the trusted domain controller: [SID filtering](index#sid-filtering) (looking in the `ExtraSids` attribute from the [`NETLOGON_VALIDATION_SAM_INFO2`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/2a12e289-7904-4ecb-9d83-6732200230c0) structure), and [Selective Authentication](index#authentication-level) limitation during the [DC's validation of the user credentials](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72). [TGT delegation](index#tgt-delegation) verification doesn't occur here, since it's a Kerberos mechanism.

_Nota bene, wether it's Kerberos or NTLM, the ExtraSids are in the same data structure, it's just named differently for each protocol. And, the SID filtering function called by the trusting DC is the same, for both authentication protocols._

### MIM PAM & Bastion (Red Forests)

> [!TIP]
> The following section is a light adaptation of [Nikhil Mittal's](https://www.labofapenetrationtester.com/2019/04/abusing-PAM.html) and [Daniel Ulrichs's](https://secureidentity.se/msds-shadowprincipal/) work.


Microsoft introduced MIM (Microsoft Identity Manager) Privileged Access Management (PAM) with Server 2016, including the following features. (Sometimes PAM is also referred to as PIM in some docs/links).

* A Bastion forest (i.e. forest in ESAE (Enhanced Security Admin Environment), a.k.a. Red Forest)
* Shadow Security Principals (i.e. admins in Bastion Forest can be mapped as Domain Admins or a "User Forest")
* Temporary group membership (i.e. add a user to a group with a time-to-live (TTL))

PAM enables the management of an existing "Production Forest" (one can think of that as a User Forest as well) using a "Bastion Forest" which has a one-way PAM trust with the existing forest. The users in the Bastion Forest can be 'mapped' to privileged groups like "Domain Admins" and "Enterprise Admins" in the Production Forest without modifying any group memberships or ACLs. This takes away the administrative overhead and reduces the chances of lateral movement techniques.

This is done by creating "Shadow Security Principals" in the Bastion Forest, which are mapped to SIDs for high-privileged groups in the User Forest, and then adding users from the Bastion Forest as members of the Shadow Security Principals.


::: details More technical notes

The main Active Directory Objects and Attributes related to the Bastion Forest are the following:

1. `msDS-ShadowPrincipalContainer`: dedicated container class for `msDS-ShadowPrincipal` objects. One default container (`CN=Shadow Principal Configuration`) is created in the Services container in the Configuration NC on the Bastion Forest). NB: Privileged Containers can be created in other locations as well, however, Kerberos will NOT work there.
2. `msDS-ShadowPrincipal`: principal from an external forest (Bastion Forest). Has the `msDS-ShadowPrincipalSid` attribute and can only be in a Shadow Principal container. Any principal may be represented by a Shadow Principal. If the Shadow Principal is in the default container (mentioned above), Kerberos tickets will embed the group membership (in the same forest) of the principal referenced by the Shadow Principal. If a TTL value of the membership is set it will integrate with Kerberos and the lifetime of the tickets will be set to the shortest expiring TTL value.
3. `msDS-ShadowPrincipalSid`: This attribute contains the SID of a principal from an external forest. SIDs from a domain of the same forest cannot be added. To be able to add SIDs from another Domain, a Forest Trust must be configured between them. This means that at least a one-way incoming Forest Trust from the Domain that holds the Shadow Principals must be configured. This attribute is also indexed.

```
Bastion ROOT (DC=BASTION,DC=LOCAL)
├── Configuration Naming Context (CN=Configuration)
│ ├── Services (CN=Services)
│ │ ├── Default Shadow Principal Container (CN=Shadow Principal Configuration)
│ │ │ ├── Shadow Principal object
│ │ │ │ ├── name: prodForest-ShadowEntrepriseAdmin
│ │ │ │ ├── member: { BASTION/bobby, BASTION/jason } (Users in Bastion Forest)
│ │ │ │ ├── msDS-ShadowPrincipalSid: S-1-5-21-[...]-519 (Entreprise Admins @ PRODUCTION.LOCAL)
│ │ │ │ ├── ...
│ │ │ ├── Shadow Principal object
│ │ │ │ ├── name: prodForest-ShadowDomainAdmin
│ │ │ │ ├── member: { BASTION/max, BASTION/jason } (Users in Bastion Forest)
│ │ │ │ ├── msDS-ShadowPrincipalSid: S-1-5-21-[...]-512 (Domain Admins @ PRODUCTION.LOCAL)
│ │ │ │ ├── ...
│ │ ├── [...] 
```
:::



## Practice

While domain trusts don't necessarily give access to resources, they allow the trusted domain's principal to query another -trusting- domain's AD info.

> And remember that all parent->child (intra-forest domain trusts) retain an implicit two way transitive trust with each other. Also, due to how child domains are added, the “Enterprise Admins” group is automatically added to Administrators domain local group in each domain in the forest. This means that trust “flows down” from the forest root, making it our objective to move from child to forest root at any appropriate step in the attack chain. (from [Will Schroeder's " A Guide to Attacking Domain Trusts"](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d)).

Attacking AD trusts comes down to the following process.

1. Map all direct and indirect trusts involved with an already compromised domain.
2. All domains from the same forest are to be considered as first-choice targets ([SID filtering](index#sid-filtering) would be disabled, allowing for [Forging a ticket](index#forging-tickets) with an [SID history](index#sid-history)).
3. For the others, permissions must be audited to finds ways in trusting domains. This is done by finding out what trusted principals can do on trusting resources (Kerberos delegations, groups membership, DACLs, etc.), and then [abuse those permissions](index#abusing-permissions). All regular AD movement techniques apply, except the target resources and the account used to authenticate are not on the same domain, that's basically it.

### Enumeration

Several tools can be used to enumerate trust relationships. The following major characteristic must be looked for, some of which are directly readable from the [TDO (Trusted Domain Object)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4) attributes and others need a little bit of logic.

* Trust partner: trusting domain for outbound trusts, trusted domain for inbound trusts. Bidirectional trusts are two one-way trusts. Retrieved from the TDO attribute `trustPartner` value.
* Trust direction: inbound, outbound, or bidirectional. Retrieved from the TDO attribute `trustDirection` integer value.
* Trust type: Parent-Child, Tree-Root, Shortcut (a.k.a. "Cross-Link"), Forest, External, or Realm (a.k.a. "Kerberos").
* Trust authentication level, transitivity, TGT delegation and SID filtering: Retrieved from a set of flags in the TDO's `trustAttributes` attribute, combined with the type of trust (see [authentication level](index#authentication-level), [transitivity](index#transitivity), [TGT delegation](index#tgt-delegation) and [SID filtering](index#sid-filtering)).

> [!TIP]
> >Keep in mind that there is a TDO \[([Trusted Domain Object](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4))] for each side of the Trust relationship so always analyze both TDOs for each trust. \[...]
> >
> >It's important to check both ends of the trust (because the characteristics could differ). \[...]
> >
> >All the trust relationship information is fetched via LDAP and preferably (if that server is operational) from the Global Catalog server. As the Global catalog contains information about every object in the forest it might also contain information about trust entities that you can't reach (e.g. due to network segmentation or because they are offline).
> >
> >_(by_ [_Carsten Sandker_](https://twitter.com/0xcsandker) _on_ [_www.securesystems.de_](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)_)_


::: tabs

=== UNIX-like

From UNIX-like systems, tools like [ldeep](https://github.com/franc-pentest/ldeep) (Python), [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) (Python), [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) (Python) and [ldapsearch](https://git.openldap.org/openldap/openldap) (C) can be used to enumerate trusts.


```bash
# ldeep supports cleartext, pass-the-hash, pass-the-ticket, etc.
ldeep ldap -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -s ldap://"$DC_IP" trusts

# ldapdomaindump will store HTML, JSON and Greppable output
ldapdomaindump --user 'DOMAIN\USER' --password "$PASSWORD" --outdir "ldapdomaindump" "$DC_HOST"

# ldapsearch-ad
ldapsearch-ad --server "$DC_HOST" --domain "$DOMAIN" --username "$USER" --password "$PASSWORD" --type trusts

# ldapsearch
ldapsearch -h ldap://"$DC_IP" -b "CN=SYSTEM,DC=$DOMAIN" "(objectclass=trustedDomain)"

```


[BloodHound](../../recon/bloodhound/index) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.


=== Windows

From Windows systems, many tools like can be used to enumerate trusts. "[A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts)" by [Will Schroeder](https://twitter.com/harmj0y) provides more in-depth guidance on how to enumerate and visually map domain trusts (in the "Visualizing Domain Trusts" section), as well as identify potential attack paths ("Foreign Relationship Enumeration" section).

#### netdom

From domain-joined hosts, the `netdom` cmdlet can be used.

```powershell
netdom trust /domain:DOMAIN.LOCAL
```

#### PowerView
Alternatively, [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) (PowerShell) supports multiple commands for various purposes.


| Command                                                   | Alias                                                        | Description                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `Get-DomainTrust`                                         | `Get-NetDomainTrust`                                         | gets all trusts for the current user's domain                                                          |
| `Get-ForestTrust`                                         | `Get-NetForestTrust`                                         | gets all trusts for the forest associated with the current user's domain                               |
| `Get-DomainForeignUser`                                   | `Find-ForeignUser`                                           | enumerates users who are in groups outside of their principal domain                                   |
| `Get-DomainForeignGroupMember`                            | `Find-ForeignGroup`                                          | enumerates all the members of a domain's groups and finds users that are outside of the queried domain |
| `Get-DomainTrustMapping`                                  | `Invoke-MapDomainTrust`                                      | try to build a relational mapping of all domain trusts                                                 |
> The [global catalog is a partial copy of all objects](https://technet.microsoft.com/en-us/library/cc728188(v=ws.10).aspx) in an Active Directory forest, meaning that some object properties (but not all) are contained within it. This data is replicated among all domain controllers marked as global catalogs for the forest. Trusted domain objects are replicated in the global catalog, so we can enumerate every single internal and external trust that all domains in our current forest have extremely quickly, and only with traffic to our current PDC.
> 
> _(by_ [_Will Schroeder_](https://twitter.com/harmj0y) _on_ [_blog.harmj0y.net_](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)_)_

```powershell
Get-DomainTrust -SearchBase "GC://$($ENV:USERDNSDOMAIN)"
```

The global catalog can be found in many ways, including a simple DNS query (see [DNS recon](../../recon/dns.md#finding-domain-controllers)).

#### BloodHound

[BloodHound](../../recon/bloodhound/index) can also be used to map the trusts. While it doesn't provide much details, it shows a visual representation.

:::


In addition to enumerating trusts, retrieving information about the permissions of trusted principals against trusting resources could also allow for lateral movement and privilege escalation. The recon techniques will depend on the permissions to abuse ([DACL](index#dacl-abuse), [Kerberos delegations](../kerberos/delegations/index), etc.).


:::details Notes on Bastion Forests

A forest is probably managed by a Bastion Forest when the `TRUST_ATTRIBUTE_PIM_TRUST (0x400)` flag is set in the trust attributes.

To enumerate the Shadow Security Principals, and LDAP query can be made to list the `Name`, `member`, and `msDS-ShadowPrincipalSid` attributes of Shadow Principals in the `CN=Shadow Principal Configuration,CN=Services,{CONFIGURATION_NAMING_CONTEXT}` container.

* `name`: name of the shadow principal
* `member`: principals (from the Bastion Forest) mapped to it
* `msDS-ShadowPrincipalSid`: the SID of the principal (from the Production Forest) whose privileges are assigned to the shadow security principal.
:::


### Forging tickets

When forging a [referral ticket](index#kerberos-authentication), or a [golden ticket](../kerberos/forged-tickets/golden), additional security identifiers (SIDs) can be added as "extra SID" and be considered as part of the user's [SID history](index#sid-history) when authenticating. Alternatively, the SID could be added beforehand, directly in the SID history attribute, with mimikatz [`sid:add`](https://tools.thehacker.recipes/mimikatz/modules/sid/add) command, but that's a topic for another day.

Then, when using the ticket, the SID history would be taken into account and could grant elevated privileges (depending on how [SID filtering](index#sid-filtering) is configured in the trust)

* If the attacker is moving across an intra-forest trust, it would allow to compromise the forest root, and by extension, all the forest, since Enterprise Admins can access all domains' domain controllers as admin (because the security boundary is the forest, not the domain).
* If the attacker is moving across an inter-forest trust, it could allow to compromise the trusting domain, depending on how [SID filtering](index#sid-filtering) is configured, and if there are some groups that have sufficient permissions.

In conclusion, before attacking trusts, it's required to enumerate them, as well as enumerate the target (trusting) domain's resources. See [enumeration](index#enumeration).

* If SID filtering is disabled in the targeted trust relationship (see [SID filtering](index#sid-filtering) and [Enumeration](index#enumeration)), a ticket (inter-realm/referral ticket, or golden ticket) can be forged with an extra SID that contains the root domain and the RID of the "Enterprise Admins" group (i.e. `S-1-5-21--519`). The ticket can then be used to access the trusting domain controller as admin and conduct a [DCSync](../credentials/dumping/dcsync) attack.
* If SID filtering is partially enabled (sometimes referred to as [SID history enabled](index#sid-history)), effectively only filtering out RID <1000, a ticket can be forged with an extra SID that contains the target domain and the RID of any group, with RID >= 1000). The ticket can then be used to conduct more attacks depending on the group's privileges.

 > For example the Exchange security groups, which allow for a [privilege escalation to DA](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) in many setups all have RIDs larger than 1000. Also many organisations will have custom groups for workstation admins or helpdesks that are given local Administrator privileges on workstations or servers.
 >
 > _(by_ [_Dirk-jan Mollema_](https://twitter.com/_dirkjan) _on_ [_dirkjanm.io_](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)_)_
* If SID filtering is fully enabled, the techniques presented above will not work since all SIDs that differ from the trusted domain will be filtered out. This is usually the case with standard inter-forest trusts. Attackers must then fall back to other methods of [permissions abuse](index#abusing-permissions). Alternatively, there are a few SIDs that won't be filtered out (see [SID filtering](index#sid-filtering) theory and [SID filtering bypass](index#sid-filtering-bypass) practice).

> [!TIP]
> If the attacker chooses to forge an inter-realm ticket forgery (i.e. referral ticket), a service ticket request must be conducted before trying to access the domain controller. In the case of a golden ticket, the target domain controller will do the hard work itself. Once the last ticket is obtained, it can be used with [pass-the-ticket](../kerberos/ptt) for the [DCSync](../credentials/dumping/dcsync) (if enough privileges, or any other operation if not).


::: tabs

=== UNIX-like

From UNIX-like systems, [Impacket](https://github.com/fortra/impacket) scripts (Python) can be used for that purpose.

* ticketer.py to forge tickets
* getST.py to request service tickets
* lookupsid.py to retrieve the domains' SIDs

If SID filtering is disabled, set the RID to 519 to act as Enterprise Admin.

If SID filtering is partially enabled, set the RID >=1000.

##### Referral ticket
```bash
# 1. forge the ticket
ticketer.py -nthash "inter-realm key" -domain-sid "compromised_domain_SID" -domain "compromised_domain_FQDN" -extra-sid "<target_domain_SID>-<RID>" -spn "krbtgt/target_domain_fqdn" "someusername"

# 2. use it to request a service ticket
KRB5CCNAME="someusername.ccache" getST.py -k -no-pass -debug -spn "CIFS/domain_controller" "target_domain_fqdn/someusername@target_domain_fqdn"
```


```bash
ticketer.py -nthash "compromised_domain_krbtgt_NT_hash" -domain-sid "compromised_domain_SID" -domain "compromised_domain_FQDN" -extra-sid "-" "someusername"
```


Impacket's [raiseChild.py](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py) script can also be used to conduct the golden ticket technique automatically when SID filtering is disabled (retrieving the SIDs, dumping the trusted domain's krbtgt, forging the ticket, dumping the forest root keys, etc.). It will forge a ticket with the Enterprise Admins extra SID.

```bash
raiseChild.py "compromised_domain"/"compromised_domain_admin":"$PASSWORD"
```


=== Windows

From Windows machines, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for that purpose.

If SID filtering is disabled, set the RID to 519 to act as Enterprise Admin.

If SID filtering is partially enabled, set the RID >=1000.

##### Referral ticket
```powershell
# Generate the ticket and use Pass-the-Ticket
Rubeus.exe golden /user:Administrator /id:500 /domain:<compromised_domain_FQDN> /sid:<compromised_domain_SID> /groups:513 /sids:<target_domain_SID>-<RID> /aes256:<compromised_domain_krbtgt_aes256_key> /ptt
```

:::

> [!TIP]
> If the goal is to perform a DCSync attack on the target domain - and if SID filtering is disabled - a stealthier approach consists in injecting the "Domain Controllers" (516) and "Enterprise Domain Controllers" (S-1-5-9) RID in the SID history. This can help avoid suspicious logs and detection.

:::

### 🛠️ SID filtering bypass

> a few SIDs will (almost) never be filtered: "Enterprise Domain Controllers" (S-1-5-9) SID and those described by the [trusted domain object (TDO)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/f2ef15b6-1e9b-48b5-bf0b-019f061d41c8#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4), as well as seven well-known SIDs (see [MS-PAC doc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280), and [improsec's blogpost](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained#yui_3_17_2_1_1673614140169_543)).
>
> _(_[_SID filtering_](index#sid-filtering) _theory)_

_//_ [_https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research_](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)

#### CVE-2020-0665

The idea behind [CVE-2020-0665](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0665) is to bypass SID filtering to authenticate as a server in the trusting forest targeting the local admin on this server (RID = 500). To do so, the local domain SID of the server is spoofed to "fake" a child domain in the trusted forest, which will be added to the list of trusted SIDs in the trusting forest domain's TDO ([Trusted Domain Object](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_f2ceef4e-999b-4276-84cd-2e2829de5fc4)) after 24 hours (see [SID filtering](index#sid-filtering)). An inter-realm/referral ticket will then be forged using the spoofed SID as extended SID which will be used to request a service ticket to that server (see [Forging tickets](index#forging-tickets)).

The attack is conducted as follows:

1. Get the local domain's SID of the target server. This step requires Windows older than Windows 10 build 1607, or before Server 2016, as it uses MS-LSAT RPC to query the target server for the SID of its local domain, that is restricted on newer versions and requires administrative privileges on the target.
2. Spoof the local domain's SID of the target server. This steps must be run as `SYSTEM` on the trusted forest's domain controller. The Frida script used for this step is made for Windows Server 2016 version 1607. If the target runs a different version, the address offset might be different and some additional preparation must be done.
3. Forging tickets. For this step, refer to [Kerberos authentication](index#kerberos-authentication) theory chapter for more details about the trust key being used, the ticket forgery is then highly similar to the [Forging ticket](index#forging-tickets) practice part.

> [!TIP]
> For more details about how this attack works under the hood, refer to the article on [dirkjanm.io](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/) by [Dirk-jan Mollema](https://twitter.com/_dirkjan).


> [!WARNING]
> Some considerations to reproduce the attack:
> 
> * Full control over the trusted forest is assumed.
> * Information that flows over to the trusting forest can be modified.
> * There is at least one server joined to a domain in the trusting forest (referred to as the "target server" here).


The attack can be conducted with [Dirk-jan Mollema](https://twitter.com/_dirkjan)'s [forest trust tools](https://github.com/dirkjanm/forest-trust-tools).

##### 1. Get Local Domain SID
```bash
# Obtain the local domain's SID of the target server in the trusting forest
# The hostname (Security Principal Name) of the target server is required
getlocalsid.py "trusted_domain"/"someusername"@"<target_server_FQDN or IP address>" "target_server_NETBIOS_name"
```

##### 2. Spoof the target SID
```bash
# Become a "domain" in the trusted forest using the spoofed SID so that this one is added to the authorized SIDs in the trusting domain
# Intercept the Netlogon request for an existing child domain in the trusted forset and modify the SID with the spoofed one by hooking lsass.exe when the NetrGetForestTrustInformation RPC call is made
# Notice that the SID of the child domain to look for and the local domain's SID of the target server should be modified with the right values
# This is to be run as SYSTEM on the trusted DC
python3 .\frida_intercept.py lsass.exe
```

##### 3. Get local admin on the target
```bash
# 1. Forge an inter-realm/referral ticket with the spoofed SID put as extended SID with RID 500 using the AES key of the incoming trust
ticketer.py -aesKey "AES_key_of_incoming_trust" -domain "trusted_target_domain_FQDN" -domain-sid "trusted_target_domain_SID" -user-id 1000 -groups 513 -extra-sid "<spoofed_SID>"-500 -spn "krbtgt/trusting_target_domain_FQDN" "someusername"

# 2. Request a service ticket using the forged referral ticket
# Notice that keys has to be manually modified in the getftST.py script before
KRB5CCNAME="someusername.ccache" getftST.py -spn "CIFS/target_server_FQDN" -target-domain "trusting_target_domain_FQDN" -via-domain "trusted_target_domain_FQDN" "domain/username" -dc-ip "target_DC_IP"

# 3. Use the obtained ST to access the target server as local admin
KRB5CCNAME=username.ccache smbclient.py -k "trusted_domain"/"someusername"@"target_server_FQDN" -no-pass
```

#### 🛠️ Keys container trust

// [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)

// Enterprise Domain Controllers have `GenericAll` on `Keys` container (`CN=keys,DN=domain,DN=local`), "Default container for key credential objects", used for gMSA ?

// Container should be empty, but if it's not, exploitable seulement s'il y a déjà des objets dans le conteneur ce qui n'est pas censé être le cas par défaut.

#### 🛠️ DNS trust

// [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)

#### 🛠️ GPO on site

// [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)

#### 🛠️ GoldenGMSA

// [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

#### 🛠️ Schema change attack ([source](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent))

Depuis le domaine source, en tant que SYSTEM, on peut modifier le schéma dans la partition de Configuration puis attendre que ce soit répliqué sur le domaine cible

Plus particulièrement en modifiant le defaultSecurityDescriptor de classes intéressantes (groupes, users, GPC), ou retirant le flag confidential

### 🛠️ Abusing permissions

#### Unconstrained delegation abuse

In order to abuse unconstrained delegation across trusts, [TGT delegation](index#tgt-delegation) must be allowed/enabled on the trust, and [Selective Authentication](index#authentication-level) must NOT be enabled (or with a configuration that would allow for the exploitation detailed below, see the [Authentication level](index#authentication-level) chapter).

In addition to that, the ideal setup would be to have a two-way trust between the compromised domain (A) and the target domain (B), in order to allow the exploitation detailed below.

1. (trusting B -> trusted A), allows access from A to B, allows to coerce authentications
2. (trusting A -> trusted B), allows access from B to A, allows the coerced account to authenticate to the attacker-controlled KUD account.

Other regular KUD-abuse-specific requirements apply (e.g. accounts not sensitive for delegation or member of the protected users group), see the [Kerberos Unconstrained Delegation](../kerberos/delegations/unconstrained) page.

If an attacker manages to gain control over an account configured for unconstrained delegation, he could escalate to domain admin privileges. Across trusts, the scenario is very similar. An attacker needs to gain control over a trusted account, configured for KUD (Kerberos Unconstrained Delegation), in order to act on a trusting resource (e.g. trusting domain's DC) as another principal (i.e. domain admin).

> [!TIP]
> By default, all domain controllers are configured for unconstrained delegation.


The [Kerberos Unconstrained Delegation](../kerberos/delegations/unconstrained#practice) page can be consulted in order to obtain operational guidance on how to abuse this context.

In most cases, the attacker will have to:

1. coerce the authentication ([PrinterBug](../print-spooler-service/printerbug), [PetitPotam](../mitm-and-coerced-authentications/ms-efsr), [ShadowCoerce](../mitm-and-coerced-authentications/ms-fsrvp), [DFSCoerce](../mitm-and-coerced-authentications/ms-dfsnm), etc.) of a high-value target (e.g. domain controller) of the trusting domain
2. retrieve the TGT delegated in the service ticket the trusting resource used to access the attacker-controlled KUD account
3. authenticate to trusting resources using the extracted TGT ([Pass the Ticket](../kerberos/ptt)) in order to conduct privileged actions (e.g. [DCSync](../credentials/dumping/dcsync))


> [!TIP]
> Read the [Unconstrained](../kerberos/delegations/unconstrained) article for more insight


#### 🛠️ DACL abuse

TODO // How a domain admin of forest A could administrate a domain in forest B ? [https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS](https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS)

TODO // Regular permissions, ACE, and whatnot abuses, but now between foreign principals, BloodHound comes in handy.

#### 🛠️ ADCS abuse

When an ADCS is installed and configured in an Active Directory environment, a CA is available for the whole forest. Every usual ADCS attack can be executed through intra-forest trusts. [ESC8](https://www.thehacker.recipes/ad/movement/ad-cs/unsigned-endpoints#web-endpoint-esc8) and [ESC11](https://www.thehacker.recipes/ad/movement/ad-cs/unsigned-endpoints#rpc-endpoint-esc11) in particular can be used to pivot to any domain within the forest associated to the C

#### 🛠️ Group memberships

// group scoping, [https://posts.specterops.io/a-pentesters-guide-to-group-scoping-c7bbbd9c7560](https://posts.specterops.io/a-pentesters-guide-to-group-scoping-c7bbbd9c7560)

## Resources

### General

[https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-1-the-mechanics/](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-1-the-mechanics/)

[https://syfuhs.net/windows-and-domain-trusts](https://syfuhs.net/windows-and-domain-trusts)

[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN)

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736874(v=ws.10)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736874(v=ws.10))

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)#ntlm-referral-processing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)#ntlm-referral-processing)

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)?redirectedfrom=MSDN)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/bac4dc69-352d-416c-a9f4-730b81ababb3)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-apds/f47e40e1-b9ca-47e2-b139-15a1e96b0e72)

[https://blogs.msmvps.com/acefekay/tag/active-directory-trusts/](https://blogs.msmvps.com/acefekay/tag/active-directory-trusts/)

[https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d)

[https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Slides-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf](https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Slides-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf)

[https://secureidentity.se/msds-shadowprincipal/](https://secureidentity.se/msds-shadowprincipal/)

[https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)

### Offensive POV

[https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-2-operational-guidance/)

[https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)

[https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)

[https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/)

[https://mayfly277.github.io/posts/GOADv2-pwning-part12](https://mayfly277.github.io/posts/GOADv2-pwning-part12)

[https://adsecurity.org/?p=282](https://adsecurity.org/?p=282)

[https://adsecurity.org/?p=1640](https://adsecurity.org/?p=1640)

[https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/](https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/)

[https://blog.harmj0y.net/redteaming/the-trustpocalypse/](https://blog.harmj0y.net/redteaming/the-trustpocalypse/)

[https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)

[https://adsecurity.org/?p=4056](https://adsecurity.org/?p=4056)

[https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)

[https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

[https://nored0x.github.io/red-teaming/active-directory-Trust-enumeration/](https://nored0x.github.io/red-teaming/active-directory-Trust-enumeration/)

[https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)

[https://adsecurity.org/?p=425](https://adsecurity.org/?p=425)

[https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

[https://www.labofapenetrationtester.com/2019/04/abusing-PAM.html](https://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
