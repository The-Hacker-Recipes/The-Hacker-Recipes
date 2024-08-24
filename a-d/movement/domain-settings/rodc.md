---
description: Read-Only Domain Controller
---

# RODC

## Theory

> The read-only Domain Controller (RODC) is a solution that Microsoft introduced for physical locations that don’t have adequate security to host a Domain Controller but still require directory services for resources in those locations. A branch office is the classic use case.
>
> (By Elad Shamir on [specterops.io](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06))

RODC holds a read-only filtered copy of the Active Directory database with all the sensitives attributes deleted, like the LAPS passwords (this refers to [RODC Filtered Attribute Set](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459\(v=ws.10\)#rodc-fas) (FAS)), and cache only specific credentials.&#x20;

### RODC Management

As any Active Directory object, an RODC has an attribute named `managedBy`. Any user or group specified in the attribute has local administrative rights on the RODC. From an attacker point of view, this means that compromising an account listed in the `managedBy` attribute leads to an RODC admin access. And with sufficient rights to modify this attribute, an attacker can promote himself to RODC admin.

### Authentication with an RODC

To authenticate a principal locally, the RODC must be allowed to retrieve his credentials. Only users, groups and computers that are in the [msDS-RevealOnDemandGroup](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealondemandgroup) and not in [msDS-NeverRevealGroup](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-neverrevealgroup) may have their credentials [cached](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459\(v=ws.10\)#credential-caching) on the RODC to be used for future local authentication (in this case, their principal name IDs are added to its [msDS-Revealed-List](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealedlist) attribute). The attributes `msDS-RevealOnDemandGroup` and `msDS-NeverRevealGroup` define the [Password Replication Policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc730883\(v=ws.10\)) of the RODC.

> **The default PRP (Password Replication Policy) specifies that no account passwords can be cached on any RODC**, and certain accounts are explicitly denied from being cached on any RODC.\
> ([Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459\(v=ws.10\)#credential-caching))

In case the RODC has cached the principal's credentials and thus, is able to authenticate it locally, it will issue a TGT. To do so, the RODC holds a derived version of the `krbtgt` key named `krbtgt_XXXXX`(where XXXXX is its random version number) and uses it to sign and encrypt the generated TGT. This `krbtgt` account's version number can also be found in its `msDS-SecondaryKrbTgtNumber` attribute.&#x20;

{% hint style="info" %}
The RODC computer account has reset rights on the account `krbtgt_XXXXX`'s password.
{% endhint %}

When the RODC generates the TGT, it indicates in the `kvno` field the version number of the key used to generate the ticket. With this TGT, it is possible to request a Service Ticket (ST) against the RODC or any accessible standard writable Domain Controller (provided that the principal is listed in `msDS-RevealOnDemandGroup` and not listed in `msDS-NeverRevealGroup`).

<figure><img src="../../../.gitbook/assets/RODC-Authentication mindmap.png" alt=""><figcaption><p>RODC authentication flow</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/RODC-Access to resources mindmap.png" alt=""><figcaption><p>RODC service access flow</p></figcaption></figure>

## Practice

Several attacks can be performed on RODCs:

* [RODC golden ticket](../kerberos/forged-tickets/rodc-golden-tickets.md)
* [Key list attack](../credentials/dumping/kerberos-key-list.md)
* [Exploiting control over a RODC computer object](../dacl/rights-on-rodc-object.md)

## Resources

{% embed url="https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06" %}

{% embed url="https://adsecurity.org/?p=3592" %}

{% embed url="https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/" %}

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754218(v=ws.10)?redirectedfrom=MSDN#how-the-authentication-process-works-on-an-rodc" %}

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753459(v=ws.10)#credential-caching" %}
