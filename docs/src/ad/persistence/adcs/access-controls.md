---
authors: ShutdownRepo
category: ad
---

# Access controls

## Theory

In [their research papers](https://posts.specterops.io/certified-pre-owned-d95910965cd2), [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) identified a set of vectors of domain persistence based on access control misconfigurations (dubbed DPERSIST3). 

Active Directory Certificate Services add multiple objects to AD, including securable ones which principals can have permissions over. This includes Certificate templates, Certificate Authorities, CA server, etc.

In the same research papers, domain escalation techniques abusing misconfigurated access controls were identified dubbed [ESC4](https://posts.specterops.io/certified-pre-owned-d95910965cd2#7c4b), [ESC5](https://posts.specterops.io/certified-pre-owned-d95910965cd2#0a38) and [ESC7](https://posts.specterops.io/certified-pre-owned-d95910965cd2#fdbf)).

If an attacker obtains sufficient permissions in a domain, he could modify security descriptors of AD CS components, in order to make them vulnerable to the attacks mentioned in [Movement > AD-CS > Access controls](../../movement/adcs/access-controls.md).

These modifications can be made with tools like [Impacket's (Python) dacledit.py](https://github.com/fortra/impacket/pull/1291) or with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module), as explained in [grant-rights.md](../../movement/dacl/grant-rights.md).