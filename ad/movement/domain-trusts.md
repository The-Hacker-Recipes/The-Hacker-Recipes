# 🛠️ Trusts



{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

Thoughts below

Access direction = !(one-way trust direction)

There are four types of Active Directory trusts available — external trusts, realm trusts, forest trusts, and shortcut trusts. ([https://techgenix.com/active-directory-trusts/](https://techgenix.com/active-directory-trusts/))

There are two main types of trusts in Microsoft Documentation : intraforest (between domains in the same forest), interforest (between two different forests)

A forest trust is a trust between two root domains in their respective forest

Trust between domains != trust between forests. The security boundary is the forest, not the domain. Elevating from domain to forest is possible while forest to another is harder.

Security Considerations for Active Directory (AD) Trusts ([https://adsecurity.org/?p=282](https://adsecurity.org/?p=282))

Forest trust ticket forging, a.k.a. enhance golden ticket from domain to access other domains in the parent forest : [https://adsecurity.org/?p=1588](https://adsecurity.org/?p=1588)&#x20;

"you can **spoof any RID >1000** group if SID history is enabled across a Forest trust! In most environments, this will allow an attacker to compromise the forest. For example the Exchange security groups, which allow for a [privilege escalation to DA](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/) in many setups all have RIDs larger than 1000. Also many organisations will have custom groups for workstation admins or helpdesks that are given local Administrator privileges on workstations or servers." ([https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/))

ldapdomaindump can be used with python to dump trust information

How a domain admin of forest A could administrate a domain in forest B ? [https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS](https://social.technet.microsoft.com/Forums/windowsserver/en-US/fa4070bd-b09f-4ad2-b628-2624030c0116/forest-trust-domain-admins-to-manage-both-domains?forum=winserverDS)

{% embed url="https://blog.harmj0y.net/redteaming/the-trustpocalypse/" %}

{% embed url="https://blog.harmj0y.net/redteaming/domain-trusts-were-not-done-yet/" %}

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent" %}

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}

{% embed url="https://nored0x.github.io/red-teaming/active-directory-Trust-enumeration/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/" %}

{% embed url="https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/" %}

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN" %}

{% embed url="https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/" %}
