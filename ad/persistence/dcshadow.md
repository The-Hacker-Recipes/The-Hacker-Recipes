# DCShadow

## Theory

In January 2018, [Benjamin Delpy](https://twitter.com/gentilkiwi) and [Vincent Le Toux](https://twitter.com/mysmartlogon) discovered a persistance technique named DCShadow. They explained how an attacker that has Domain Admin or Enterprise Admin privileges (precisely `DS-Install-Replica` `DS-Replication-Manage-Topology` and `DS-Replication-Synchronize` minimal rights) could create a rogue Domain Controller by adding `Server` and `nTDSDSA` objects in the configuration naming context to push malicious objects with replication process at legitimate Read-Write Domain Controller. Moreover, the attacker must configure the following values on [servicePrincipalName LDAP attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname) of the rogue DC: `E3514235-4B06-11D1-AB04-00C04FC2DCD2/8515DDE8-1CE8-44E5–9C34-8A187C454208/<DNS domain name>` and `GC/<DNS hostname>/<DNS forest name>`. Those are necessary to use [Directory Replication Service](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47). The attacker use DRSUAPI functions by calling DCERPC methods to push data:

* [DRSAddEntry](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/06764fc5-4df6-4104-b6af-a92bdaa81f6e) to add objects to promote the computer into DC.
* [DRSReplicaAdd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/7219df91-4eea-494f-88e3-780d40d2d559) to add replication source & avoid Knowledge Consistency Checker (KCC) process that initiates AD spanning tree replication topology every 15 minutes.
* [DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) from legit DC to ask data synchronization.
* Each call is prefixed with a call to [DRSBind](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d) method and suffixed with a call to [DRSUnbind](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/49eb17c9-b6a9-4cea-bef8-66abda8a7850) method.

Now that the attack is complete, the attacker delete SPNs, `Server` and `nTDSDSA` objects to restore the rogue DC to normal domain server.

The main goal of DCShadow is to combine it with other persistance techniques as [SID History](/ad/persistence/sid-history.md), [AdminSDHolder](/ad/persistence/adminsdholder.md), [configure RBCD on the KRBTGT account](/ad/persistence/kerberos/delegation-to-krbtgt.md), edit [ntpwdHistory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/529c9a6e-3666-43b5-9c45-0ab0b319d58e) attribute, edit [PrimaryGroupID](https://learn.microsoft.com/en-us/windows/win32/adschema/a-primarygroupid) attribute, edit [whenChanged](https://learn.microsoft.com/en-us/windows/win32/adschema/a-whenchanged) attribute, modify DACLs and even more, to be more opsec against SIEM because only legitimate DCs send their logs to the log collector.

## Practice

Many commands are possible to exploit different persistence attacks with DCShadow,I will not list all of them however I advise you to see the [DCShadow part of THR's tool wiki](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow).

{% tabs %}
{% tab title="Windows" %}
On Windows, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used to modify any attribute with [`lsadump::dcshadow`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow):

* Start RPC server and specify attribute to modify in first tab:

```bash
!+
!processtoken
lsadump::dcshadow /object:$OBJECT_TO_MODIFY /attribute:$ATTRIBUTE_TO_MODIFY /value=$VALUE_TO_SET
```

* In second tab, push values:

```bash
sekurlsa::pth /user:Administrator /domain:$DOMAIN /ntlm:$NTLM_HASH /impersonate
lsadump::dcshadow /push
```
{% endtab %}

{% tab title="UNIX-like" %}
{% hint style="warning" %}
🛠️ dcshadow.py WIP...
{% endhint %}
{% endtab %}
{% endtabs %}

## Ressources

{% embed url="https://www.dcshadow.com/" %}

{% embed url="https://web.archive.org/web/20180129120052/https://blog.alsid.eu/dcshadow-explained-4510f52fc19d" %}

{% embed url="https://static.tenable.com/marketing/whitepapers/Whitepaper-DCShadow_Explained_A_Technical_Deep_Dive_Into_the_New_AD_Attack.pdf" %}

{% embed url="https://www.synetis.com/dcshadow-attaque-ad/" %}

{% embed url="https://www.nopsec.com/blog/in-the-dcshadow-how-to-become-a-domain-controller/" %}

{% embed url="https://www.nolimitsecu.fr/dcshadow/" %}

{% embed url="https://blog.riskivy.com/dcshadow/" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow" %}