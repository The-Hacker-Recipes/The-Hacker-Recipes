---
description: They told me I could be anything I wanted ... So I became a domain controller
authors: ShutdownRepo
category: ad
---

# DC Shadow

## Theory

The idea behind this persistence technique is to have an attacker-controlled machine act as a domain controller (shadow DC) to push changes onto the domain by forcing other domain controllers to replicate.

There are two requirements for a machine to act as a domain controller:

1. Be registered as a DC in the domain**: this is done by;
   1. modifying the computer's SPN (`ServicePrincipalName`) to `GC/$HOSTNAME.$DOMAIN/$DOMAIN`
   2. adding an entry like `CN=$HOSTNAME,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=$DOMAIN` with the following attribute values:
      * `objectClass: server`
      * `dNSHostName: $HOSTNAME.$DOMAIN`
      * `serverReference: CN=$HOSTNAME,CN=Computers,DC=$DOMAIN`
2. Be able to request and/or respond to specific RPC calls: `DRSBind`, `DRSUnbind`, `DRSCrackNames,` `DRSAddEntry`, `DRSReplicaAdd`, `DRSReplicaDel`, `DRSGetNCChanges`.

Below is the attack workflow (step 1 & 2 can be switched if need be):

1. Register the workstation that will act as the shadow DC
    1. add the required entry in `CN=Configuration`
    2. modify the workstation's SPN
2. Prepare the changes to be pushed onto the domain (with calls to `DRSAddEntry`)
3. Push the changes by forcing another legitimate DC to replicate from the workstation with a `DRSReplicaAdd` call, which automatically makes a `DRSGetNCChanges` call from the legitimate DC to the shadow DC.
4. Unregister the workstation so it is not longer considered to be a DC (by a `DRSReplicaDel` call and by reverting changes made to `CN=Configuration` and the workstation's SPN). 

![](<./assets/Adding entry to Configuration container.png>)

<div class="caption">(step 1.1) add the entry to <code>CN=Configuration</code></div>


![](<./assets/Modifying the workstation SPN.png>)

(step 1.2) modify the workstation's SPN{.caption}


![](<./assets/DRSUAPI network capture.png>)

An example of DRSUAPI traffic for a successful DC Shadow attack{.caption}


It is important to note that this technique can be used as a "meta" one, in the sense that it permits to use other persistence techniques, such as [SID history](../sid-history.md) , [Delegation to KRBTGT](../kerberos/delegation-to-krbtgt.md) and even [DACL abuse](../dacl).

For instance, a DC Shadow attack can be conducted to register a controlled workstation as a domain controller, and then use that to push changes to the domain that would expose it to DACL abuse.

![](<./assets/overview.png>)

"leHack 2023 - Un conseil, brûlez tout" by Charlie Bromberg and Volker Carstein"{.caption}


## Practice

::: tabs

=== UNIX-like

> [!CAUTION]
> _July 27th 2023_ : There is currently no way to exploit this technique purely from a distant UNIX-like machine, as it requires some tools that have yet to be made.


=== Windows

DC Shadow can be performed by using Mimikatz. It works in every 64-bits Windows Server version up to 2022 (included). Everything happens on the workstation that will act as the shadow DC.

Two Mimikatz shells are required:

* one with domain admin privileges (called the trigger shell from now on)
* one as `NT-AUTHORITY\SYSTEM` (called the RPC shell from now on)

### Preparing shells


```
# In a mimikatz shell, launched with DA rights
# This will be the trigger shell
privilege::debug

# The following command will open a new mimikatz shell as NT-AUTHORITY\SYSTEM
# This will be the RPC shell
process::runp

# On both shell, run the following command to confirm permissions
# On the trigger shell, it will return the domain admin account name (used to lauch the first mimikatz shell)
# On the RPC shell, it will return NT-AUTHORITY\SYSTEM
token::whoami
```


### Preparing changes to push


```
# (RPC shell)
lsadump::dcshadow /object:ObjectToModify /attribute:AttributeToModifyOnTargetedObject /value:NewValueOfTargetedAttribute
```


### Pushing changes


```
# (Trigger shell)
# The command below will register the shadow DC, push the changes, and unregister
lsadump::dcshadow /push
```


See the [`lsadump::dcshadow`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow) at The Hacker Tools for more info.

:::


## Talk

[LeHack 2023 - Un conseil, brulez tout.pdf](<../../.gitbook/assets/LeHack 2023 - Un conseil, brulez tout.pdf>)

## Resources

[https://www.dcshadow.com/](https://www.dcshadow.com/)

[https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow)

[https://stealthbits.com/blog/creating-persistence-dcshadow/](https://stealthbits.com/blog/creating-persistence-dcshadow/)

[https://blog.netwrix.com/2022/09/28/dcshadow_attack/](https://blog.netwrix.com/2022/09/28/dcshadow_attack/)

[https://www.netwrix.com/how_dcshadow_persistence_attack_works.html](https://www.netwrix.com/how_dcshadow_persistence_attack_works.html)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)