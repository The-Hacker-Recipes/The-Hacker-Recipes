---
authors: CravateRouge, ShutdownRepo, sckdev
category: ad
---

# Grant ownership

t has the following command-line arguments.This abuse can be carried out when controlling an object that has `WriteOwner` or `GenericAll` over any object.

The attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they see fit. For instance, the attacker could change the target object's permissions and [grant rights](grant-rights.md).

::: tabs

=== UNIX-like

From UNIX-like systems, this can be done with [Impacket](https://github.com/SecureAuthCorp/impacket)'s owneredit.py (Python).

```bash
owneredit.py -action write -new-owner 'attacker' -target 'victim' 'DOMAIN'/'USER':'PASSWORD'
```

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set owner $TargetObject $ControlledPrincipal
```


=== Windows

From Windows systems, this can be achieved with [Set-DomainObjectOwner](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObjectOwner/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash
Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'
```

:::