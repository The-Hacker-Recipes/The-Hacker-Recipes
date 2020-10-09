# Granting ownership

This abuse can be carried out when controlling an object that has `WriteOwner` or `GenericAll` over any object.

The attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they see fit. This can be achieved with [Set-DomainObjectOwner](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObjectOwner/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'
```

