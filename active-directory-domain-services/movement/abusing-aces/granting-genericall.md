# Granting GenericAll

This abuse can be carried out when controlling an object that has `WriteDacl` over any object.

The attacker can write a new ACE to the target object’s DACL \(Discretionary Access Control List\). This can give the attacker full control of the target object. This can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

For instance, this ACE can be abused to grant `GenericAll` rights over the compromised object.

```bash
Add-DomainObjectAcl -TargetIdentity "target_object" -Rights All
```

When an object has `WriteDacl` over the Domain object, it is possible to gain domain admin privileges. Exchange Servers used to have this right, allowing attackers to conduct a PrivExchange attack \(see the [PushSubscription abuse](../forced-authentications/privexchange-pushsubscription-abuse.md), and the [NTLM relay attack](../abusing-ntlm/ntlm-relay.md) using Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) and the `--escalate-user` option\)

