# Granting GenericAll

This abuse can be carried out when controlling an object that has `WriteDacl` over any object.

The attacker can write a new ACE to the target object’s DACL \(Discretionary Access Control List\). This can give the attacker full control of the target object. This can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

For instance, this ACE can be abused to grant `GenericAll` rights over the compromised object.

```bash
Add-DomainObjectAcl -TargetIdentity "target_object" -PrincipalIdentity "controlled_object" -Rights All
```

{% hint style="info" %}
The same process can be applied to grant the DCSync right to an object
{% endhint %}

{% hint style="info" %}
A few tests showed the `Add-DomainObjectAcl` command needed to be run with the `-Credential` and `-Domain` options in order to work
{% endhint %}

When an object has `WriteDacl` over the Domain object, it is possible to gain domain admin privileges. Exchange Servers used to have this right, allowing attackers to conduct a PrivExchange attack \(see the [PushSubscription abuse](../forced-authentications/privexchange-pushsubscription-abuse.md), and the [NTLM relay attack](../abusing-ntlm/ntlm-relay.md) using Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) and the `--escalate-user` option\)

{% hint style="success" %}
Pro tip for UNIX-like users, ntlmrelayx has the ability to operate that abuse with the --escalate-user option \(see [this](https://medium.com/@arkanoidctf/hackthebox-writeup-forest-4db0de793f96)\).
{% endhint %}

