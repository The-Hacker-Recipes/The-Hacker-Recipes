# Grant rights

This abuse can be carried out when controlling an object that has `WriteDacl` over any object.

The attacker can write a new ACE to the target object’s DACL \(Discretionary Access Control List\). This can give the attacker full control of the target object. This can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

For instance, this ACE can be abused to grant `GenericAll` rights over the compromised object.

```bash
Add-DomainObjectAcl -TargetIdentity "target_object" -PrincipalIdentity "controlled_object" -Rights All
```

{% hint style="info" %}
The same process can be applied to allow an object to [DCSync](../credentials/dumping/dcsync.md) \(with `-Rights DCSync`\) even though `GenericAll` includes all `ExtendedRights`, hence the three extended rights needed for DCSync to work \(`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`\)

Pro tip for UNIX-like users, ntlmrelayx has the ability to operate that abuse with the `--escalate-user` option \(see [this](https://medium.com/@arkanoidctf/hackthebox-writeup-forest-4db0de793f96)\).
{% endhint %}

{% hint style="info" %}
A few tests showed the `Add-DomainObjectAcl` command needed to be run with the `-Credential` and `-Domain` options in order to work
{% endhint %}

When an object has `WriteDacl` over the Domain object, it is possible to operate [DCSync](../credentials/dumping/dcsync.md). Exchange Servers used to have this right, allowing attackers to conduct a PrivExchange attack \(see the [PushSubscription abuse](../mitm-and-coerced-authentications/pushsubscription-abuse.md), and the [NTLM relay attack](../lm-and-ntlm/relay.md) using Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) and the `--escalate-user` option\)

## References

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync" %}

