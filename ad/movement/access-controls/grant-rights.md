# Grant rights

This abuse can be carried out when controlling an object that has `WriteDacl` over any object.

The attacker can write a new ACE to the target object’s DACL (Discretionary Access Control List). This can give the attacker full control of the target object. This can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

For instance, this ACE can be abused to grant `GenericAll` rights over the compromised object.

```bash
Add-DomainObjectAcl -TargetIdentity "target_object" -PrincipalIdentity "controlled_object" -Rights All
```

{% hint style="info" %}
A few tests showed the `Add-DomainObjectAcl` command needed to be run with the `-Credential` and `-Domain` options in order to work
{% endhint %}

The same process can be applied to allow an object to [DCSync](../credentials/dumping/dcsync.md) (with `-Rights DCSync`) even though `GenericAll` includes all `ExtendedRights`, hence the two extended rights needed for DCSync to work (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`)

Exchange Servers used to have WriteDacl over domain objects, allowing attackers to conduct a [PrivExchange](../exchange-services/privexchange.md) attack.

For this specific use case, on UNIX-like systems, [dcsync.py](https://github.com/n00py/DCSync) can be used to abuse WriteDacl permission against a domain object to grant DCSync rights and operated the dump.

```bash
dcsync.py -dc "domaincontroller" -t "target object distinguished name" "domain\user:password"
```

Alternatively, ntlmrelayx has the ability to operate that abuse with the `--escalate-user` option (see [this](https://medium.com/@arkanoidctf/hackthebox-writeup-forest-4db0de793f96)).

## References

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync" %}
