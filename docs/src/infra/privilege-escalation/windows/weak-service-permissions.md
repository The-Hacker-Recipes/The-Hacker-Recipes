# 🛠️ Weak service permissions

## Theory

File permissions in Windows control who can access, modify, or execute files on the system. If these permissions are misconfigured, unauthorized users could potentially alter or replace critical files, leading to security vulnerabilities such as unauthorized access.

Here's a quick summary of Windows file permissions based on the provided table:

    F (Full access): Grants complete control over the file, including modifying and deleting it.
    M (Modify access): Allows editing and deleting the file, but not changing permissions.
    RX (Read and execute access): Permits viewing the file and executing it if it's an executable.
    R (Read-only access): Only allows viewing the file without making changes.
    W (Write-only access): Permits writing to the file but not reading or executing it.

## Pratice

### Insecure Permissions on Service Executable :

This type of abuse can occur when the binary of a Windows service is misconfigured, meaning that the permissions for this binary allow, for example, a local user without special privileges to modify it or even replace it with a malicious one, the Attacker can obtain the privileges of the service account in general a high privileges account.

For the enumeration can be done with Powershell, first using native Powershell commands (Living off the Land) But also with [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). The main difference between the two is on the result PowerUp is able to tell you if a service is vulnerable or not while PowerShell just lists the Binary Services.

```bash
# USING POWERSHELL
> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# USING POWERUP
> Get-ModifiableServiceFile
```

If you have identified your vulnerable binary with a tool like PowerUp or even Winpeas, you can check the permissions of this binary with **icacls.exe**. The most interesting permissions are (F) and (M) if they are related to a group such as `Everyone:` or a local user for exemple.
```bash
> icacls C:\path\to\binary.exe
```

