---
authors: ShutdownRepo
category: ad
---

# Skeleton key

## Theory

Skeleton key is a persistence attack used to set a master password on one or multiple Domain Controllers. The master password can then be used to authenticate as any user in the domain while they can still authenticate with their original password. It makes detecting this attack a difficult task since it doesn't disturb day-to-day usage in the domain.

Skeleton key injects itself into the LSASS process of a Domain Controller to create the master password. It requires Domain Admin rights and `SeDebugPrivilege` on the target (which are given by default to domain admins). 

> [!WARNING]
> Since this attack is conducted in memory by reserving a region of memory with `VirtualAllocEx()` and by patching functions, the master password doesn't remain active after a DC reboot.

This attack currently supports NTLM and Kerberos (RC4 only) authentications. Below are a few explanation of how it works depending on the authentication protocol it injects a master key for. 

::: tabs

=== NTLM auth

The attack employs a three-steps process to create a master password for NTLM authentication.

1. Reserves a memory region using `VirtualAllocEx()` for the `lsass.exe` process. This memory space is used to store a modified version of the NTLM password validation function `MsvpPasswordValidate()`.
2. Attaches itself to the `lsass.exe` process and locates `MsvpSamValidate()` (authentication function) from `MSV1_0.dll` (which is the DLL in charge of NTLM authentication).
3. Finds the call to `MsvpPasswordValidate()` (password validation function) in `MsvpSamValidate()` and patches it to make it point to the modified `MsvpPasswordValidate()` stored in the memory region from step 1.

When called, the modified version of `MsvpPasswordValidate()` first calls the original `MsvpPasswordValidate()`: therefore if a legitimate authentication is tried, it will succeed.

If the original `MsvpPasswordValidate()` fails, the modified version will call the original`MsvpPasswordValidate()` again but will make it compare password hash supplied during the authentication with the hash of the master password set when launching the attack (i.e. `mimikatz` by default when using Mimikatz for this attack).


=== Kerberos auth

The attack doesn't support salt-enabled key-derivation functions (i.e. AES128 and AES256) since it would either require to

* compute the relevant user’s Skeleton Key in real time (which is designed to be costly and would likely cause issues on the DC)
* or compute all the domain users’ Skeleton Keys offline and store them, which requires a lot of memory.

The Skeleton Key attack then only supports RC4-HMAC-based Kerberos authentication, as RC4-HMAC’s key-derivation function does not involve a user-based salt (making the Skeleton RC4-HMAC key the same for all users).

There are three steps to create a skeleton key for Kerberos authentication:

1. Reserving a memory region for the `lsass.exe` process using `VirtualAllocEx()`. This memory space is used to store a modified version of `Decrypt` and `SamIRetrieveMultiplePrimaryCredentials()` functions used in following steps.
2. Making sure users will authenticate using RC4-HMAC encryption instead of AES encryption. In order to do that, `SamIRetrieveMultiplePrimaryCredentials()` function is hooked just like `MsvpPasswordValidate()` for NTLM and calls made to this function are patched. The hooked `SamIRetrieveMultiplePrimaryCredentials()` checks for the package name `Kerberos-Newer-Keys` and returns `STATUS_DS_NO_ATTRIBUTE_OR_VALUE` to effectively disable AES-based authentication.
3. Patching `CDLocateCSystem()` from `cryptdll.dll` to call a modified version of the `Decrypt` function. The modified `Decrypt` function works like the modified `MsvpPasswordValidate()` for NTLM : it first calls the original `Decrypt` function to make sure the users can still log on with their original username and password. Then if the previous step fails, it replaces the retrieved password hash with the supplied Skeleton RC4-HMAC key (which is the same as the Skeleton Key NTLM hash) and calls the original `Decrypt` function again, making the authentication successful.

:::


## Practice

Skeleton Key can be injected with the [`misc::skeleton`](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton) command in Mimikatz. It works in every 64-bits Windows Server version up to 2019 (included).

Mimikatz must be either launched as `NT-AUTHORITY\SYSTEM` or be executed with a domain admin account on the Domain Controller. For the latter, debug privileges (`SeDebugPrivilege`) must be set for Mimikatz to work. This can be done with the [`privilege::debug`](https://tools.thehacker.recipes/mimikatz/modules/privilege/debug) command.

```bash
mimikatz "privilege::debug" "misc::skeleton"
```

> [!TIP]
> By default, the master password injected is `mimikatz`.

![](./assets/mimikatz_skeleton_key_ws2019.png)

Skeleton key injection and usage illustration on a Windows Server 2019{.caption}

## Resources

[https://adsecurity.org/?p=1255](https://adsecurity.org/?p=1255)

[https://pentestlab.blog/2018/04/10/skeleton-key](https://pentestlab.blog/2018/04/10/skeleton-key)

[https://www.virusbulletin.com/uploads/pdf/magazine/2016/vb201601-skeleton-key.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/2016/vb201601-skeleton-key.pdf)