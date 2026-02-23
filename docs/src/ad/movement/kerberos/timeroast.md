---
authors: felixbillieres, ShutdownRepo
category: ad
---

# Timeroasting

## Theory

Timeroasting is an attack technique that abuses Microsoft's proprietary NTP extension to extract password-equivalent hashes for computer and trust accounts from domain controllers without requiring authentication. These hashes can subsequently be cracked offline.

Domain-joined computers synchronize their system clocks using NTP, with domain controllers acting as authoritative time sources. To address NTP's lack of authentication, Microsoft implemented a custom extension that cryptographically authenticates NTP responses using computer account credentials.

When a computer requests time synchronization, it includes its computer account's RID (Relative Identifier) in the NTP request. The domain controller responds with a Message Authentication Code (MAC) computed using the computer account's NTLM hash as the key. This design allows unauthenticated clients to request salted password hashes for any computer account in the domain by specifying different RID values.

> [!NOTE]
> Authentication to the domain controller is not required to make NTP requests. An attacker can query any RID, and the server will respond with a MAC computed using that account's password hash.

While this presents no security risk when computer accounts use strong, randomly generated passwords, many Active Directory environments contain accounts with weak or default passwords, particularly those created through legacy methods or manual provisioning processes.

Unlike [Kerberoasting](kerberoast.md), Timeroasting returns only RIDs rather than computer account names. To map RIDs to hostnames, attackers can leverage SMB NULL session enumeration if available, or correlate successfully cracked passwords against a list of known computer names gathered through reconnaissance.

## Practice

Timeroasting can be performed in two contexts: unauthenticated (for initial access) and authenticated (for lateral movement or privilege escalation). Each approach offers distinct advantages.

### Unauthenticated Timeroasting

> [!IMPORTANT]
> Unlike [Kerberoasting](kerberoast.md), unauthenticated Timeroasting can be carried out without any prior foothold (no valid domain credentials required).

This approach is particularly valuable for initial access scenarios where no domain credentials are available. However, it only returns RIDs rather than computer names, requiring additional steps to map hashes to specific accounts.

::: tabs

=== UNIX-like

The [Timeroast](https://github.com/SecuraBV/Timeroast) (Python) tool can extract computer account password hashes from a domain controller.

```bash
python3 timeroast.py "$DC_IP"
```

Alternatively, [NetExec](https://github.com/Pennyw0rth/NetExec) (formerly CrackMapExec) includes a Timeroasting module that can perform the attack without authentication.

```bash
netexec smb "$DC_IP" -M timeroast
```

The extracted SNTP hashes can be cracked using [Hashcat](https://github.com/hashcat/hashcat) mode 31300 (requires a recent or beta version). 

Alternatively, the [timecrack](https://github.com/SecuraBV/Timeroast/blob/main/extra-scripts/timecrack.py) Python script can perform dictionary-based attacks, though it is slower than optimized Hashcat operations.

```bash
# Using Hashcat (mode 31300)
hashcat -m 31300 -a 0 -O hashes.txt $wordlist --username

# Using timecrack.py (alternative)
timecrack.py extracted_hashes.txt $wordlist
```

=== Windows

The [Timeroast](https://github.com/SecuraBV/Timeroast) (PowerShell) tool can be used to perform the attack from Windows systems.

```powershell
. .\timeroast.ps1
```

:::

### Authenticated Timeroasting

Performing Timeroasting with valid domain credentials offers distinct advantages, making it valuable beyond initial access scenarios:

* **Automatic RID-to-hostname mapping**: When authenticated, RIDs can be automatically resolved to their corresponding computer account names through Active Directory queries, eliminating the need for manual correlation or SMB NULL session enumeration.
* **Improved cracking performance**: SNTP hashes extracted via Timeroasting can be cracked approximately 10 times faster than traditional Kerberos TGS-REP (etype 23) hashes. While this does not make randomly generated machine passwords crackable, it significantly improves success rates when targeting weak passwords, particularly in environments with poor password hygiene or legacy provisioning processes.
* **Enhanced operational security**: While [Kerberoasting](kerberoast.md) can be modified to target computer accounts by requesting Service Principal Names (SPNs) for all systems, this approach generates substantial network traffic and is more likely to be detected. Timeroasting produces less conspicuous network patterns and remains a relatively obscure technique, making it more suitable for stealth-focused red team operations.

> [!NOTE]
> Authenticated Timeroasting might appear redundant since tools like Rubeus or Invoke-Kerberoast could be adapted to target computer accounts. However, the significant performance improvements and reduced detection profile make Timeroasting a valuable alternative in red team scenarios.

::: tabs

=== Windows

The [Invoke-AuthenticatedTimeRoast](https://github.com/The-Viper-One/Invoke-AuthenticatedTimeRoast) (PowerShell) tool is designed for authenticated Timeroasting operations and automatically resolves RIDs to hostnames through Active Directory queries.

```powershell
# Default execution
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP

# Generate wordlist based on computer names
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP -GenerateWordlist
```

:::

### Cracking SNTP hashes

SNTP hashes can be cracked using [Hashcat](https://github.com/hashcat/hashcat) mode 31300. This mode requires Hashcat v7.1.2 or later; earlier versions (such as v6.2.6) do not support this hash format.

When the hash file contains RIDs as usernames (as output by tools like `netexec` or `timeroast.py`), the `--username` flag must be used to properly parse the hash format.

```bash
hashcat -m 31300 -a 0 -O hashes.txt $wordlist --username
```

> [!TIP]
> When cracking SNTP hashes, supplement standard wordlists and rule sets with a custom wordlist containing all computer account names (lowercased, without the trailing `$`). This approach helps identify cases where computer passwords match their hostnames—a pattern frequently observed when accounts are created using the `net computer` command or when the "Assign this computer account as a pre-Windows 2000 Computer" compatibility option is enabled in the Active Directory Users and Computers GUI.

> [!TIP]
> NTP traffic is common in AD environments, making Timeroasting difficult to detect. The attack generates minimal audit logs and is unlikely to trigger security alerts.

## Resources

[https://github.com/SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)

[https://github.com/The-Viper-One/Invoke-AuthenticatedTimeRoast](https://github.com/The-Viper-One/Invoke-AuthenticatedTimeRoast)

[Timeroasting, Trustroasting and Computer Spraying - Secura Whitepaper](https://cybersecurity.bureauveritas.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)

