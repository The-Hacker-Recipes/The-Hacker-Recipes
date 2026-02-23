---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# Admin & Special Account Enumeration

## Theory

Administrative privileges over the SCCM Management Point (MP) are required to query the MP's WMI database for admin and special accounts. This enumeration step allows identifying SCCM administrators and special service accounts configured within the SCCM infrastructure.

> [!TIP]
> For additional attack techniques and defense strategies related to SCCM enumeration, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [RECON-1: LDAP Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-1/recon-1_description.md)
> - [RECON-2: SMB Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-2/recon-2_description.md)
> - [RECON-3: HTTP Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-3/recon-3_description.md)
> - [RECON-5: SMS Provider Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-5/recon-5_description.md)
> - [RECON-6: Remote Registry Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-6/recon-6_description.md)
> - [RECON-7: Local File Site Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-7/recon-7_description.md)

## Practice

::: tabs

=== Windows

Admin users can be enumerated using the following command:

```powershell
SharpSCCM.exe get class-instances SMS_ADMIN
```

![](<../assets/SCCM_Lateral_Movement_User_Enum.png>)

Admin user enumeration in SCCM{.caption}

Special accounts can be enumerated using the following command:

```powershell
SharpSCCM.exe get class-instances SMS_SCI_Reserved
```

![](<../assets/SCCM_Lateral_Movement_Special_Account_Enum.png>)

Special Account Enumeration in SCCM{.caption}

:::

## Resources

[https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON)

