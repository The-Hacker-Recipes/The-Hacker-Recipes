# enum4linux ⚙️

The Perl script [enum4linux.pl](https://github.com/CiscoCXSecurity/enum4linux) is a powerful tool able to operate recon techniques for [LDAP](ldap.md), [NBT-NS](nbt-ns.md) and [MS-RPC](ms-rpc.md). It's an alternative to a similar program named [enum.exe](https://packetstormsecurity.com/files/download/31882/enum.tar.gz) (C++) created for Windows systems. Lately, a rewrite of enum4linux in Python has surfaced, called [enum4linux-ng.py](https://github.com/cddmp/enum4linux-ng). The enum4linux scripts are mainly wrappers around the Samba tools [nmblookup](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html), [net](https://www.samba.org/samba/docs/current/man-html/net.8.html), [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) and [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html).

The following techniques can be operated.

* Service & port scan (for LDAP(S), SMB, NetBIOS, MS-RPC)
* NetBIOS names and workgroup (via [reverse lookup](nbt-ns.md))
* SMB dialects checks (SMBv1 only or SMBv1 and higher)
* RPC sessions checks (checks if the user creds supplied are valid or if [null session](ms-rpc.md#null-sessions) works)
* Domain information via LDAP (find out whether host is a parent or child DC)
* Domain information via RPC ([via SMB named pipe](ms-rpc.md#recon-through-interesting-named-pipes) `\pipe\lsarpc` for MS-RPC)
* OS information via RPC ([via SMB named pipe](ms-rpc.md#recon-through-interesting-named-pipes) `\pipe\srvsvc` for MS-RPC)
* Users, groups, shares, policies, printers, services via RPC
* Users, groups and machines via [RID cycling](ms-rpc.md#rid-cycling)
* SMB Share names bruteforcing

All of the techniques mentioned above (except RID cycling) will be operated when running the following command.

```bash
enum4linux-ng.py -A $TARGET_IP
```

RID cycling can be enabled with the `-R` option.
