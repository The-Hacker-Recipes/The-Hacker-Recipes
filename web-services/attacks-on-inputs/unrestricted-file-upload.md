# Unrestricted file upload

## Theory

Many web applications manage files and allow users to upload and download pictures, documents and so on (e.g. profile pictures). When file upload procedures are not secured enough, attackers can sometimes upload content that servers will execute when later requested or included (PHP, ASP, JSP...).

Among other things, unrestricted file uploads can lead to defacement (visual appearance alteration), client-side attacks (like [XSS](../../web/inputs/xss.md)), or even RCE (Remote Code Execution).

## Practice

Testers need to find forms that allow users to upload content. On a server using PHP, the following test can be operated.

1. Upload a PHP file with the following content: `<?php phpinfo(): ?>`
2. Find a way to request or include that file
3. Assert that the `phpinfo()` function is executed
4. Repeat steps 1 to 3 but with a PHP file with a code execution payload: `<?php system('whoami'); ?>`

{% hint style="info" %}
As command execution functions can be filtered (`system`, `passthru`, `exec`, `shell_exec`), the `phpinfo` testing phase is required to assert that arbitrary PHP code is included and interpreted.
{% endhint %}

Exploiting unrestricted file uploads is like playing "cat and mouse". Inputs can be filtered and filters can be bypassed.

* **Filename**: depending on the filters put in place, some tricks can sometimes work like
  * using a valid but **lesser known extension** to bypass blacklists (let's say the `.php` extension is blacklisted, what about `.php3`, `.php4`, `.php5`, `.php6`, `.pht`, `.phpt` and `.phtml` ?)
  * using a **double extension** like `.jpg.php` or `.php.jpg` can sometimes work, either when filenames are badly filtered and controlled, or when Apache HTTP servers are badly configured. On Apache servers, when files have multiple extensions, each extension is mapped either to a MIME type or to a handler. If one of the extensions is mapped to a handler, the requested file will be interpreted with that handler. Consequently, if the `.php` extension is mapped to a PHP handler in the Apache configuration, a filename with multiple extensions will always be interpreted as a PHP file when requested if one of the extensions is `.php`.&#x20;
  * using a **NULL byte** or another separator to bypass filters that do but don't check control characters such as null characters (`.php%00.jpg` or `.php\x00.jpg`) (this as been fixed in PHP 5.3.4), or a separator like `.asp;.jpg` (IIS6 and prior). The file will then be uploaded with the `.php` extension and it will possible to request it and make the server interpret its content.
  * alternating upper and lower case letters to bypass **case sensitive** rules (`.pHp`, `.aSp`)
  * using a **special extension** like `.p.phphp` that might be changed to `.php` after going through some flawed protections
* **Content type (MIME type)**: the media type (sent as "Content-type: MIME type") identifier is sent along with the name and content of the uploaded file. These filters can easily be bypassed by sending a whitelisted/not blacklisted type (`image/jpeg` or `image/png`)
* **File type**: depending on the detector used, testers should make sure to have a valid whitelisted type and include the PHP code in a way it doesn't make the file corrupted (inserting malicious code after valid data/header, or within the file's metadata like the EXIF comments section) to bypass detectors that only read the magic bytes/headers/first characters. For example, it is possible to create a `.php.gif` file with a valid header by writing `GIF89a` at the beginning of the file like the following example.

```php
GIF89a
<?php
// php reverse shell
?>
```

{% hint style="info" %}
Keep in mind that requesting a file and including it are two different things.

If the uploaded file contains PHP code, it can be included and the code will be interpreted, regardless of the filename and extensions. Testers will need to find a way to include that file (see [File inclusion](../../web/inputs/file-inclusion/)) to achieve remote code execution.

If the uploaded file contains a valid PHP extension in its name, it will  usally be possible to request it and the PHP code will be interpreted, no need to combine the file upload with a file inclusion to achieve remote code execution. Of course, this will depend on the server configuration.
{% endhint %}

[Gifsicle](https://github.com/kohler/gifsicle) (C) is a tool used to generate and edit GIF files. Testers can use it to embed PHP code in the comment section of a GIF. This technique can bypass the `getimagesize()` function sometimes used as a file type detection function without additional protections.

[Fuxploider](https://github.com/almandin/fuxploider) (Python) is a tool used to automate the process of detecting and exploiting file upload forms flaws. As any other fuzzing tool, testers need to be careful when using it.

## References

{% embed url="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload" %}

{% embed url="https://teambi0s.gitlab.io/bi0s-wiki/web/file-upload/" %}

{% embed url="https://doddsecurity.com/94/remote-code-execution-in-the-avatars/" %}

{% embed url="https://www.acunetix.com/websitesecurity/upload-forms-threat/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files" %}
