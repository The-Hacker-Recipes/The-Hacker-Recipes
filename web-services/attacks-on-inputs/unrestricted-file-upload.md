# Unrestricted file upload

## Theory

Many web applications manage files and allow users to upload and download pictures, documents and so on \(e.g. profile pictures\). When file upload procedures are not secured enough, attackers can sometimes upload content that servers will execute when later requested \(PHP, ASP, JSP...\).

Among other things, unrestricted file uploads can lead to defacement \(visual appearance alteration\), client-side attacks \(like [XSS](xss-cross-site-scripting.md)\), or even RCE \(Remote Code Execution\).

## Practice

Testers need to find forms that allow users to upload content. On a server using PHP, the following test can be operated.

1. Upload a PHP file with the following content: `<?php phpinfo(): ?>`
2. Find a way to request that file
3. Assert that the `phpinfo()` function is executed
4. Repeat steps 1 to 3 but with a PHP file with a code execution payload: `<?php system('whoami'); ?>`

{% hint style="info" %}
As command execution functions can be filtered \(`system`, `passthru`, `exec`, `shell_exec`\), the `phpinfo` testing phase is required to assert that arbitrary PHP code is included and interpreted.
{% endhint %}

Exploiting unrestricted file uploads is like playing "cat and mouse". Inputs can be filtered and filters can be bypassed.

* **Filters on the extension**: depending on the filters put in place, some tricks can sometimes work like
  * using a valid but **lesser known extension** to bypass blacklists \(let's say the `.php` extension is blacklisted, what about `.php3`, `.php4`, `.php5`, `.php6`, `.pht`, `.phpt` and `.phtml` ?\)
  * using a **double-extension** to bypass filters that don't check the extension ends the filename

    \(`.jpg.php` on Apache, `.asp;.jpg` on IIS6 and prior\)

  * using a **NULL-byte** to bypass filters that do but don't check control characters such as null characters \(`.php%00.jpg` or `.php\x00.jpg`\) \(this as been fixed in PHP 5.3.4\)
  * alternating upper and lower case letters to bypass case sensitive rules \(`.pHp`, `.aSp`\)
* **Filters on the media type \(MIME type\)**: the media type identifier is sent along with the name and content of the uploaded file. These filters can easily bypassed by sending a whitelisted/not blacklisted type \(`image/jpeg` or `image/png`\)
* **Protection mechanisms on dangerous extensions**: `.p.phphp` might be changed to `.php` after going through some flawed protections
* **File type detection**: depending on the detector used, testers can try **concatenation** \(inserting malicious code after valid data/header, or within the file's metadata like the EXIF comments section\) to bypass detectors that only read the magic bytes/headers/first characters. For example, it is possible to create a `.php.gif` file with a valid header by writing `GIF89` at the beginning of the file like the following example.

```php
GIF89
<?php
// php reverse shell
?>
```

[Gifsicle](https://github.com/kohler/gifsicle) \(C\) is a tool used to generate and edit GIF files. Testers can use it to embed PHP code in the comment section of a GIF. This technique can bypass the `getimagesize()` function sometimes used as a file type detection function without additional protections.

[Fuxploider](https://github.com/almandin/fuxploider) \(Python\) is a tool used to automate the process of detecting and exploiting file upload forms flaws. As any other fuzzing tool, testers need to be careful when using it.

## References

{% embed url="https://owasp.org/www-community/vulnerabilities/Unrestricted\_File\_Upload" caption="" %}

{% embed url="https://teambi0s.gitlab.io/bi0s-wiki/web/file-upload/" caption="" %}

{% embed url="https://doddsecurity.com/94/remote-code-execution-in-the-avatars/" caption="" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files" caption="" %}

