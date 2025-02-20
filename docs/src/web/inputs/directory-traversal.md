---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# 🛠️ Directory traversal

## Theory

Directory traversal (or Path traversal) is a vulnerability that allows an individual to read arbitrary files on a web server. Inputs that are not validated by the back-end server may be vulnerable to payloads such as "../../../". Using this method, an attacker can go beyond the root directory of the website, thus reaching arbitrary files hosted on the web server (`/etc/passwd`, `/etc/hosts`, `c:/boot.ini`, etc.).

### Notes

Some details are important to know beforehand.

#### Path separator

As the [Owasp](https://kennel209.gitbooks.io/owasp-testing-guide-v4/content/en/web_application_security_testing/testing_directory_traversalfile_include_otg-authz-001.html) mentions, each operating system uses different characters as a path separator.

_Unix-like OS_:

```
root directory: "/"
directory separator: "/"
```

_Windows OS' Shell'_:

```
root directory: "<drive letter>:\"
directory separator: "\" or "/"
```

_Classic Mac OS_:

```
root directory: "<drive letter>:"
directory separator: ":"
```

#### Windows

Files and directories are case-insensitive, so there's no need to try different payloads based on case sensitivity. Also, one has to make sure that the payloads don't use a fixed drive letter ("C:"), but more ("D:", "E:"...).

Directory traversal could lead to Remote Code Execution (RCE).

## Practice

### Tool

The tool [dotdotpwn](https://github.com/wireghoul/dotdotpwn) (Perl) can help in finding and exploiting directory traversal vulnerabilities by fuzzing the web app. However, manual testing is usually more efficient.

```bash
# With a request file where /?argument=TRAVERSAL (request file must be in /usr/share/dotdotpwn)
dotdotpwn.pl -m payload -h $RHOST -x $RPORT -p $REQUESTFILE -k "root:" -f /etc/passwd
​
# Generate a wordlist in STDOUT that can be used by other fuzzers (ffuf, gobuster...)
dotdotpwn -m stdout -d 5
```

### Manual testing

#### Reconnaissance

The first step is to find what kind of system is used (Linux, Windows...). One could do that by checking on which [web technology](https://www.thehacker.recipes/web/recon/web-technologies) is used (some technologies run on Linux while others run on Windows).

Next, finding the right parameter to inject is essential. Usually, a vulnerable parameter is one that requires a file that will be fetched by the back-end server using a path (form parameters, cookies...).

```bash
# Example
http://example.com/getItem.jsp?item=file.html
```

Then, to construct a payload, it's interesting to have a set of important files to search:

* [Linux (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#interesting-linux-files)
* [Windows (PayloadsAllTheThings)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#interesting-windows-files)

#### Filter bypass

Various filters could be set for a web application (using a Web Application Firewall for example). A set of bypass payloads can be found in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#basic-exploitation).

### User privilege

[soffensive.com](https://www.soffensive.com/posts/web-app-sec/2018-06-19-exploiting-blind-file-reads-path-traversal-vulnerabilities-on-microsoft-windows-operating-systems/):

> If you can successfully retrieve one of the following files, you are at least a member of the Administrators group:

```
    c:/documents and settings/administrator/ntuser.ini
    c:/documents and settings/administrator/desktop/desktop.ini
    c:/users/administrator/desktop/desktop.ini
    c:/users/administrator/ntuser.ini
```

> [!WARNING]
> There may be no "administrator" account, you have to guess the right one in that case.

> If you can read either of these files, the file reading process has `LocalSystem`privileges.

```
    c:/system volume information/wpsettings.dat
    C:/Windows/CSC/v2.0.6/pq
    C:/Windows/CSC/v2.0.6/sm
    C:/$Recycle.Bin/S-1-5-18/desktop.ini
```

## Resources

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)

[https://kennel209.gitbooks.io/owasp-testing-guide-v4/content/en/web_application_security_testing/testing_directory_traversalfile_include_otg-authz-001.html](https://kennel209.gitbooks.io/owasp-testing-guide-v4/content/en/web_application_security_testing/testing_directory_traversalfile_include_otg-authz-001.html)

[https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)

[https://www.soffensive.com/posts/web-app-sec/2018-06-19-exploiting-blind-file-reads-path-traversal-vulnerabilities-on-microsoft-windows-operating-systems/](https://www.soffensive.com/posts/web-app-sec/2018-06-19-exploiting-blind-file-reads-path-traversal-vulnerabilities-on-microsoft-windows-operating-systems/)