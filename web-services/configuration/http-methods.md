# 🛠️ HTTP methods abuse

## Theory

Some HTTP methods \(a.k.a. verbs\) can be used for malicious purposes: PUT, DELETE, etc.

The HTTP methods abuse is not aimed at gaining access to a specific page like verb tampering but more like what methods are accepted by the server and how can we profit from those

{% embed url="https://github.com/ShutdownRepo/httpmethods" %}

## Pratique

### Reconnaissance

The HTTP method `OPTIONS` allows anyone to know which request methods are supported by the server.

```text
curl -X OPTIONS https://example.com -i
```

#### PUT

The `PUT` method can be used to upload arbitrary files. Some directories have different rights, it can be useful to test the method on a wide range of directories.

**Uploading a file with a specific extension**

[davtest](https://gitlab.com/kalilinux/packages/davtest) is a tool for HTTP method testing \(specific to WebDAV\).

> This program attempts to exploit WebDAV enabled servers by:
>
> * attempting to create a new directory \(MKCOL\)
> * attempting to put test files of various programming langauges \(PUT\)
> * optionally attempt to put files with .txt extension, then move to executable \(MOVE\)
> * check if files executed or were uploaded properly - optionally upload a backdoor/shell file for languages which execute

```text
davtest.pl -url https://example.com
```

#### DELETE

The DELETE method can be used to delete a resource, which can be useful from an attacker's point of view \(denial of service, sabotage...\).

### CVE-2017-12615 - Apache Tomcat PUT

This vulnerability targets Apache Tomcat 7.0.0 to 7.0.79 running on Windows. By design, you are not allowed to upload JSP files via the PUT method on the Apache Tomcat servers. This is likely a security measure to prevent an attacker from uploading a JSP shell and gaining remote code execution on the server. However, due to the insufficient checks, an attacker could gain remote code execution on Apache Tomcat servers from version 7.0.0 to version 7.0.79 where the PUT method is enabled.

The request to upload a JSP file to the server is as simple as that:

```text
PUT /myfile.jsp/
Host: domain-name:port
Connection: close
Content-Length: 85

<% out.write("<html><body><h3>[+] JSP upload successfully.</h3></body></html>"); %>
```

You can also exploit it using curl: [https://github.com/breaktoprotect/CVE-2017-12615\#exploit-using-curl](https://github.com/breaktoprotect/CVE-2017-12615#exploit-using-curl)

{% embed url="https://github.com/breaktoprotect/CVE-2017-12615" %}

