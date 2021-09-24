# 🛠️ Default credentials

## Theory

Default credentials are a really simple and extremely common way to get initial access to a system. Many devices \(especially in the Internet of Things\) come with default non-random passwords that are often left unchanged. Here is an example of a few very common credentials :

| Username | Password |
| :--- | :--- |
| `admin` | `admin` |
| `root` | `root` |
| `tomcat` | `tomcat` |
| `password` | `password` |

## Practice

### Lists

You can find a bunch of default passwords related to a wide range of brands in these resources:

* [https://cirt.net/passwords](https://cirt.net/passwords)
* [https://datarecovery.com/rd/default-passwords/](https://datarecovery.com/rd/default-passwords/)
* [https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
* [https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)

You can also pick passwords from the list of the most common passwords :

* [https://en.wikipedia.org/wiki/List\_of\_the\_most\_common\_passwords](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)

### Alternatives to lists

You can also find them using Google Dorks:

```text
intext:'password' intext:'default' Application Name
```

Another way would be to check the manual or vendor documentation.

The source code can contain the default credentials in comments, often left out in production by developers.

On physical hardware, a sticker could be present, containing the default credentials.

## References

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web\_Application\_Security\_Testing/04-Authentication\_Testing/02-Testing\_for\_Default\_Credentials" %}

