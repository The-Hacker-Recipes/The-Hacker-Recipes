---
authors: ShutdownRepo
category: web
---

# Default credentials

## Theory

Default credentials are a really simple and extremely common way to get initial access to a system. Many devices (especially in the Internet of Things) come with default non-random passwords that are often left unchanged. Below is a list of very common credentials :

| Username | Password |
| ---------- | ---------- |
| `admin` | `admin` |
| `root` | `root` |
| `tomcat` | `tomcat` |
| `password` | `password` |

## Practice

Default passwords can be found through the following means

* Password lists
    * [SecLists Default-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
    * [Default Creds Cheatsheet](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)
    * [CIRT.net passwords](https://cirt.net/passwords)
    * [Datarecovery default password](https://datarecovery.com/rd/default-passwords/)
* [Wikipedia's list of most common passwords](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)
* Google Dorks: `intext:'password' intext:'default' Application Name`
* Manual or vendor documentation
* Source code
* Physically (e.g. a sticker indicating the default credentials)

> [!TIP]
> This technique is not to be confused with credential bruteforcing which aims at sending multiple login+password attempts until valid credentials are found. The "default credentials" technique aims at finding potential valid creds depending on the information gathered during the reconnaissance phase.

## Resources

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)