# 🛠️ CMS

## Theory

Content Management System \(CMS\) is a software widely used for websites creation and management. It allows its users to create and manage websites such as blogs, forums, online stores, etc. Due to it's wide use by "non-tech" users, a lot of vulnerabilities can be found on websites using a CMS.

## Practice

### Tools

CMS scan for vulnerabilities on **WordPress** with [WPScan](https://github.com/wpscanteam/wpscan).

Simple scan:

```bash
wpscan -url $URL
```

{% tabs %}
{% tab title="Enumerate users" %}
```bash
wpscan -url $URL -enumerate u
```
{% endtab %}

{% tab title="Brute-force a single user" %}
```bash
wpscan -url $URL -wordlist wordlist.txt -username $username
```
{% endtab %}

{% tab title="Brute-force all the users" %}
```bash
wpscan -url www.example.com -e u -wordlist wordlist.txt
```
{% endtab %}
{% endtabs %}

CMS scan for vulnerabilities with [droopescan](https://github.com/droope/droopescan).

Simple scan:

```bash
droopescan scan -u $URL
```

For known CMS:

```bash
droopescan scan $cms_name -u $URL
```

### Other tools

**Browser extension**: [Wappalyzer](https://www.wappalyzer.com/) allows its user to identify technologies on websites \(including CMS\).  
**Website**: [Whatcms.org](https://whatcms.org/) which helps in answering the question "What CMS Is This Site Using?" by entering an URL.  
**Source code and robots.txt**: information about the CMS used can be written in these files.

