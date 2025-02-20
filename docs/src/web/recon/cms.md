---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# Content Management System (CMS)

## Theory

A Content Management System (CMS) is a type of software widely used for websites creation and management. It the allows its users to easily create and manage websites such as blogs, forums and online stores. Among web applications, the large usage of CMS makes those software a huge target.

Here is a shortlist of the most common CMS: [WordPress](https://wordpress.com/), [Joomla](https://www.joomla.org/), [Shopify](https://www.shopify.com/), [Drupal](https://www.drupal.org/), [Magento](https://magento.com/), [Typo3](https://typo3.org/).

## Practice

The use of a CMS on a web application is usually quite easy to spot with visual elements:

* Credits at the bottom or corner of pages
* HTTP headers
* Common files (e.g. `robots.txt`, `sitemap.xml`)
* Comments and metadata (HTML, CSS, JavaScript)
* Stack traces and verbose error messages

Automated scanning tools can also help identify which technologies are used, and if known vulnerabilities may be present. Tools vary depending on the CMS technology to audit.

* [WPScan](https://github.com/wpscanteam/wpscan) (Ruby) can be used for sites that use WordPress
* [droopescan](https://github.com/SamJoan/droopescan) (Python) supports Drupal, SilverStripe and WordPress and partially supports Joomla and Moodle.
* [Wappalyzer](https://www.wappalyzer.com/) is a browser extension that can detect the use of certain software including CMS
* [Whatcms.org](https://whatcms.org/) can help answering the question "What CMS is this site using?" but needs the target website to be accessible from the Internet.

::: tabs

=== WPScan

For web applications built with WordPress, [WPScan](https://github.com/wpscanteam/wpscan) (Ruby) can be used to enumerate information and potential vulnerabilities. Appart from bruteforce and enumeration operations, WPScan doesn't implement exploits.

```bash
# simple scan (no exploitation)
wpscan --url $URL

# enumerate users
wpscan --url $URL --enumerate u

# enumerate a range of users
wpscan --url $URL --enumerate u1-100

# bruteforce a user
wpscan --url $URL --username $username --passwords "/path/to/wordlist.txt"

# enumerate and bruteforce users
wpscan --url $URL --enumerate u --passwords "/path/to/wordlist.txt"
```


=== droopescan

For web applications built with Drupal, SilverStripe, WordPress, Joomla or Moodle, [droopescan](https://github.com/SamJoan/droopescan) (Python) can be used to enumerate information and potential vulnerabilities. Apart from bruteforce and enumeration operations, WPScan doesn't implement exploits.

```bash
# CMS identification
droopescan scan -u $URL

# Basic scan (known CMS)
droopescan scan $cms_name -u $URL
```

:::