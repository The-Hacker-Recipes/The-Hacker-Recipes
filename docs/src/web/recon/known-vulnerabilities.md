---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# Known vulnerabilities

## Theory

This step ends the reconnaissance phase. The previous steps were aimed at gaining knowledge about the attack surface

* Web server
* [Content Management System (CMS)](cms.md)
* [Web Application Firewall (WAF)](waf-fingerprinting.md)
* JavaScript Frameworks
* and other technologies

Known vulnerabilities may then be identified depending on these information.

## Practice

Known vulnerabilities can be found from the following resources

* [exploit-db.com](https://www.exploit-db.com/): an online exploit database
* [searchsploit](https://www.exploit-db.com/searchsploit) is a command-line utility that allows to do offline searches through the exploit-db
* [CVE Details](https://www.cvedetails.com/), [NVD NIST](https://nvd.nist.gov/vuln/search) and [MITRE](https://cve.mitre.org/cve/search_cve_list.html) are online CVE (Common Vulnerabilities and Exposures) searches

```bash
# search exploits for a technology
searchsploit $technology

# Read an exploit
searchsploit -x $exploit_path

# Copy an exploit to the current directory
searchsploit -m $exploit_path

# Update the searchsploit database
searchsploit -u
```

When a vulnerability is found, one can research a Proof-Of-Concept (PoC) to try at exploiting the vulnerability. Most public PoCs can be found on [GitHub](https://github.com/).