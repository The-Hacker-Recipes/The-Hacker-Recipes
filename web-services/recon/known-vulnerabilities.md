# 🛠️ Known vulnerabilities

## Theory

Once we have gathered all the useful information we could, it's time to find possible vulnerabilities associated with the components we found.

## Practice

### Tool

Searching exploits with [searchsploit](https://github.com/offensive-security/exploitdb).

```bash
searchsploit $component_name
```

Two interesting commands related to searchsploit:

```bash
# Check what is inside a payload
searchsploit -x $payload_name.txt
# Update the searchsploit database
searchsploit -u
```

{% hint style="info" %}
Searchsploit gets its database directly from [exploit-db](https://www.exploit-db.com/).
{% endhint %}

### Manual research

**CVE lists**:

* [CVE Details](https://www.cvedetails.com/)
* [NVD NIST](https://nvd.nist.gov/vuln/search)
* [MITRE](https://cve.mitre.org/cve/search_cve_list.html)

When a vulnerability is found, one can research a Proof-Of-Concept \(POC\) on the internet and more precisely, on [GitHub](https://github.com/).

