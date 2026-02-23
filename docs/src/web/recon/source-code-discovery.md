---
authors: ShutdownRepo, felixbillieres
category: web
---

# Source code discovery

## Theory

Web applications may expose source code, version control systems, or configuration files that should remain inaccessible. These exposures occur when development artifacts are accidentally deployed to production environments or when directory listing is enabled on web servers.

### What can be exposed

Source code discovery can reveal:
- **API keys and secrets**: Hardcoded credentials, tokens, and configuration keys
- **Application logic**: Business rules, authentication mechanisms, and internal workflows
- **Database credentials**: Connection strings and database schemas
- **Internal endpoints**: Administrative interfaces and development APIs
- **Sensitive comments**: Developer notes containing passwords or system information

### Common exposure types

- **Version control systems**: `.git/`, `.svn/`, `.hg/` directories
- **Backup files**: `.bak`, `.old`, `.swp`, `.tmp`, `.orig`, `.save`
- **Configuration files**: `.env`, `config.php`, `web.config`, `appsettings.json`
- **IDE artifacts**: `.idea/`, `.vscode/`, `.DS_Store`
- **Temporary files**: Logs, cache files, and development artifacts

## Practice

### Version control discovery

#### Git repositories

Exposed `.git/` directories allow complete repository reconstruction, including source code, commit history, and sensitive information.

::: tabs

=== GitHack

[GitHack](https://github.com/lijiejie/GitHack) (Python) can be used to download and reconstruct Git repositories from accessible `.git/` directories.

```bash
python3 GitHack.py http://$TARGET/.git/
```

=== git-dumper

[git-dumper](https://github.com/arthaud/git-dumper) (Python) can be used to download exposed Git repositories.

```bash
python3 git_dumper.py http://$TARGET/.git/ output/
```

:::

#### SVN repositories

SVN repositories can be exposed through accessible `.svn/` directories. [svn-extractor](https://github.com/anantshri/svn-extractor) (Python) can be used to extract information from exposed repositories.

### File and directory discovery

Backup files, configuration files, and IDE artifacts are commonly left on servers during development or deployment. [Directory fuzzing](directory-fuzzing.md) tools can be used to discover them systematically.

::: tabs

=== ffuf

```bash
# Backup files
ffuf -w $WORDLIST -u http://$TARGET/FUZZ -e .bak,.old,.swp,.tmp,.orig,.save

# Configuration files
ffuf -w $WORDLIST -u http://$TARGET/FUZZ -e .env,.config,.yaml,.json,.xml
```

=== gobuster

```bash
# Backup files
gobuster dir -u http://$TARGET -w $WORDLIST -x bak,old,swp,tmp

# Configuration files
gobuster dir -u http://$TARGET -w $WORDLIST -x env,config,yaml,json,xml
```

:::

#### DS_Store files

`.DS_Store` files on macOS systems reveal directory structure and file names. [ds_store_exp](https://github.com/lijiejie/ds_store_exp) (Python) can be used to extract file listings from exposed `.DS_Store` files.

```bash
python3 ds_store_exp.py http://$TARGET/.DS_Store
```

### Public files analysis

`robots.txt` and sitemap files, while intended to be public, can reveal hidden directories and files that should be investigated.

```bash
curl http://$TARGET/robots.txt
curl http://$TARGET/sitemap.xml
```

### Automated scanning

::: tabs

=== Dumpall

[Dumpall](https://github.com/0xHJK/dumpall) (Python) can be used to discover and download exposed version control repositories, backup files, and configuration files.

```bash
python3 dumpall.py -u http://$TARGET
```

=== GitLeaks

[GitLeaks](https://github.com/gitleaks/gitleaks) (Go) can be used to scan downloaded repositories for secrets and sensitive information.

```bash
gitleaks detect --source-path ./downloaded_repo --verbose
```

:::

> [!TIP]
> Exposed `.git/` directories and configuration files frequently contain credentials and sensitive application logic.

> [!CAUTION]
> Downloaded source code may contain hardcoded credentials. Tools like GitLeaks should be used to scan for secrets.

## Resources

[GitHack — Git repository downloader](https://github.com/lijiejie/GitHack)

[git-dumper — alternative Git repository downloader](https://github.com/arthaud/git-dumper)

[svn-extractor — SVN repository extractor](https://github.com/anantshri/svn-extractor)

[ds_store_exp — DS_Store file parser](https://github.com/lijiejie/ds_store_exp)

[Dumpall — multi-type exposure scanner](https://github.com/0xHJK/dumpall)

[GitLeaks — secret scanner for Git repositories](https://github.com/gitleaks/gitleaks)

[SecLists — Discovery/Web-Content/common-backups.txt](https://github.com/danielmiessler/SecLists)

[OWASP — testing for source code disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Testing_for_Source_Code_Disclosure)

[CWE-527 — exposure of version control repository](https://cwe.mitre.org/data/definitions/527.html)
