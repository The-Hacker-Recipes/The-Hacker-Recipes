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

### Impact assessment

Exposed source code should be prioritized based on:
- **Sensitivity of revealed information**: Credentials > API keys > application logic
- **Accessibility**: Publicly accessible > authenticated-only
- **Completeness**: Full source code > partial exposure

## Practice

### Version control discovery

#### Git repositories

Exposed `.git/` directories allow complete repository reconstruction, including source code, commit history, and sensitive information.

::: tabs

=== GitHack

[GitHack](https://github.com/lijiejie/GitHack) downloads and reconstructs Git repositories from accessible `.git/` directories.

```bash
python3 GitHack.py http://$TARGET/.git/
```

=== GitDumper

[GitDumper](https://github.com/arthaud/git-dumper) provides an alternative for downloading exposed Git repositories.

```bash
python3 git_dumper.py http://$TARGET/.git/ output/
```

:::

#### SVN repositories

SVN repositories can be exposed through accessible `.svn/` directories. Tools like [SVN Dumper](https://github.com/anantshri/svn-extractor) extract information from exposed repositories.

### File type discovery

#### Backup files

Backup files (`.bak`, `.old`, `.swp`, `.tmp`, `.orig`, `.save`) are commonly left on servers during development or deployment. Directory fuzzing tools should be used to discover these files systematically.

::: tabs

=== ffuf

```bash
ffuf -w /path/to/wordlist.txt -u http://$TARGET/FUZZ -e .bak,.old,.swp,.tmp,.orig,.save
```

=== gobuster

```bash
gobuster dir -u http://$TARGET -w /path/to/wordlist.txt -x bak,old,swp,tmp
```

:::

#### Configuration files

Configuration files (`.env`, `config.php`, `web.config`, `appsettings.json`, `settings.py`, `config.yaml`, `.htaccess`, `.gitignore`) frequently contain sensitive information and should not be publicly accessible.

### IDE and system files

#### IDE artifacts

IDE directories (`.idea/`, `.vscode/`, `.settings/`) and editor files (`.DS_Store`, `.vimrc`, `.emacs`) can reveal project structure and sensitive information.

#### DS_Store files

`.DS_Store` files on macOS systems reveal directory structure and file names. Tools like `ds_store_parser` can analyze downloaded files.

```bash
# Download and parse
curl http://$TARGET/.DS_Store -o ds_store_file
python3 ds_store_parser.py ds_store_file
```

### Public files analysis

#### Robots.txt and sitemaps

`robots.txt` and sitemap files, while intended to be public, can reveal hidden directories and files that should be investigated.

```bash
curl http://$TARGET/robots.txt
curl http://$TARGET/sitemap.xml
```

### Automated scanning

::: tabs

=== Dumpall

[Dumpall](https://github.com/0xHJK/dumpall) discovers and downloads exposed version control repositories, backup files, and configuration files.

```bash
python3 dumpall.py -u http://$TARGET
```

=== GitLeaks

[GitLeaks](https://github.com/gitleaks/gitleaks) scans downloaded repositories for secrets and sensitive information.

```bash
gitleaks detect --source-path ./downloaded_repo --verbose
```

:::

> [!TIP]
> Exposed `.git/` directories and configuration files frequently contain credentials and sensitive application logic.

> [!CAUTION]
> Downloaded source code may contain hardcoded credentials. Tools like GitLeaks should be used to scan for secrets.

## Resources

### Tools
- [GitHack](https://github.com/lijiejie/GitHack) - Git repository downloader
- [GitDumper](https://github.com/arthaud/git-dumper) - Alternative Git downloader
- [SVN Dumper](https://github.com/anantshri/svn-extractor) - SVN repository extractor
- [Dumpall](https://github.com/0xHJK/dumpall) - Multi-type exposure scanner
- [GitLeaks](https://github.com/gitleaks/gitleaks) - Secret scanner

### Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) - Discovery/Web-Content/common-backups.txt

### References
- [Source Code Disclosure Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Testing_for_Source_Code_Disclosure)
- [Git Exposure Vulnerabilities](https://cwe.mitre.org/data/definitions/527.html)
