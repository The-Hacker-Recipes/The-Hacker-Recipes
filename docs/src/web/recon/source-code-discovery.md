---
authors: ShutdownRepo, felixbillieres
category: web
---

# Source code discovery

Web applications sometimes expose source code, version control systems, or configuration files that should not be publicly accessible. Discovering these files can reveal sensitive information such as API keys and secrets, database credentials, application logic and business rules, internal endpoints and functionality, comments with sensitive information, and hardcoded passwords or tokens.

Common exposed files and directories include version control systems (`.git/`, `.svn/`, `.hg/`), backup files (`.bak`, `.old`, `.swp`, `.tmp`), configuration files (`.env`, `config.php`, `web.config`), IDE files (`.idea/`, `.vscode/`, `.DS_Store`), and temporary files and logs.

## Git repository discovery

Git repositories can be exposed if the `.git/` directory is accessible. This allows attackers to download the entire source code, commit history, and potentially sensitive information.

::: tabs

=== GitHack

[GitHack](https://github.com/lijiejie/GitHack) (Python) is a tool that can download and reconstruct a Git repository from a publicly accessible `.git/` directory.

```bash
# Download exposed Git repository
python3 GitHack.py http://target.com/.git/

# Note: Some versions/forks may support specifying output directory with -o option
```

=== GitDumper

[GitDumper](https://github.com/arthaud/git-dumper) (Python) is another tool for downloading Git repositories from exposed `.git/` directories.

```bash
# Download Git repository
python3 git_dumper.py http://target.com/.git/ output/
```

=== Manual testing

```bash
# Check if .git directory is accessible
curl -I http://target.com/.git/

# Try to access Git config
curl http://target.com/.git/config

# Try to access Git index
curl http://target.com/.git/index

# List Git objects (if directory listing is enabled)
curl http://target.com/.git/objects/
```

:::

## SVN repository discovery

Subversion (SVN) repositories can also be exposed, typically through the `.svn/` directory.

```bash
# Check for SVN entries
curl http://target.com/.svn/entries

# Try to access SVN wc.db (SQLite database)
curl http://target.com/.svn/wc.db
```

Tools like [SVN Dumper](https://github.com/anantshri/svn-extractor) can be used to extract information from exposed SVN repositories.

## Backup files discovery

Backup files are often created during development or deployment and may be left on the server.

```bash
# Common backup file extensions to test
curl http://target.com/index.php.bak
curl http://target.com/index.php.old
curl http://target.com/index.php.swp
curl http://target.com/index.php~
curl http://target.com/index.php.tmp
curl http://target.com/index.php.orig
curl http://target.com/index.php.save
```

### Automated discovery

Use directory fuzzing tools with backup file wordlists:

```bash
# Using ffuf with backup extensions
ffuf -w /path/to/wordlist.txt -u http://target.com/FUZZ -e .bak,.old,.swp,.tmp,.orig,.save

# Using gobuster
gobuster dir -u http://target.com -w /path/to/wordlist.txt -x bak,old,swp,tmp
```

## Configuration files discovery

Configuration files often contain sensitive information and should not be publicly accessible.

```bash
# Common configuration files
curl http://target.com/.env
curl http://target.com/config.php
curl http://target.com/web.config
curl http://target.com/appsettings.json
curl http://target.com/settings.py
curl http://target.com/config.yaml
curl http://target.com/.htaccess
curl http://target.com/.gitignore
```

## IDE and editor files

IDE and editor files can reveal project structure and sometimes sensitive information.

```bash
# Check for IDE directories
curl http://target.com/.idea/
curl http://target.com/.vscode/
curl http://target.com/.project
curl http://target.com/.classpath
curl http://target.com/.settings/

# Check for editor files
curl http://target.com/.DS_Store
curl http://target.com/.vimrc
curl http://target.com/.emacs
```

## DS_Store files

`.DS_Store` files on macOS can reveal directory structure and file names.

```bash
# Download and parse DS_Store file
curl http://target.com/.DS_Store -o ds_store_file

# Use tools like ds_store_parser (various implementations available on GitHub)
python3 ds_store_parser.py ds_store_file
```

## Robots.txt and sitemap analysis

While `robots.txt` and sitemaps are meant to be public, they can reveal hidden directories and files.

```bash
# Check robots.txt
curl http://target.com/robots.txt

# Check sitemap
curl http://target.com/sitemap.xml
curl http://target.com/sitemap.txt
```

## Automated scanning

::: tabs

=== Dumpall

[Dumpall](https://github.com/0xHJK/dumpall) (Python) is a tool that can discover and download exposed version control repositories, backup files, and configuration files.

```bash
# Scan for exposed files
# Note: Check the project README for exact syntax as options may vary by version
python3 dumpall.py -u http://target.com
```

=== GitLeaks

[GitLeaks](https://github.com/gitleaks/gitleaks) can scan Git repositories for secrets and sensitive information. Useful after downloading an exposed repository.

```bash
# Scan downloaded repository
gitleaks detect --source-path ./downloaded_repo --verbose
```

:::

> [!TIP]
> Source code discovery can reveal critical information. Always check for exposed `.git/` directories and configuration files, as they often contain credentials and sensitive application logic.

> [!CAUTION]
> Downloaded source code may contain hardcoded credentials or sensitive information. Use tools like GitLeaks to scan for secrets before manually reviewing code.
