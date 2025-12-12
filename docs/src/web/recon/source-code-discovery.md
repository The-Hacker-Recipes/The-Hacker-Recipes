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
python3 GitHack.py http://$TARGET/.git/
```

# Note: Some versions/forks may support specifying output directory with -o option
```

=== GitDumper

[GitDumper](https://github.com/arthaud/git-dumper) (Python) is another tool for downloading Git repositories from exposed `.git/` directories.

```bash
# Download Git repository
python3 git_dumper.py http://$TARGET/.git/ output/
```

=== Manual testing

```bash
# Check if .git directory is accessible
curl -I http://$TARGET/.git/

# Try to access Git config
curl http://$TARGET/.git/config

# Try to access Git index
curl http://$TARGET/.git/index

# List Git objects (if directory listing is enabled)
curl http://$TARGET/.git/objects/
```

:::

## SVN repository discovery

Subversion (SVN) repositories can also be exposed, typically through the `.svn/` directory.

```bash
# Check for SVN entries
curl http://$TARGET/.svn/entries

# Try to access SVN wc.db (SQLite database)
curl http://$TARGET/.svn/wc.db
```

Tools like [SVN Dumper](https://github.com/anantshri/svn-extractor) can be used to extract information from exposed SVN repositories.

## Backup files discovery

Backup files are often created during development or deployment and may be left on the server.

```bash
# Common backup file extensions to test
curl http://$TARGET/index.php.bak
curl http://$TARGET/index.php.old
curl http://$TARGET/index.php.swp
curl http://$TARGET/index.php~
curl http://$TARGET/index.php.tmp
curl http://$TARGET/index.php.orig
curl http://$TARGET/index.php.save
```

### Automated discovery

Use [directory fuzzing](directory-fuzzing.md) tools with backup file wordlists:

```bash
# Using ffuf with backup extensions
ffuf -w /path/to/wordlist.txt -u http://$TARGET/FUZZ -e .bak,.old,.swp,.tmp,.orig,.save

# Using gobuster
gobuster dir -u http://$TARGET -w /path/to/wordlist.txt -x bak,old,swp,tmp
```

## Configuration files discovery

Configuration files often contain sensitive information and should not be publicly accessible.

```bash
# Common configuration files
curl http://$TARGET/.env
curl http://$TARGET/config.php
curl http://$TARGET/web.config
curl http://$TARGET/appsettings.json
curl http://$TARGET/settings.py
curl http://$TARGET/config.yaml
curl http://$TARGET/.htaccess
curl http://$TARGET/.gitignore
```

## IDE and editor files

IDE and editor files can reveal project structure and sometimes sensitive information.

```bash
# Check for IDE directories
curl http://$TARGET/.idea/
curl http://$TARGET/.vscode/
curl http://$TARGET/.project
curl http://$TARGET/.classpath
curl http://$TARGET/.settings/

# Check for editor files
curl http://$TARGET/.DS_Store
curl http://$TARGET/.vimrc
curl http://$TARGET/.emacs
```

## DS_Store files

`.DS_Store` files on macOS can reveal directory structure and file names.

```bash
# Download and parse DS_Store file
curl http://$TARGET/.DS_Store -o ds_store_file
```

# Use tools like ds_store_parser (various implementations available on GitHub)
python3 ds_store_parser.py ds_store_file
```

## Robots.txt and sitemap analysis

While `robots.txt` and sitemaps are meant to be public, they can reveal hidden directories and files.

```bash
# Check robots.txt
curl http://$TARGET/robots.txt

# Check sitemap
curl http://$TARGET/sitemap.xml
curl http://$TARGET/sitemap.txt
```

## Automated scanning

::: tabs

=== Dumpall

[Dumpall](https://github.com/0xHJK/dumpall) (Python) is a tool that can discover and download exposed version control repositories, backup files, and configuration files.

```bash
# Scan for exposed files
# Note: Check the project README for exact syntax as options may vary by version
python3 dumpall.py -u http://$TARGET
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
