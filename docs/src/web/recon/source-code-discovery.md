---
authors: ShutdownRepo, felixbillieres
category: web
---

# Source code discovery

Web applications may expose source code, version control systems, or configuration files that should remain inaccessible. These files can reveal API keys, database credentials, application logic, internal endpoints, sensitive comments, and hardcoded credentials.

Common exposures include version control directories (`.git/`, `.svn/`, `.hg/`), backup files (`.bak`, `.old`, `.swp`, `.tmp`), configuration files (`.env`, `config.php`, `web.config`), and IDE files (`.idea/`, `.vscode/`, `.DS_Store`).

## Git repository discovery

Exposed `.git/` directories allow complete repository reconstruction, including source code, commit history, and sensitive information.

::: tabs

=== GitHack

[GitHack](https://github.com/lijiejie/GitHack) downloads and reconstructs Git repositories from accessible `.git/` directories.

=== GitDumper

[GitDumper](https://github.com/arthaud/git-dumper) provides an alternative for downloading exposed Git repositories.

:::

## SVN repository discovery

SVN repositories can be exposed through accessible `.svn/` directories. Tools like [SVN Dumper](https://github.com/anantshri/svn-extractor) can extract information from exposed repositories.

## Backup files discovery

Backup files (`.bak`, `.old`, `.swp`, `.tmp`, `.orig`, `.save`) are commonly left on servers during development or deployment. Directory fuzzing tools should be used to discover these files systematically.

## Configuration files discovery

Configuration files (`.env`, `config.php`, `web.config`, `appsettings.json`, `settings.py`, `config.yaml`, `.htaccess`, `.gitignore`) frequently contain sensitive information and should not be publicly accessible.

## IDE and editor files

IDE directories (`.idea/`, `.vscode/`, `.settings/`) and editor files (`.DS_Store`, `.vimrc`, `.emacs`) can reveal project structure and sensitive information.

## DS_Store files

`.DS_Store` files on macOS systems reveal directory structure and file names. Tools like `ds_store_parser` can analyze downloaded files.

## Robots.txt and sitemap analysis

`robots.txt` and sitemap files, while intended to be public, can reveal hidden directories and files that should be investigated.

## Automated scanning

::: tabs

=== Dumpall

[Dumpall](https://github.com/0xHJK/dumpall) discovers and downloads exposed version control repositories, backup files, and configuration files.

=== GitLeaks

[GitLeaks](https://github.com/gitleaks/gitleaks) scans downloaded repositories for secrets and sensitive information.

:::

> [!TIP]
> Exposed `.git/` directories and configuration files frequently contain credentials and sensitive application logic.

> [!CAUTION]
> Downloaded source code may contain hardcoded credentials. Tools like GitLeaks should be used to scan for secrets.
