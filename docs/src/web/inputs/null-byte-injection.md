---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# 🛠️ Null-byte injection

## Theory

Null byte is a bypass technique for sending data that would be filtered otherwise. It relies on injecting the null byte characters (`%00`, `\x00`) in the supplied data. Its role is to terminate a string.

## Practice

### File access restriction by extension

Accessing a file in an application that appends an extension.

Example:

1. An attacker wants to retrieve the file`/etc/passwd` but an extension `.php` is appended automatically such as `/etc/passwd.php`.
2. The attacker uses the null byte to terminate the string and throw away the `.php` extension: `/etc/passwd%00`

### File upload restriction by extension

Uploading a file that is filtered by its extension.

Example:

1. An attacker wants to upload a `malicious.php`, but the only extension allowed is `.pdf`.
2. The attacker constructs the file name such as `malicious.php%00.pdf` and uploads the file.
3. The application reads the `.pdf` extension, validate the upload, and later throws the end of the string due to the null byte.
4. The file `malicious.php` is then put in the server.