---
authors: KenjiEndo15, ShutdownRepo
category: web
---

# Password change

Websites that manage user accounts usually offer a "password change" feature. This offers attackers an interesting vector as it could potentially lead to Account Takeover (ATO).

When this feature is present on a website, there a a few things to check.

* Is the previous password required to set a new one? If it's not, this could potentially make CSRF attacks lead to Account Takeover (ATO).
* Is the username/id/login/email sent somewhere in the password change request? If it is, can that parameter be changed to another usename/id/... to change another account's password?