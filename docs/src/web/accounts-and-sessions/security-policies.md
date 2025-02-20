---
authors: ShutdownRepo
category: web
---

# Security policies

## Theory

‌Passwords are strings used to authenticate a user or services. They are very important and must meet several criteria because a password that is too weak can easily be guessed via a brute force attack.

* For a simple user: at least twelve alphanumeric characters using minimum two of these following types : upper and lower case letters, numbers and special characters. 
* For a privileged user (administrator): at least twelve alphanumeric characters using minimum three of these following types : upper and lower case letters, numbers and special characters. 

## Practice 

Check when registering on the application if those criteria are required to set a password and if we can bypass the policy.

* Is the password policy strong enough ?
* Is the password policy applied ? On the front end? On the Back End?