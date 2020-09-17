# Password reset

## Theory

During the password recovery process, an attacker may be able to retrieve information by sending an insecure token. This spoofing may allow the attacker to reset the password of other accounts in order to compromise them.

The password reset link should be single, time-limited and secure enough.

## Practice <a id="practice"></a>

* Is it a single link ?
* Is the link limited in time ?
* Is the token exploitable ?
* Is the user enumeration possible ?

