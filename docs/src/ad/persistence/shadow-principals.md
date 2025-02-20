---
authors: Pri3st, ShutdownRepo
category: ad
---

# Shadow Principals (PAM)

## Theory

When a Bastion Forest is compromised, there are multiple ways to obtain persistence on the forest it manages (i.e. called "Production Forest" here).

1. Mark a low-privilege user from the Production Forest as an Shadow Security Principal in the Bastion Forest
2. Modify a Shadow Principal Object's DACL: add ACEs over a Shadow Principal Object (at least `Read Members` and `Write Members`) allowing a controlled user add and remove principals at will (in the `member` attribute.

## Resources

[https://www.labofapenetrationtester.com/2019/04/abusing-PAM.html](https://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)

[https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)