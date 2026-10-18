# Security

Please report a vulnerability privately, not in a public issue: open this
repository's **Security** tab and choose **Report a vulnerability**. You will
hear back within a week.

What counts here:

- a certificate, hostname or signature that should be refused and is not;
- a proxy's credentials, cookies, TLS tickets or a client key reaching
  anywhere they were not sent to;
- a response or request that can be split, smuggled or misread;
- anything that makes a Worker do work an attacker chose.

A fingerprint that a site tells apart from a real browser is not a security
issue; open an ordinary issue for it.

Fixes go into the latest release. Older releases are not patched.
