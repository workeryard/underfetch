Certificates for `trust.test.ts`, made with openssl and valid for a century:
a CA (P-256), a server certificate for `localhost` and a client certificate
(RSA 2048) it signed, and the CA and client key again in DER. The CA's own
key was thrown away, so nothing else can be signed with it. Test keys only.
