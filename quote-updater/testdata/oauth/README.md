# Google sign-in test keys

Test-only RSA keys standing in for Google's ID-token signing keys (`auth.rs` and the
backoffice's sign-in tests). They sign nothing real.

- `signer-a.key`, `signer-b.key`: RSA 2048, PKCS#8 PEM, made with
  `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.
- `jwks-a.json`: key `a`'s public half as Google publishes its keys, a JWK set, under key id
  `key-a`. `jwks-ab.json`: keys `a` and `b` (`key-b`), as after a rotation.

The JWK `n` is the key's modulus (`openssl rsa -in signer-a.key -noout -modulus`, hex, as
base64url bytes) and `e` is 65537 (`AQAB`).
