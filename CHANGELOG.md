# CHANGELOG

Entries are listed in reverse chronological order.

# 0.2.2

* Adds `impl AsRef<[u8]> for PublicKey`.
* Adds `impl AsRef<[u8]> for SecretKey`.

# 0.2.1

* Adds `impl AsRef<[u8]> for PublicKeyBytes`.

# 0.2.0

* Adds experimental futures-based batch verification API, gated by the `batch` feature.

# 0.1.0

Initial release, attempting to match the actual `zcashd` behavior.
