# CHANGELOG

Entries are listed in reverse chronological order.

# 0.2.3

* The previous implementation exactly matched the behavior of `libsodium`
  `1.0.15` with the `ED25519_COMPAT` configuration, but this configuration
  wasn't used by `zcashd`. This commit changes the validation rules to exactly
  match without `ED25519_COMPAT`, and highlights the remaining inconsistencies
  with the Zcash specification that were not addressed in the previous spec
  fix.

# 0.2.2

* Adds `impl AsRef<[u8]> for PublicKey`.
* Adds `impl AsRef<[u8]> for SecretKey`.

# 0.2.1

* Adds `impl AsRef<[u8]> for PublicKeyBytes`.

# 0.2.0

* Adds experimental futures-based batch verification API, gated by the `batch` feature.

# 0.1.0

Initial release, attempting to match the actual `zcashd` behavior.
