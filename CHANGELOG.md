# CHANGELOG

Entries are listed in reverse chronological order.

# 0.4.1

* Change `docs.rs` configuration in `Cargo.toml` to not refer to the removed
  `batch` feature so that the docs render correctly on `docs.rs`.

# 0.4.0

* The sync batch verification api is changed to remove a dependence on the
  message lifetime that made it difficult to use in async contexts.

# 0.3.0

* Change terminology from secret and public keys to signing and verification
  keys.
* Remove async batch verification in favor of a sync api; the async approach is
  to be developed in another crate.

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
