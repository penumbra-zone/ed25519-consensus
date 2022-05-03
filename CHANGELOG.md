# CHANGELOG

Entries are listed in reverse chronological order.

# 1.2.1

* Change `VerificationKey`'s `Debug` impl to print hex bytes.

# 1.2.0

* Add `to_bytes`/`as_bytes` for `VerificationKey`.
* Add `SigningKey::verification_key()` convenience method (instead of `From`).

# 1.1.0

* Support `no_std`.
* Add `to_bytes`/`as_bytes` methods to complement the `Into` implementations (by @0xdeadbeef).

# 1.0.0

* Remove Zcash-specific language, update dependencies, and re-release as
  `ed25519-consensus`.

# `ed25519-zebra` changelog entries

## 2.2.0

* Add `PartialOrd`, `Ord` implementations for `VerificationKeyBytes`.  While
  the derived ordering is not cryptographically meaningful, deriving these
  traits is useful because it allows, e.g., using `VerificationKeyBytes` as the
  key to a `BTreeMap` (contributed by @cloudhead).

## 2.1.2

* Updates `sha2` version to `0.9` and `curve25519-dalek` version to `3`.

## 2.1.1

* Add a missing multiplication by the cofactor in batch verification and test
  that individual and batch verification agree.  This corrects an omission that
  should have been included in `2.0.0`.

## 2.1.0

* Implements `Clone + Debug` for `batch::Item` and provides
  `batch::Item::verify_single` to perform fallback verification in case
  of batch failure.

## 2.0.0

* Implements ZIP 215, so that batched and individual verification
  agree on whether signatures are valid.

## 1.0.0

* Adds `impl TryFrom<&[u8]>` for all types.

## 1.0.0-pre.0

* Add a note about versioning to handle ZIP 215.

## 0.4.1

* Change `docs.rs` configuration in `Cargo.toml` to not refer to the removed
  `batch` feature so that the docs render correctly on `docs.rs`.

## 0.4.0

* The sync batch verification api is changed to remove a dependence on the
  message lifetime that made it difficult to use in async contexts.

## 0.3.0

* Change terminology from secret and public keys to signing and verification
  keys.
* Remove async batch verification in favor of a sync api; the async approach is
  to be developed in another crate.

## 0.2.3

* The previous implementation exactly matched the behavior of `libsodium`
  `1.0.15` with the `ED25519_COMPAT` configuration, but this configuration
  wasn't used by `zcashd`. This commit changes the validation rules to exactly
  match without `ED25519_COMPAT`, and highlights the remaining inconsistencies
  with the Zcash specification that were not addressed in the previous spec
  fix.

## 0.2.2

* Adds `impl AsRef<[u8]> for PublicKey`.
* Adds `impl AsRef<[u8]> for SecretKey`.

## 0.2.1

* Adds `impl AsRef<[u8]> for PublicKeyBytes`.

## 0.2.0

* Adds experimental futures-based batch verification API, gated by the `batch` feature.

## 0.1.0

Initial release, attempting to match the actual `zcashd` behavior.
