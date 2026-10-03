# Changelog

## 1.1.0

Compatibility and security fixes so that the library behaves like the JS reference implementation (`altcha-lib` v2).

### Breaking changes

- `ChallengeParameters.ExpiresAt` and `ServerSignatureVerificationData.Expire` changed from `long?` to `double?`, so fractional expiry values signed by JS issuers can be read. This breaks source and binary compatibility for code that reads these properties.
- `AltchaPow.VerifySolution` throws `ArgumentException` when `HmacSignatureSecret` is null or empty. Before, it skipped the signature check and accepted unsigned or forged challenges.
- A challenge deserialized from JSON is verified against its `parameters` exactly as received: unknown keys, JSON value types and key casing are all covered by the signature, and the key is derived from the same JSON. Changes made to the typed `Challenge.Parameters` after deserialization are ignored by `VerifySolution`.
- Zero and empty optional parameters (`expiresAt: 0`, `memoryCost: 0`, `parallelism: 0`, `keySignature: ""`, `data: {}`) are now signed as they are serialized, and only null values are left out, as in JS. Null optional parameters are never written to JSON, whatever the serializer options.

### Fixes

- Signature: challenges that were tampered with on the wire (string-typed numbers, extra keys, different key casing, duplicate keys) are rejected. JS-issued challenges with unknown parameter keys, zero or empty values, or fractional `expiresAt` now verify.
- Signature: challenges serialized with default or ASP.NET `JsonSerializerOptions` (which write nulls) verify again.
- Expiry: `expiresAt` is compared against the current time in fractional seconds, and any non-zero value, including negative values, is an expiry. The Sentinel `expire` value can be fractional or negative; a negative value counts as expired.
- Key prefix: matching is case-insensitive, including the last digit of an odd-length prefix, and `CreateChallenge` issues the prefix in lowercase.
- `CreateChallenge` adds a `keySignature` only to signed challenges.
- `VerifySolution` returns `InvalidSolution` instead of throwing `AltchaException` when signed parameters cannot be used to derive the key (unsupported algorithm, or invalid key prefix, salt or nonce hex). In ASP.NET Core, such payloads are reported as `InvalidSolution` instead of `Malformed`.
- Random nonce and salt are 16 bytes, as in JS.

## 1.0.0

Initial release.
