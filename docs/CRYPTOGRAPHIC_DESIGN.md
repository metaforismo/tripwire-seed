# Cryptographic design

## Standards and scope

Version 0.1 implements an English 12-word BIP39 mnemonic, BIP39 seed derivation,
BIP32 hierarchical keys, and the BIP84 native SegWit account at
`m/84'/coin_type'/0'`. Mainnet uses coin type `0`; testnet and signet use `1`.

Primary specifications:

- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [BIP380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)

No custom key derivation, brainwallet transform, or wallet-specific private
format is used.

## Base mnemonic

The operating-system CSPRNG produces 128 bits. BIP39 appends the first four bits
of `SHA256(entropy)` as a checksum, splits the resulting 132 bits into 12 groups
of 11 bits, and maps them to the 2,048-word English list.

The mnemonic is never derived from a sentence. BIP39 explicitly describes
computer-generated randomness rather than user-created “brainwallet” text.

## BIP39 passphrase

BIP39 derives a 64-byte seed using:

```text
PBKDF2-HMAC-SHA512(
  password = NFKD(mnemonic),
  salt = "mnemonic" || NFKD(passphrase),
  iterations = 2048,
  output_length = 64
)
```

The empty passphrase creates the base/decoy wallet. The generated non-empty
passphrase creates the protected wallet. Every passphrase is valid, so
fingerprint and address verification are operational requirements.

## CSPRNG passphrase sampling

For every word, the program requests 16 random bits from the operating system
and masks to the low 11 bits. Because `2^16` is exactly divisible by `2^11`,
each of the 2,048 word indices has equal probability. With `w` independent
words, construction entropy is exactly `11w` bits.

Words are joined with hyphens to reduce confusion with the space-delimited base
mnemonic. The separators are part of the BIP39 passphrase and must be restored
exactly.

## Dice passphrase sampling

Five fair d6 rolls encode a base-6 value in `0..7776`:

```text
v = ((((d1 - 1) * 6 + (d2 - 1)) * 6 + (d3 - 1)) * 6 + (d4 - 1)) * 6 + (d5 - 1)
```

Values from `0` through `6143` are accepted and mapped with `v mod 2048`.
Values from `6144` through `7775` are rejected. The accepted range contains
exactly three complete copies of the 2,048-word index space, so the mapping is
uniform. Rejection is expected and does not reduce the entropy of accepted
words.

This method assumes independent, fair physical rolls. The CLI cannot detect a
loaded die, transcription bias, selective rerolling, or fabricated input.

## Public wallet derivation

For each role, the tool derives:

```text
account:  m/84'/coin_type'/0'
receive:  m/84'/coin_type'/0'/0/0
change:   m/84'/coin_type'/0'/1/*
```

It emits the master fingerprint, account xpub, BIP380-checksummed receive and
change descriptors, and first receive address. The checksum detects descriptor
transcription and copy/paste errors; it does not authenticate the descriptor or
hide the xpub. The account derivation and xpub remain available for manual
watch-only import in compatible software.

The collision check compares the complete derived account xpubs for the decoy
and protected roles. It does not rely only on the four-byte fingerprint and is
not a search of existing wallets, blockchains, private databases, or the global
key space.

## Semantic validation of public references

A version 1 watch-only reference is not accepted merely because it is valid
JSON. For both the decoy and protected roles, the loader parses the account xpub,
requires the fixed BIP84 account path and expected network prefix, derives
relative path `m/0/0`, and reconstructs:

- the first receive address;
- `wpkh([fingerprint/origin]xpub/0/*)` with its BIP380 checksum; and
- `wpkh([fingerprint/origin]xpub/1/*)` with its BIP380 checksum.

The reconstructed values must exactly equal the serialized fields. The role
names, account policy, collision scope, and equality of the two complete account
xpubs are also recomputed. This catches contradictory or partially edited public
metadata before a fingerprint is printed or any secret is requested.

The four-byte master fingerprint cannot itself be proven from the account xpub.
BIP84 reaches the account through hardened derivation, and public child data
cannot recover the hardened parent relationship. The loader therefore checks
that the fingerprint is canonical lower-case hexadecimal and used consistently
inside both descriptors; that is a self-consistency check, not proof of
provenance.

## Watch-only reference fingerprint

The strict version 1 watch-only structure is serialized as compact JSON in its
fixed Rust field order. The public reference fingerprint is:

```text
SHA256(
  "tripwire-seed/watch-only-fingerprint/v1" || 0x00 ||
  compact_version_1_watch_only_json
)
```

The domain separator prevents the digest from being confused with an ordinary
SHA-256 of the JSON or reused silently for another protocol. The fingerprint is
encoded as 64 lower-case hexadecimal characters; verification also accepts
upper-case hexadecimal input.

Every version 1 public field is committed: schema, network, account policy,
account xpubs, BIP380 descriptors, first addresses, roles, and collision
metadata. Any supported field change therefore changes the fingerprint except
with a SHA-256 collision. A future schema must define a new domain separator and
canonical representation rather than silently reusing version 1.

This construction provides integrity only relative to an expected fingerprint
retained through a separate authenticated channel. It is not keyed, so it is
not a MAC; it has no signer, so it is not a digital signature; and computing it
from an untrusted file does not establish provenance.

## Secret lifetime and limitations

- Owned generated strings and BIP39 objects use zeroization where their Rust
  types support it.
- Temporary serialized secret bundles are zeroized after use.
- Hardened BIP32 derivation requires private key material in process memory.
  The upstream BIP32 types do not provide a complete process-wide wipe
  guarantee.
- Watch-only JSON and fingerprints are public wallet metadata and are not
  zeroized, but they can reveal address relationships.
- The operating system, allocator, terminal, swap, crash dumps, cameras, and
  compromised dependencies can retain or expose secrets.
- Compiler optimizations and hidden library copies mean zeroization is defense
  in depth, not a guarantee that no copy ever existed.

Use a dedicated, trusted offline environment and power it down after completing
and verifying backups.
