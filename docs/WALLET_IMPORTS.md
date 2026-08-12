# Wallet import guidance

## Read this first

Always perform a recovery drill before funding either wallet. Start on signet
or testnet where supported. Record the master fingerprint, derivation path, and
first receive address printed by `tripwire-seed`, then require the destination
wallet to reproduce the expected public data.

Stop if any value differs. Common causes include a passphrase typo, a different
derivation path, a different network, Unicode normalization surprises, or an
application-specific account policy.

The watch-only JSON is a `tripwire-seed` interchange file, not a vendor-native
wallet file. It contains the exact public values needed for manual import and
comparison, including BIP380-checksummed receive/change descriptors, but
Sparrow, COLDCARD, and Ashigaru are not expected to open that JSON directly.

## Sparrow Wallet

Sparrow supports 12-word BIP39 software-wallet import and separate master
fingerprint, derivation, and xpub fields for watch-only wallets. Its official
[Quick Start guide](https://sparrowwallet.com/docs/quick-start.html) documents
both flows.

For the decoy wallet:

1. Create a new or imported software wallet.
2. Select 12 BIP39 words and enter the base mnemonic.
3. Leave the BIP39 passphrase empty.
4. Select native SegWit with `m/84'/0'/0'` on mainnet.
5. Verify the master fingerprint and first receive address.

For the protected wallet, repeat the process in a separate Sparrow wallet and
enter the BIP39 passphrase exactly, including hyphens.

For watch-only use, create an xpub/watch-only keystore and enter the account
xpub, master fingerprint, and derivation from the exported JSON. Public xpubs
do not spend funds, but they reveal wallet activity and address relationships;
treat them as privacy-sensitive.

## COLDCARD

COLDCARD's official [Master Seed guide](https://coldcard.com/docs/master-seed/)
documents 12-word BIP39 import. Its [advanced tools
guide](https://coldcard.com/docs/advanced/) documents BIP39 passphrase wallets
and SeedQR display/import on supported devices.

1. Begin with an empty or deliberately reset device and choose `Import Existing`
   with `12 Words`.
2. Enter the base mnemonic manually, or scan the numeric SeedQR on a supported
   COLDCARD Q only in a controlled environment.
3. Verify the base-wallet fingerprint before treating it as the decoy wallet.
4. Apply the BIP39 passphrase on the COLDCARD itself.
5. Verify the protected-wallet fingerprint and first BIP84 receive address.

SeedQR contains only the mnemonic. It does not contain the separate BIP39
passphrase. A camera that sees it has obtained the full base-wallet secret and
can attempt passphrase guesses offline.

## Ashigaru

Ashigaru describes its recovery model as a standards-based mnemonic secured by
a passphrase on the [official project site](https://ashigaru.rs/). The
[Terminal navigation guide](https://ashigaru.rs/docs/ashigaru-terminal-navigation/)
shows the create/restore wallet flow.

1. Use Ashigaru's create/restore flow on a verified installation.
2. Enter the 12-word mnemonic.
3. Leave the passphrase empty for the decoy role, or enter the generated
   passphrase exactly for the protected role.
4. Confirm the network and BIP84 account details before funding.

Ashigaru may expose additional wallet features and account families beyond the
BIP84 account emitted here. This project does not export Ashigaru application
state, Dojo configuration, PayNym metadata, BIP47 relationships, labels, or
transaction history.

## Operational tripwire limits

A decoy balance is not an automated alarm. Detecting a spend requires monitoring
the decoy wallet, which can reveal public-key or address information to the
monitoring infrastructure. This project deliberately leaves monitoring out of
scope. Decide separately whether the privacy cost of monitoring is acceptable.
