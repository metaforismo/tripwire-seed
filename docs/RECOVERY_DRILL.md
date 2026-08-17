# Version-pinned recovery drill protocol

This protocol is for proving that one disposable Tripwire Seed wallet pair can
be recovered in specific, version-pinned third-party wallet software. It is a
manual release gate, not an automated test and not a certification of Sparrow,
COLDCARD, Ashigaru, or future versions of those products.

Use only newly generated, **unfunded** signet or testnet material. Never use a
production mnemonic, production BIP39 passphrase, funded address, existing
hardware-wallet seed, or another person's device or account.

## What a successful drill establishes

For one frozen Tripwire Seed commit, one candidate executable, and one pinned
wallet/platform combination, a successful drill shows that:

- the empty BIP39 passphrase recreates the intended decoy account;
- the exact non-empty BIP39 passphrase recreates the intended protected account;
- the recovered public account policy agrees with a prior strict watch-only
  reference; and
- `tripwire-seed verify` exact-matches that prior reference and its independently
  retained fingerprint.

It does not audit the external wallet, prove compatibility with other versions,
protect against a compromised device, or justify funding the test wallet.

## Roles

Use two people when possible:

- **operator**: performs the drill on the isolated test systems;
- **reviewer**: verifies version pins, artifact hashes, checklist completion, and
  privacy-safe evidence without receiving the mnemonic or passphrase.

The reviewer must not ask for screenshots, recordings, logs, exports, or support
bundles containing wallet secrets or complete wallet metadata.

## Freeze the test environment

Before generating any disposable wallet material, record only public build and
software information:

```text
Tripwire Seed commit:
Tripwire Seed candidate archive:
Candidate archive SHA-256:
Candidate executable SHA-256:
GitHub attestation identifier or URL:
Operating system and architecture:
Wallet product:
Wallet version / firmware version:
Wallet artifact download source:
Wallet artifact SHA-256 or vendor verification result:
Hardware model or simulator/test environment, when applicable:
Test network:
Date:
Operator initials or pseudonym:
Reviewer initials or pseudonym:
```

Do not record local usernames, hostnames, serial numbers, device identifiers,
wallet names derived from personal information, or unrelated filesystem paths.

## Prepare the isolated environment

1. Review the frozen Tripwire Seed source and verify the candidate checksum and
   provenance according to `docs/REPRODUCIBLE_BUILDS.md`.
2. Use a clean, trusted, offline or appropriately isolated machine.
3. Disable screen sharing, terminal recording, clipboard history, cloud backup,
   crash-report upload, remote support, and automatic photo synchronization for
   the duration of the drill.
4. Use a destination wallet installation or device intended only for disposable
   testing. Reset it according to its official procedure before the drill.
5. Confirm the selected network is signet or testnet. Stop if the wallet cannot
   clearly separate the chosen test network from mainnet.
6. Prepare two independent storage locations for public evidence:
   - the strict watch-only JSON reference;
   - its printed 64-character fingerprint stored separately.

Both items are privacy-sensitive financial metadata even though they contain no
spending secret.

## Generate the disposable reference

Run the frozen candidate interactively:

```console
tripwire-seed create \
  --network signet \
  --watch-only-out drill.tripwire-watch-only.json
```

Use the default CSPRNG passphrase generation or the documented fair-dice method.
Do not substitute a memorable human phrase for this interoperability drill.

During creation:

- complete the required mnemonic and passphrase re-entry checks;
- do not use dangerous plaintext export;
- display SeedQR only when the specific device import path requires it and the
  camera environment is controlled;
- write down the mnemonic and passphrase only on temporary offline material under
  the operator's control; and
- retain the printed watch-only fingerprint independently from the JSON file.

The public reference is the source of truth for later comparison. Do not edit it
to match what an external wallet displays.

## Validate the reference before secret entry

On a separate invocation, inspect the public file before typing any secret:

```console
tripwire-seed fingerprint \
  --watch-only drill.tripwire-watch-only.json
```

Require the output to match the independently retained fingerprint. A mismatch
means the drill stops before mnemonic or passphrase entry.

The operator and reviewer should record only:

```text
Reference schema accepted: yes/no
Independent fingerprint matched before secret prompts: yes/no
```

Do not include the fingerprint itself in public evidence when it would expose a
private wallet relationship.

## Remove the original live session

Before recovery, close the original Tripwire Seed process and remove any
external wallet state created during initial inspection. The purpose is to prove
recovery from the mnemonic/passphrase plus the prior public reference, not to
reuse an already-open wallet.

This step cannot guarantee that the operating system, SSD, swap, snapshots,
backups, or camera environment forgot the secrets. The drill must not claim
secure deletion.

## Recover the decoy role

For the selected wallet product and pinned version:

1. Start its documented restore/import flow.
2. Enter the same 12-word BIP39 mnemonic.
3. Leave the BIP39 passphrase empty.
4. Select the exact test network used in the reference.
5. Select or confirm native SegWit BIP84 account zero according to the product's
   documented UI.
6. Compare the public values exposed by that wallet against the `decoy` account
   in the prior reference.

Require exact agreement for every value the wallet exposes from this set:

- role and network;
- BIP84 derivation path;
- master fingerprint;
- account xpub;
- receive descriptor or equivalent account policy;
- change descriptor or equivalent account policy; and
- first receive address.

A wallet may not expose every field. Record `not exposed by this version` rather
than inferring or fabricating a match. Any exposed disagreement fails the drill.

## Recover the protected role

Create a separate restored wallet/session from the same mnemonic:

1. Enter the same 12 words.
2. Enter the generated BIP39 passphrase exactly, including word order, ASCII
   hyphens, case, and spacing as shown by Tripwire Seed.
3. Select the same test network and BIP84 account policy.
4. Compare the exposed public values against the `protected` account in the
   prior reference using the same exact-match rules.

The protected and decoy account xpubs must differ. If they are equal, stop and
preserve no public claim of success.

## Verify both roles with Tripwire Seed

After the external-wallet recovery, run:

```console
tripwire-seed verify \
  --watch-only drill.tripwire-watch-only.json \
  --expected-fingerprint <independently-retained-fingerprint>
```

Enter the mnemonic and passphrase only through the interactive no-echo prompts.
The command must report exact success for the complete strict reference, not
merely one address or fingerprint.

A successful external-wallet comparison without a successful strict verify is
not a completed Tripwire Seed recovery drill.

## Required negative drills

Use the same disposable material and require all of the following to fail safely:

### Wrong passphrase

Restore or inspect with a one-character or one-word passphrase change. The result
must be treated as a different valid wallet, never as the intended protected
role. Do not publish the wrong wallet's metadata.

### Wrong expected fingerprint

Run `tripwire-seed verify` with a syntactically valid but different 64-character
fingerprint. It must reject the reference before requesting mnemonic or
passphrase input.

### Modified public reference

Work on a copy of the JSON and change one public field, such as network, first
address, descriptor, account xpub, role, or collision metadata. The loader or
exact verification must reject the contradiction or mismatch.

Never alter the retained original reference.

### Wrong network

Attempt the restore under a different test network or modify the copied reference
network. A drill must not report success merely because testnet and signet can
share some serialization forms.

## Product-specific evidence sheet

Complete one sheet per product, version, platform, and role:

```text
Product:
Version / firmware:
Platform / hardware model:
Artifact verification:
Network:
Role: decoy / protected
Mnemonic import path used: manual words / SeedQR / other documented path
Separate BIP39 passphrase entry supported: yes/no
BIP84 account-zero policy selected: yes/no
Master fingerprint: exact match / not exposed / mismatch
Account xpub: exact match / not exposed / mismatch
Receive descriptor or policy: exact match / not exposed / mismatch
Change descriptor or policy: exact match / not exposed / mismatch
First receive address: exact match / not exposed / mismatch
Tripwire Seed strict verify: success/failure
Negative drills: all passed / failure
Unexpected warnings or application-specific defaults:
Unsupported behavior documented:
Reviewer checked evidence: yes/no
```

Do not paste actual fingerprints, xpubs, descriptors, addresses, mnemonic words,
passphrase words, SeedQR data, device identifiers, or wallet database paths into
the public sheet.

## Privacy-safe evidence

Public evidence may contain:

- frozen source commit;
- candidate and external-wallet artifact hashes;
- version and platform identifiers;
- commands with secret values replaced by placeholders;
- pass/fail outcomes;
- field names that matched or were not exposed;
- non-sensitive application defaults and caveats; and
- reviewer identity or pseudonym when voluntarily disclosed.

Public evidence must not contain:

- mnemonic, BIP39 passphrase, seed, xprv, private key, SeedQR, or plaintext
  secret export;
- complete account xpub, descriptor, fingerprint, address, or watch-only JSON;
- screenshots or recordings of secret entry or wallet public metadata;
- funded transaction data or wallet history;
- device serial number, onion credential, IP address, local username, hostname,
  or unrelated personal data.

## Completion criteria

Issue [#8](https://github.com/metaforismo/tripwire-seed/issues/8) may be closed
only when:

- Sparrow, COLDCARD, and Ashigaru each have at least one version-pinned completed
  sheet for the claimed platform or hardware configuration;
- both decoy and protected roles exact-match every public value exposed by each
  product;
- strict Tripwire Seed verification succeeds against the original reference;
- all negative drills fail safely;
- unsupported combinations and unexposed fields are stated explicitly;
- a reviewer checks the privacy-safe evidence; and
- no real or funded wallet material was used.

Passing this protocol does not authorize a stable release by itself. Independent
reproduction under issue #7 and independent security review under issue #9
remain separate gates.
