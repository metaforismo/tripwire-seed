# Reproduction evidence privacy

Independent-build evidence should contain public software and environment facts,
not wallet or personal data.

Allowed examples:

- repository, commit, target, workflow, artifact, and attestation identifiers;
- operating-system and toolchain versions;
- exact public commands;
- archive and executable hashes;
- pass/fail results and mismatch explanations; and
- voluntarily disclosed operator and reviewer identities or pseudonyms.

Do not publish mnemonic words, BIP39 passphrases, seeds, xprvs, complete account
xpubs, descriptors, addresses, fingerprints, wallet files, transaction history,
local usernames, hostnames, home-directory paths, serial numbers, IP addresses,
or unrelated environment variables.
