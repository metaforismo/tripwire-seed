//! Public BIP84 wallet metadata derivation for decoy and protected wallets.

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{
    Address, CompressedPublicKey, Network,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result, descriptor::with_checksum};

/// Stable schema identifier for watch-only exports.
pub const WATCH_ONLY_SCHEMA: &str = "tripwire-seed/watch-only/v1";
/// Exact account policy represented by version 1 watch-only exports.
pub const ACCOUNT_STANDARD: &str = "BIP39 + BIP32 + BIP84 native SegWit (account 0)";
/// Exact explanation attached to the local account-xpub equality check.
pub const COLLISION_SCOPE: &str =
    "Exact equality of the two locally derived BIP84 account xpubs; not a global collision search.";

/// Network presets supported by the CLI.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletNetwork {
    /// Bitcoin mainnet.
    Bitcoin,
    /// Bitcoin public testnet.
    Testnet,
    /// Bitcoin signet.
    Signet,
}

impl WalletNetwork {
    /// Convert to rust-bitcoin's network value.
    #[must_use]
    pub const fn bitcoin_network(self) -> Network {
        match self {
            Self::Bitcoin => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Signet => Network::Signet,
        }
    }

    /// Return the SLIP-44 coin type used in the BIP84 account path.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Bitcoin => 0,
            Self::Testnet | Self::Signet => 1,
        }
    }

    fn account_xpub_prefix(self) -> &'static str {
        match self {
            Self::Bitcoin => "xpub",
            Self::Testnet | Self::Signet => "tpub",
        }
    }
}

/// Public, watch-only metadata for one wallet role.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPublicInfo {
    /// `decoy` for the empty passphrase or `protected` for the supplied passphrase.
    pub role: String,
    /// Four-byte BIP32 master fingerprint.
    pub master_fingerprint: String,
    /// BIP84 account derivation path.
    pub account_derivation: String,
    /// Account-level extended public key.
    pub account_xpub: String,
    /// Checksummed BIP380 receive descriptor.
    pub receive_descriptor: String,
    /// Checksummed BIP380 change descriptor.
    pub change_descriptor: String,
    /// First native `SegWit` receiving address.
    pub first_receive_address: String,
}

/// Result of comparing the full account public keys, not only 32-bit fingerprints.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollisionCheck {
    /// True only when both roles derived the exact same BIP84 account xpub.
    pub same_account_xpub: bool,
    /// A precise explanation of the scope of the check.
    pub scope: String,
}

/// Public metadata for a base/decoy wallet and a passphrase-protected wallet.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireSummary {
    /// Stable export schema identifier.
    pub schema: String,
    /// Selected Bitcoin network.
    pub network: WalletNetwork,
    /// Script and derivation standard.
    pub account_standard: String,
    /// Wallet derived with the empty BIP39 passphrase.
    pub decoy: WalletPublicInfo,
    /// Wallet derived with the supplied BIP39 passphrase.
    pub protected: WalletPublicInfo,
    /// Local equality check for the two full account xpubs.
    pub collision_check: CollisionCheck,
}

/// Derive public BIP84 metadata for the decoy and protected roles.
///
/// # Errors
///
/// Returns an error when BIP32 master or child derivation fails or an internal
/// BIP84 derivation path cannot be parsed.
pub fn derive_tripwire_summary(
    mnemonic: &Mnemonic,
    passphrase: &str,
    network: WalletNetwork,
) -> Result<TripwireSummary> {
    let decoy = derive_wallet("decoy", mnemonic, "", network)?;
    let protected = derive_wallet("protected", mnemonic, passphrase, network)?;
    let same_account_xpub = decoy.account_xpub == protected.account_xpub;

    Ok(TripwireSummary {
        schema: WATCH_ONLY_SCHEMA.to_owned(),
        network,
        account_standard: ACCOUNT_STANDARD.to_owned(),
        decoy,
        protected,
        collision_check: CollisionCheck {
            same_account_xpub,
            scope: COLLISION_SCOPE.to_owned(),
        },
    })
}

/// Validate all public relationships represented by a version 1 watch-only export.
///
/// The check reconstructs the expected BIP84 descriptors and first receive
/// addresses from each account xpub, verifies the role and derivation policy,
/// and recomputes the collision metadata. It cannot prove that a master
/// fingerprint belongs to an account xpub because hardened derivation prevents
/// that relationship from being recovered from public data alone.
///
/// # Errors
///
/// Returns [`Error::UnsupportedWatchOnlyFormat`] for another schema or account
/// policy, and [`Error::InvalidWatchOnlyReference`] for internally inconsistent
/// public metadata.
pub fn validate_tripwire_summary(summary: &TripwireSummary) -> Result<()> {
    if summary.schema != WATCH_ONLY_SCHEMA || summary.account_standard != ACCOUNT_STANDARD {
        return Err(Error::UnsupportedWatchOnlyFormat);
    }

    validate_wallet_public_info(&summary.decoy, "decoy", summary.network)?;
    validate_wallet_public_info(&summary.protected, "protected", summary.network)?;

    let expected_collision = summary.decoy.account_xpub == summary.protected.account_xpub;
    if summary.collision_check.same_account_xpub != expected_collision
        || summary.collision_check.scope != COLLISION_SCOPE
    {
        return Err(Error::InvalidWatchOnlyReference);
    }

    Ok(())
}

fn derive_wallet(
    role: &str,
    mnemonic: &Mnemonic,
    passphrase: &str,
    network: WalletNetwork,
) -> Result<WalletPublicInfo> {
    let secp = Secp256k1::new();
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let master = Xpriv::new_master(network.bitcoin_network(), seed.as_ref())?;
    let fingerprint = master.fingerprint(&secp);
    let account_derivation = account_derivation(network);
    let account_path = DerivationPath::from_str(&account_derivation)
        .map_err(|error| Error::DerivationPath(error.to_string()))?;
    let account_private = master.derive_priv(&secp, &account_path)?;
    let account_public = Xpub::from_priv(&secp, &account_private);
    let first_receive_path = DerivationPath::from_str("m/0/0")
        .map_err(|error| Error::DerivationPath(error.to_string()))?;
    let first_receive = account_public.derive_pub(&secp, &first_receive_path)?;
    let compressed = CompressedPublicKey(first_receive.public_key);
    let address = Address::p2wpkh(&compressed, network.bitcoin_network());
    let origin = descriptor_origin(&account_derivation);
    let xpub = account_public.to_string();
    let receive_descriptor = with_checksum(&format!("wpkh([{fingerprint}/{origin}]{xpub}/0/*)"))?;
    let change_descriptor = with_checksum(&format!("wpkh([{fingerprint}/{origin}]{xpub}/1/*)"))?;

    Ok(WalletPublicInfo {
        role: role.to_owned(),
        master_fingerprint: fingerprint.to_string(),
        account_derivation,
        account_xpub: xpub,
        receive_descriptor,
        change_descriptor,
        first_receive_address: address.to_string(),
    })
}

fn validate_wallet_public_info(
    wallet: &WalletPublicInfo,
    expected_role: &str,
    network: WalletNetwork,
) -> Result<()> {
    let expected_derivation = account_derivation(network);
    if wallet.role != expected_role
        || wallet.account_derivation != expected_derivation
        || !is_canonical_fingerprint(&wallet.master_fingerprint)
        || !wallet
            .account_xpub
            .starts_with(network.account_xpub_prefix())
    {
        return Err(Error::InvalidWatchOnlyReference);
    }

    let account_public =
        Xpub::from_str(&wallet.account_xpub).map_err(|_| Error::InvalidWatchOnlyReference)?;
    if account_public.depth != 3
        || !matches!(
            account_public.child_number,
            ChildNumber::Hardened { index: 0 }
        )
    {
        return Err(Error::InvalidWatchOnlyReference);
    }

    let secp = Secp256k1::verification_only();
    let first_receive_path =
        DerivationPath::from_str("m/0/0").map_err(|_| Error::InvalidWatchOnlyReference)?;
    let first_receive = account_public
        .derive_pub(&secp, &first_receive_path)
        .map_err(|_| Error::InvalidWatchOnlyReference)?;
    let compressed = CompressedPublicKey(first_receive.public_key);
    let expected_address = Address::p2wpkh(&compressed, network.bitcoin_network()).to_string();
    let origin = descriptor_origin(&expected_derivation);
    let expected_receive = with_checksum(&format!(
        "wpkh([{}/{origin}]{}/0/*)",
        wallet.master_fingerprint, wallet.account_xpub
    ))
    .map_err(|_| Error::InvalidWatchOnlyReference)?;
    let expected_change = with_checksum(&format!(
        "wpkh([{}/{origin}]{}/1/*)",
        wallet.master_fingerprint, wallet.account_xpub
    ))
    .map_err(|_| Error::InvalidWatchOnlyReference)?;

    if wallet.first_receive_address != expected_address
        || wallet.receive_descriptor != expected_receive
        || wallet.change_descriptor != expected_change
    {
        return Err(Error::InvalidWatchOnlyReference);
    }

    Ok(())
}

fn account_derivation(network: WalletNetwork) -> String {
    format!("m/84'/{}'/0'", network.coin_type())
}

fn descriptor_origin(account_derivation: &str) -> String {
    account_derivation
        .trim_start_matches("m/")
        .replace('\'', "h")
}

fn is_canonical_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 8
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use bip39::Language;
    use bitcoin::hex::DisplayHex;

    use super::*;

    const BIP84_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn summary() -> TripwireSummary {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, BIP84_MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        derive_tripwire_summary(&mnemonic, "test-passphrase", WalletNetwork::Bitcoin)
            .unwrap_or_else(|error| unreachable!("valid derivation: {error}"))
    }

    fn replace_decoy_xpub(summary: &mut TripwireSummary, account_public: Xpub) {
        let account_xpub = account_public.to_string();
        let origin = descriptor_origin(&summary.decoy.account_derivation);
        summary.decoy.account_xpub = account_xpub.clone();
        summary.decoy.receive_descriptor = with_checksum(&format!(
            "wpkh([{}/{origin}]{account_xpub}/0/*)",
            summary.decoy.master_fingerprint
        ))
        .unwrap_or_else(|error| unreachable!("test descriptor is valid: {error}"));
        summary.decoy.change_descriptor = with_checksum(&format!(
            "wpkh([{}/{origin}]{account_xpub}/1/*)",
            summary.decoy.master_fingerprint
        ))
        .unwrap_or_else(|error| unreachable!("test descriptor is valid: {error}"));
        summary.collision_check.same_account_xpub =
            summary.decoy.account_xpub == summary.protected.account_xpub;
    }

    #[test]
    fn matches_bip84_first_address_vector() {
        let summary = summary();
        assert_eq!(
            summary.decoy.first_receive_address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert!(!summary.collision_check.same_account_xpub);
        assert_eq!(
            summary.decoy.receive_descriptor,
            "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s"
        );
        assert_eq!(
            summary.decoy.change_descriptor,
            "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#vatdkr6g"
        );
    }

    #[test]
    fn matches_bip39_seed_vector() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, BIP84_MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let seed = mnemonic.to_seed("TREZOR");
        assert_eq!(
            seed.as_hex().to_string(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn empty_passphrase_is_detected_as_same_wallet() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, BIP84_MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let summary = derive_tripwire_summary(&mnemonic, "", WalletNetwork::Bitcoin)
            .unwrap_or_else(|error| unreachable!("valid derivation: {error}"));
        assert!(summary.collision_check.same_account_xpub);
    }

    #[test]
    fn generated_summary_is_semantically_valid() {
        validate_tripwire_summary(&summary())
            .unwrap_or_else(|error| unreachable!("generated summary validates: {error}"));
    }

    #[test]
    fn semantic_validation_rejects_inconsistent_public_fields() {
        let original = summary();

        let mut wrong_role = original.clone();
        wrong_role.decoy.role = "protected".to_owned();
        assert!(matches!(
            validate_tripwire_summary(&wrong_role),
            Err(Error::InvalidWatchOnlyReference)
        ));

        let mut wrong_descriptor = original.clone();
        wrong_descriptor.protected.receive_descriptor.push('x');
        assert!(matches!(
            validate_tripwire_summary(&wrong_descriptor),
            Err(Error::InvalidWatchOnlyReference)
        ));

        let mut wrong_address = original.clone();
        wrong_address.decoy.first_receive_address.push('x');
        assert!(matches!(
            validate_tripwire_summary(&wrong_address),
            Err(Error::InvalidWatchOnlyReference)
        ));

        let mut wrong_collision = original;
        wrong_collision.collision_check.same_account_xpub =
            !wrong_collision.collision_check.same_account_xpub;
        assert!(matches!(
            validate_tripwire_summary(&wrong_collision),
            Err(Error::InvalidWatchOnlyReference)
        ));
    }

    #[test]
    fn semantic_validation_rejects_non_account_extended_keys() {
        let original = summary();
        let account_public = Xpub::from_str(&original.decoy.account_xpub)
            .unwrap_or_else(|error| unreachable!("generated account xpub parses: {error}"));

        let mut wrong_depth = original.clone();
        replace_decoy_xpub(
            &mut wrong_depth,
            Xpub {
                depth: 2,
                ..account_public
            },
        );
        assert!(matches!(
            validate_tripwire_summary(&wrong_depth),
            Err(Error::InvalidWatchOnlyReference)
        ));

        let mut wrong_child = original;
        replace_decoy_xpub(
            &mut wrong_child,
            Xpub {
                child_number: ChildNumber::Hardened { index: 1 },
                ..account_public
            },
        );
        assert!(matches!(
            validate_tripwire_summary(&wrong_child),
            Err(Error::InvalidWatchOnlyReference)
        ));
    }
}
