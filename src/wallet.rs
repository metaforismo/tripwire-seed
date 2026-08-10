//! Public BIP84 wallet metadata derivation for decoy and protected wallets.

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::{
    Address, CompressedPublicKey, Network,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Network presets supported by the CLI.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
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
}

/// Public, watch-only metadata for one wallet role.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct WalletPublicInfo {
    /// `decoy` for the empty passphrase or `protected` for the supplied passphrase.
    pub role: String,
    /// Four-byte BIP32 master fingerprint.
    pub master_fingerprint: String,
    /// BIP84 account derivation path.
    pub account_derivation: String,
    /// Account-level extended public key.
    pub account_xpub: String,
    /// Receive descriptor body. A checksum is intentionally not claimed.
    pub receive_descriptor: String,
    /// Change descriptor body. A checksum is intentionally not claimed.
    pub change_descriptor: String,
    /// First native `SegWit` receiving address.
    pub first_receive_address: String,
}

/// Result of comparing the full account public keys, not only 32-bit fingerprints.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CollisionCheck {
    /// True only when both roles derived the exact same BIP84 account xpub.
    pub same_account_xpub: bool,
    /// A precise explanation of the scope of the check.
    pub scope: String,
}

/// Public metadata for a base/decoy wallet and a passphrase-protected wallet.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
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
        schema: "tripwire-seed/watch-only/v1".to_owned(),
        network,
        account_standard: "BIP39 + BIP32 + BIP84 native SegWit (account 0)".to_owned(),
        decoy,
        protected,
        collision_check: CollisionCheck {
            same_account_xpub,
            scope: "Exact equality of the two locally derived BIP84 account xpubs; not a global collision search."
                .to_owned(),
        },
    })
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
    let account_derivation = format!("m/84'/{}'/0'", network.coin_type());
    let account_path = DerivationPath::from_str(&account_derivation)
        .map_err(|error| Error::DerivationPath(error.to_string()))?;
    let account_private = master.derive_priv(&secp, &account_path)?;
    let account_public = Xpub::from_priv(&secp, &account_private);
    let first_receive_path = DerivationPath::from_str("m/0/0")
        .map_err(|error| Error::DerivationPath(error.to_string()))?;
    let first_receive = account_public.derive_pub(&secp, &first_receive_path)?;
    let compressed = CompressedPublicKey(first_receive.public_key);
    let address = Address::p2wpkh(&compressed, network.bitcoin_network());
    let origin = account_derivation
        .trim_start_matches("m/")
        .replace('\'', "h");
    let xpub = account_public.to_string();

    Ok(WalletPublicInfo {
        role: role.to_owned(),
        master_fingerprint: fingerprint.to_string(),
        account_derivation,
        account_xpub: xpub.clone(),
        receive_descriptor: format!("wpkh([{fingerprint}/{origin}]{xpub}/0/*)"),
        change_descriptor: format!("wpkh([{fingerprint}/{origin}]{xpub}/1/*)"),
        first_receive_address: address.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use bip39::Language;
    use bitcoin::hex::DisplayHex;

    use super::*;

    const BIP84_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn matches_bip84_first_address_vector() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, BIP84_MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let summary = derive_tripwire_summary(&mnemonic, "test-passphrase", WalletNetwork::Bitcoin)
            .unwrap_or_else(|error| unreachable!("valid derivation: {error}"));
        assert_eq!(
            summary.decoy.first_receive_address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert!(!summary.collision_check.same_account_xpub);
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
}
