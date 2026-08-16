//! CLI entrypoint for `tripwire-seed`.

use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand, ValueEnum};
use tripwire_seed::{
    DEFAULT_PASSPHRASE_WORDS, Error, Result,
    audit::{audit_passphrase, audit_passphrase_with_entropy},
    export::{
        read_watch_only, render_seedqr, verify_watch_only, write_plaintext_secret_bundle,
        write_watch_only,
    },
    fingerprint::{verify_watch_only_fingerprint, watch_only_fingerprint},
    passphrase::{DiceAccumulator, GeneratedPassphrase, generate_system},
    wallet::{TripwireSummary, WalletNetwork, derive_tripwire_summary},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a new base mnemonic and a high-entropy BIP39 passphrase.
    Create(CreateArgs),
    /// Inspect an existing mnemonic/passphrase pair without revealing it.
    Inspect(InspectArgs),
    /// Print the canonical fingerprint of a watch-only reference.
    Fingerprint(FingerprintArgs),
    /// Verify a recovery drill against a prior watch-only export.
    Verify(VerifyArgs),
    /// Audit a passphrase conservatively without deriving a wallet.
    AuditPassphrase,
}

#[derive(Debug, clap::Args)]
struct CreateArgs {
    /// Source used to select random passphrase words.
    #[arg(long, value_enum, default_value_t = PassphraseSource::System)]
    passphrase_source: PassphraseSource,

    /// Number of independently selected passphrase words (12 = 132 bits).
    #[arg(long, default_value_t = DEFAULT_PASSPHRASE_WORDS)]
    passphrase_words: usize,

    /// Bitcoin network used for BIP84 public metadata.
    #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
    network: NetworkArg,

    /// Write a new watch-only JSON file. Existing files are never overwritten.
    #[arg(long)]
    watch_only_out: Option<PathBuf>,

    /// Display the mnemonic as a `SeedQR` after a separate confirmation.
    #[arg(long)]
    show_seedqr: bool,

    /// DANGEROUS: write mnemonic and passphrase as owner-only plaintext JSON.
    #[arg(long, value_name = "NEW_PATH")]
    dangerous_secret_out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct InspectArgs {
    /// Bitcoin network used for BIP84 public metadata.
    #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
    network: NetworkArg,

    /// Write a new watch-only JSON file. Existing files are never overwritten.
    #[arg(long)]
    watch_only_out: Option<PathBuf>,

    /// Display the mnemonic as a `SeedQR` after a separate confirmation.
    #[arg(long)]
    show_seedqr: bool,

    /// DANGEROUS: write mnemonic and passphrase as owner-only plaintext JSON.
    #[arg(long, value_name = "NEW_PATH")]
    dangerous_secret_out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct FingerprintArgs {
    /// Version 1 watch-only export whose public fields will be fingerprinted.
    #[arg(long, value_name = "PATH")]
    watch_only: PathBuf,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Version 1 watch-only export produced before the recovery drill.
    #[arg(long, value_name = "PATH")]
    watch_only: PathBuf,

    /// Independently retained SHA-256 fingerprint of the watch-only reference.
    #[arg(long, value_name = "SHA256")]
    expected_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum PassphraseSource {
    System,
    Dice,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum NetworkArg {
    Bitcoin,
    Testnet,
    Signet,
}

impl From<NetworkArg> for WalletNetwork {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Bitcoin => Self::Bitcoin,
            NetworkArg::Testnet => Self::Testnet,
            NetworkArg::Signet => Self::Signet,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Create(arguments) => create(arguments),
        Commands::Inspect(arguments) => inspect(arguments),
        Commands::Fingerprint(arguments) => fingerprint(&arguments),
        Commands::Verify(arguments) => verify(&arguments),
        Commands::AuditPassphrase => audit_interactive(),
    }
}

fn create(arguments: CreateArgs) -> Result<()> {
    require_interactive_terminal()?;
    println!(
        "Use this command on a trusted offline computer. Terminal history, cameras, swap, and malware remain outside this tool's control."
    );
    confirm_exact("Type CREATE to continue: ", "CREATE")?;

    let mut entropy = Zeroizing::new([0_u8; 16]);
    getrandom::fill(entropy.as_mut())?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())?;
    let generated = match arguments.passphrase_source {
        PassphraseSource::System => generate_system(arguments.passphrase_words)?,
        PassphraseSource::Dice => collect_dice_passphrase(arguments.passphrase_words)?,
    };
    let summary = derive_tripwire_summary(
        &mnemonic,
        generated.expose(),
        WalletNetwork::from(arguments.network),
    )?;

    println!(
        "\nGenerated passphrase: {} words, {} bits of construction entropy, source {:?}.",
        generated.word_count(),
        generated.entropy_bits(),
        generated.source()
    );
    if generated.rejected_dice_groups() > 0 {
        println!(
            "Rejected dice groups (expected and security-preserving): {}",
            generated.rejected_dice_groups()
        );
    }
    confirm_exact("Type REVEAL to display both secrets: ", "REVEAL")?;
    println!("\n=== SECRET: BASE BIP39 MNEMONIC ===");
    println!("{mnemonic}");
    println!("=== SECRET: BIP39 PASSPHRASE ===");
    println!("{}", generated.expose());
    println!("=== END SECRETS ===\n");
    verify_backup(&mnemonic, generated.expose())?;

    let audit = audit_passphrase_with_entropy(generated.expose(), Some(generated.entropy_bits()));
    print_audit(&audit);
    print_summary(&summary);
    process_exports(
        &mnemonic,
        generated.expose(),
        &summary,
        arguments.watch_only_out,
        arguments.show_seedqr,
        arguments.dangerous_secret_out,
    )
}

fn inspect(arguments: InspectArgs) -> Result<()> {
    require_interactive_terminal()?;
    let mut mnemonic_text = Zeroizing::new(rpassword::prompt_password(
        "BIP39 mnemonic (input hidden): ",
    )?);
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_text.trim())?;
    mnemonic_text.zeroize();
    let passphrase = Zeroizing::new(rpassword::prompt_password(
        "BIP39 passphrase (input hidden; empty means base wallet): ",
    )?);
    let audit = audit_passphrase(passphrase.as_str());
    let summary = derive_tripwire_summary(
        &mnemonic,
        passphrase.as_str(),
        WalletNetwork::from(arguments.network),
    )?;

    print_audit(&audit);
    print_summary(&summary);
    process_exports(
        &mnemonic,
        passphrase.as_str(),
        &summary,
        arguments.watch_only_out,
        arguments.show_seedqr,
        arguments.dangerous_secret_out,
    )
}

fn fingerprint(arguments: &FingerprintArgs) -> Result<()> {
    let summary = read_watch_only(&arguments.watch_only)?;
    println!("{}", watch_only_fingerprint(&summary)?);
    Ok(())
}

fn verify(arguments: &VerifyArgs) -> Result<()> {
    require_interactive_terminal()?;
    let expected = read_watch_only(&arguments.watch_only)?;
    let reference_fingerprint = watch_only_fingerprint(&expected)?;
    if let Some(supplied) = &arguments.expected_fingerprint {
        verify_watch_only_fingerprint(supplied, &expected)?;
        println!("Watch-only reference fingerprint: OK");
    } else {
        println!("Watch-only reference fingerprint: {reference_fingerprint}");
        println!(
            "No independent fingerprint was supplied; reference authenticity was not established."
        );
    }

    let mut mnemonic_text = Zeroizing::new(rpassword::prompt_password(
        "BIP39 mnemonic (input hidden): ",
    )?);
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_text.trim())?;
    mnemonic_text.zeroize();
    let passphrase = Zeroizing::new(rpassword::prompt_password(
        "BIP39 passphrase (input hidden): ",
    )?);
    let actual = derive_tripwire_summary(&mnemonic, passphrase.as_str(), expected.network)?;

    verify_watch_only(&expected, &actual)?;
    println!("Watch-only recovery verification: OK");
    print_summary(&actual);
    Ok(())
}

fn audit_interactive() -> Result<()> {
    require_interactive_terminal()?;
    let passphrase = Zeroizing::new(rpassword::prompt_password(
        "Passphrase to audit (input hidden): ",
    )?);
    print_audit(&audit_passphrase(passphrase.as_str()));
    Ok(())
}

fn verify_backup(mnemonic: &Mnemonic, passphrase: &str) -> Result<()> {
    println!("Verify the backup before any export.");
    let mut mnemonic_copy = Zeroizing::new(rpassword::prompt_password(
        "Re-enter the 12-word mnemonic (input hidden): ",
    )?);
    let parsed_copy = Mnemonic::parse_in_normalized(Language::English, mnemonic_copy.trim());
    mnemonic_copy.zeroize();
    let passphrase_copy = Zeroizing::new(rpassword::prompt_password(
        "Re-enter the BIP39 passphrase (input hidden): ",
    )?);

    if parsed_copy.as_ref().ok() != Some(mnemonic) || passphrase_copy.as_str() != passphrase {
        return Err(Error::BackupVerificationFailed);
    }
    println!("Backup verification: OK");
    Ok(())
}

fn collect_dice_passphrase(word_count: usize) -> Result<GeneratedPassphrase> {
    let mut collector = DiceAccumulator::new(word_count)?;
    println!(
        "Roll a fair six-sided die in five-roll groups. Values 1-6 only. Some groups are rejected to remove bias."
    );
    while collector.accepted_words() < collector.required_words() {
        let remaining = collector.required_words() - collector.accepted_words();
        let prompt = format!("Enter more rolls ({remaining} words still needed; input hidden): ");
        let mut rolls = Zeroizing::new(rpassword::prompt_password(prompt)?);
        collector.push_rolls(rolls.as_str())?;
        rolls.zeroize();
        println!(
            "Accepted words: {}/{}; rejected groups: {}",
            collector.accepted_words(),
            collector.required_words(),
            collector.rejected_groups()
        );
    }
    collector.finish()
}

fn process_exports(
    mnemonic: &Mnemonic,
    passphrase: &str,
    summary: &TripwireSummary,
    watch_only_out: Option<PathBuf>,
    show_seedqr: bool,
    dangerous_secret_out: Option<PathBuf>,
) -> Result<()> {
    if let Some(path) = watch_only_out {
        write_watch_only(&path, summary)?;
        println!("Watch-only metadata written to {}", path.display());
        println!("Watch-only fingerprint: {}", watch_only_fingerprint(summary)?);
        println!(
            "Store the fingerprint separately from the JSON if you want to detect later substitution."
        );
    }

    if show_seedqr {
        println!(
            "WARNING: SeedQR is the mnemonic in machine-readable form. Cameras and terminal scrollback can capture it."
        );
        confirm_exact("Type SHOW SEEDQR to continue: ", "SHOW SEEDQR")?;
        let rendered = render_seedqr(mnemonic)?;
        println!("{}", rendered.as_str());
    }

    if let Some(path) = dangerous_secret_out {
        println!(
            "DANGER: this writes both secrets in plaintext. SSDs and copy-on-write filesystems may retain deleted data."
        );
        confirm_exact("Type WRITE PLAINTEXT to continue: ", "WRITE PLAINTEXT")?;
        write_plaintext_secret_bundle(&path, mnemonic, passphrase)?;
        println!("Plaintext secret bundle written to {}", path.display());
    }
    Ok(())
}

fn print_summary(summary: &TripwireSummary) {
    println!("\n=== PUBLIC VERIFICATION DATA ===");
    for wallet in [&summary.decoy, &summary.protected] {
        println!("Role: {}", wallet.role);
        println!("  master fingerprint: {}", wallet.master_fingerprint);
        println!("  derivation: {}", wallet.account_derivation);
        println!("  account xpub: {}", wallet.account_xpub);
        println!("  receive descriptor: {}", wallet.receive_descriptor);
        println!("  change descriptor: {}", wallet.change_descriptor);
        println!("  first receive address: {}", wallet.first_receive_address);
    }
    println!(
        "Exact local account-xpub equality: {}",
        summary.collision_check.same_account_xpub
    );
    println!("Scope: {}", summary.collision_check.scope);
}

fn print_audit(audit: &tripwire_seed::audit::PassphraseAudit) {
    println!("\n=== PASSPHRASE ASSESSMENT ===");
    if let Some(bits) = audit.verified_construction_entropy_bits {
        println!("Verified construction entropy: {bits} bits");
    } else {
        println!("Verified construction entropy: unknown (human input)");
    }
    println!(
        "BIP39 NFKD normalization changes input: {}",
        audit.normalization_changes_input
    );
    if audit.warnings.is_empty() {
        println!("No obvious warning found; this is not proof of global uniqueness or strength.");
    } else {
        for warning in &audit.warnings {
            println!("WARNING: {warning}");
        }
    }
}

fn require_interactive_terminal() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::InteractiveTerminalRequired);
    }
    Ok(())
}

fn confirm_exact(prompt: &str, expected: &str) -> Result<()> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut confirmation = Zeroizing::new(String::new());
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != expected {
        return Err(Error::ConfirmationFailed);
    }
    Ok(())
}
