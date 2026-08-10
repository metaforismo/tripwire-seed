//! Uniform random-word passphrase generation from the English BIP39 list.

use bip39::Language;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Number of entries in the BIP39 English wordlist.
pub const WORDLIST_SIZE: usize = 2_048;
const WORDLIST_SIZE_U16: u16 = 2_048;
/// Exact construction entropy contributed by one uniform word selection.
pub const BITS_PER_WORD: usize = 11;
/// Smallest supported generated passphrase.
pub const MIN_WORDS: usize = 6;
/// Largest supported generated passphrase.
pub const MAX_WORDS: usize = 24;
const DICE_GROUP_SIZE: usize = 5;
const ACCEPTED_DICE_VALUES: u16 = 6_144;

/// Provenance for a generated passphrase.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GenerationSource {
    /// Bytes obtained from the operating system CSPRNG.
    System,
    /// Physical d6 rolls mapped with rejection sampling.
    Dice,
}

/// A generated passphrase whose owned string is zeroized on drop.
pub struct GeneratedPassphrase {
    value: Zeroizing<String>,
    source: GenerationSource,
    word_count: usize,
    rejected_dice_groups: usize,
}

impl std::fmt::Debug for GeneratedPassphrase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeneratedPassphrase")
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .field("word_count", &self.word_count)
            .field("entropy_bits", &self.entropy_bits())
            .field("rejected_dice_groups", &self.rejected_dice_groups)
            .finish()
    }
}

impl GeneratedPassphrase {
    /// Borrow the passphrase for immediate use.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.as_str()
    }

    /// Return how the passphrase was sampled.
    #[must_use]
    pub const fn source(&self) -> GenerationSource {
        self.source
    }

    /// Return the number of uniformly selected words.
    #[must_use]
    pub const fn word_count(&self) -> usize {
        self.word_count
    }

    /// Return the exact construction entropy in bits.
    #[must_use]
    pub const fn entropy_bits(&self) -> usize {
        self.word_count * BITS_PER_WORD
    }

    /// Return the number of rejected five-roll groups for dice generation.
    #[must_use]
    pub const fn rejected_dice_groups(&self) -> usize {
        self.rejected_dice_groups
    }
}

/// Stateful collector for unbiased d6-based passphrase generation.
///
/// Five rolls encode a value in `0..7776`. Values in `6144..7776` are rejected;
/// accepted values map evenly onto the 2,048-word list. This avoids modulo bias.
pub struct DiceAccumulator {
    required_words: usize,
    pending_rolls: Zeroizing<Vec<u8>>,
    word_indices: Zeroizing<Vec<u16>>,
    rejected_groups: usize,
}

impl std::fmt::Debug for DiceAccumulator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiceAccumulator")
            .field("required_words", &self.required_words)
            .field("pending_rolls", &"[REDACTED]")
            .field("accepted_words", &self.word_indices.len())
            .field("rejected_groups", &self.rejected_groups)
            .finish()
    }
}

impl DiceAccumulator {
    /// Create a dice collector for `required_words` passphrase words.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PassphraseWordCount`] when the requested count is
    /// outside the supported range.
    pub fn new(required_words: usize) -> Result<Self> {
        validate_word_count(required_words)?;
        Ok(Self {
            required_words,
            pending_rolls: Zeroizing::new(Vec::new()),
            word_indices: Zeroizing::new(Vec::with_capacity(required_words)),
            rejected_groups: 0,
        })
    }

    /// Add d6 rolls. ASCII whitespace is ignored; every other character must be 1-6.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDice`] if the input contains a non-whitespace
    /// character outside `1..=6`.
    pub fn push_rolls(&mut self, input: &str) -> Result<()> {
        for byte in input.bytes() {
            if byte.is_ascii_whitespace() {
                continue;
            }
            if !(b'1'..=b'6').contains(&byte) {
                return Err(Error::InvalidDice);
            }
            if self.word_indices.len() < self.required_words {
                self.pending_rolls.push(byte - b'1');
            }
        }

        while self.pending_rolls.len() >= DICE_GROUP_SIZE
            && self.word_indices.len() < self.required_words
        {
            let value =
                self.pending_rolls
                    .drain(..DICE_GROUP_SIZE)
                    .fold(0_u16, |accumulator, digit| {
                        accumulator
                            .saturating_mul(6)
                            .saturating_add(u16::from(digit))
                    });
            if value < ACCEPTED_DICE_VALUES {
                self.word_indices.push(value % WORDLIST_SIZE_U16);
            } else {
                self.rejected_groups = self.rejected_groups.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Return the number of words selected so far.
    #[must_use]
    pub fn accepted_words(&self) -> usize {
        self.word_indices.len()
    }

    /// Return the required word count.
    #[must_use]
    pub const fn required_words(&self) -> usize {
        self.required_words
    }

    /// Return the number of rejected five-roll groups.
    #[must_use]
    pub const fn rejected_groups(&self) -> usize {
        self.rejected_groups
    }

    /// Finish generation after enough unbiased selections have been collected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InsufficientDice`] until the requested number of
    /// accepted five-roll groups has been collected.
    pub fn finish(self) -> Result<GeneratedPassphrase> {
        if self.word_indices.len() != self.required_words {
            return Err(Error::InsufficientDice {
                accepted: self.word_indices.len(),
                required: self.required_words,
            });
        }
        let joined = join_word_indices(self.word_indices.as_slice());
        Ok(GeneratedPassphrase {
            value: joined,
            source: GenerationSource::Dice,
            word_count: self.required_words,
            rejected_dice_groups: self.rejected_groups,
        })
    }
}

/// Generate a uniform random-word passphrase using the operating system CSPRNG.
///
/// # Errors
///
/// Returns an error when `word_count` is outside the supported range or the
/// operating system random source fails.
pub fn generate_system(word_count: usize) -> Result<GeneratedPassphrase> {
    validate_word_count(word_count)?;
    let mut selected = Zeroizing::new(Vec::with_capacity(word_count));

    for _ in 0..word_count {
        let mut random = Zeroizing::new([0_u8; 2]);
        getrandom::fill(random.as_mut())?;
        // 2^16 is exactly divisible by 2^11, so this reduction is unbiased.
        let index = u16::from_be_bytes(*random) & 0x07ff;
        selected.push(index);
    }

    let joined = join_word_indices(selected.as_slice());

    Ok(GeneratedPassphrase {
        value: joined,
        source: GenerationSource::System,
        word_count,
        rejected_dice_groups: 0,
    })
}

fn join_word_indices(indices: &[u16]) -> Zeroizing<String> {
    let words = Language::English.word_list();
    let mut joined = Zeroizing::new(String::new());
    for (position, index) in indices.iter().enumerate() {
        if position > 0 {
            joined.push('-');
        }
        joined.push_str(words[usize::from(*index)]);
    }
    joined
}

fn validate_word_count(word_count: usize) -> Result<()> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&word_count) {
        return Err(Error::PassphraseWordCount {
            min: MIN_WORDS,
            max: MAX_WORDS,
            actual: word_count,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_ones_select_first_word() {
        let mut accumulator = DiceAccumulator::new(6)
            .unwrap_or_else(|error| unreachable!("valid word count: {error}"));
        accumulator
            .push_rolls("11111 11111 11111 11111 11111 11111")
            .unwrap_or_else(|error| unreachable!("valid dice: {error}"));
        let generated = accumulator
            .finish()
            .unwrap_or_else(|error| unreachable!("enough rolls: {error}"));
        assert_eq!(
            generated.expose(),
            "abandon-abandon-abandon-abandon-abandon-abandon"
        );
        assert_eq!(generated.entropy_bits(), 66);
    }

    #[test]
    fn upper_tail_is_rejected() {
        let mut accumulator = DiceAccumulator::new(6)
            .unwrap_or_else(|error| unreachable!("valid word count: {error}"));
        accumulator
            .push_rolls("66666 11111 11111 11111 11111 11111 11111")
            .unwrap_or_else(|error| unreachable!("valid dice: {error}"));
        assert_eq!(accumulator.rejected_groups(), 1);
        assert_eq!(accumulator.accepted_words(), 6);
    }

    #[test]
    fn invalid_dice_is_rejected() {
        let mut accumulator = DiceAccumulator::new(6)
            .unwrap_or_else(|error| unreachable!("valid word count: {error}"));
        assert!(matches!(
            accumulator.push_rolls("12340"),
            Err(Error::InvalidDice)
        ));
    }

    #[test]
    fn debug_redacts_secrets() {
        let generated = generate_system(12)
            .unwrap_or_else(|error| unreachable!("OS randomness available: {error}"));
        let debug = format!("{generated:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(generated.expose()));
    }
}
