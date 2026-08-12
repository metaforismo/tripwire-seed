//! BIP380 output descriptor checksum support.

use crate::{Error, Result};

const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

/// Compute the eight-character BIP380 checksum for a descriptor body.
///
/// The input must not include the `#checksum` suffix.
///
/// # Errors
///
/// Returns [`Error::DescriptorAlreadyContainsChecksum`] when the body already
/// contains `#`, or [`Error::InvalidDescriptorCharacter`] when it contains a
/// character outside BIP380's checksum input character set.
pub fn descriptor_checksum(descriptor: &str) -> Result<String> {
    if descriptor.contains('#') {
        return Err(Error::DescriptorAlreadyContainsChecksum);
    }
    descriptor_checksum_unchecked(descriptor)
}

fn descriptor_checksum_unchecked(descriptor: &str) -> Result<String> {
    let mut checksum = 1_u64;
    let mut group = 0_u64;
    let mut group_count = 0_u8;

    for (position, character) in descriptor.char_indices() {
        let Some(value) = INPUT_CHARSET.find(character) else {
            return Err(Error::InvalidDescriptorCharacter {
                position,
                character,
            });
        };
        checksum = polymod_step(checksum, (value & 31) as u64);
        group = group * 3 + (value >> 5) as u64;
        group_count += 1;

        if group_count == 3 {
            checksum = polymod_step(checksum, group);
            group = 0;
            group_count = 0;
        }
    }

    if group_count > 0 {
        checksum = polymod_step(checksum, group);
    }
    for _ in 0..8 {
        checksum = polymod_step(checksum, 0);
    }
    checksum ^= 1;

    let mut output = String::with_capacity(8);
    for index in 0..8 {
        let shift = 5 * (7 - index);
        let value = ((checksum >> shift) & 31) as usize;
        output.push(char::from(CHECKSUM_CHARSET[value]));
    }
    Ok(output)
}

/// Append a standard BIP380 checksum to a descriptor body.
///
/// # Errors
///
/// Returns [`Error::DescriptorAlreadyContainsChecksum`] when the body already
/// contains `#`, or [`Error::InvalidDescriptorCharacter`] when it contains a
/// character outside BIP380's checksum input character set.
pub fn with_checksum(descriptor: &str) -> Result<String> {
    let checksum = descriptor_checksum(descriptor)?;
    let mut output = String::with_capacity(descriptor.len() + 9);
    output.push_str(descriptor);
    output.push('#');
    output.push_str(&checksum);
    Ok(output)
}

fn polymod_step(checksum: u64, value: u64) -> u64 {
    let top = checksum >> 35;
    let mut next = ((checksum & 0x7_ffff_ffff) << 5) ^ value;
    for (index, generator) in GENERATOR.iter().enumerate() {
        if ((top >> index) & 1) != 0 {
            next ^= generator;
        }
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_official_bip380_vector() {
        assert_eq!(
            with_checksum("raw(deadbeef)")
                .unwrap_or_else(|error| unreachable!("official vector is valid: {error}")),
            "raw(deadbeef)#89f8spxm"
        );
    }

    #[test]
    fn rejects_characters_outside_bip380_charset() {
        assert!(matches!(
            descriptor_checksum("raw(Ü)"),
            Err(Error::InvalidDescriptorCharacter {
                position: 4,
                character: 'Ü'
            })
        ));
    }

    #[test]
    fn refuses_to_append_a_second_checksum() {
        assert!(matches!(
            with_checksum("raw(deadbeef)#89f8spxm"),
            Err(Error::DescriptorAlreadyContainsChecksum)
        ));
        assert!(matches!(
            descriptor_checksum("raw(deadbeef)#89f8spxm"),
            Err(Error::DescriptorAlreadyContainsChecksum)
        ));
    }

    #[test]
    fn empty_body_has_a_deterministic_checksum() {
        assert_eq!(
            descriptor_checksum("")
                .unwrap_or_else(|error| unreachable!("empty body is encodable: {error}")),
            "7h0w2xvg"
        );
    }

    #[test]
    fn covers_the_complete_bip380_input_charset() {
        assert_eq!(
            descriptor_checksum_unchecked(INPUT_CHARSET)
                .unwrap_or_else(|error| unreachable!("BIP380 charset is encodable: {error}")),
            "fzuaxexw"
        );
    }
}
