use tripwire_seed::{
    Error,
    descriptor::{descriptor_checksum, with_checksum},
    fingerprint::{verify_watch_only_fingerprint, watch_only_fingerprint},
    wallet::{TripwireSummary, validate_tripwire_summary},
};

#[test]
fn public_fuzz_corpus_contains_a_valid_watch_only_reference() {
    let encoded = include_bytes!("../fuzz/corpus/public_surfaces/valid_watch_only.json");
    let summary: TripwireSummary = serde_json::from_slice(encoded)
        .unwrap_or_else(|error| unreachable!("public corpus JSON must decode: {error}"));
    validate_tripwire_summary(&summary)
        .unwrap_or_else(|error| unreachable!("public corpus summary must validate: {error}"));

    let fingerprint = watch_only_fingerprint(&summary)
        .unwrap_or_else(|error| unreachable!("public corpus summary must serialize: {error}"));
    verify_watch_only_fingerprint(&fingerprint, &summary)
        .unwrap_or_else(|error| unreachable!("self fingerprint must verify: {error}"));
}

#[test]
fn public_fuzz_corpus_covers_checksum_success_and_rejection() {
    let descriptor = include_str!("../fuzz/corpus/public_surfaces/bip380_descriptor.txt");
    assert_eq!(
        with_checksum(descriptor)
            .unwrap_or_else(|error| unreachable!("BIP380 seed must be valid: {error}")),
        "raw(deadbeef)#89f8spxm"
    );

    let checksummed = include_str!("../fuzz/corpus/public_surfaces/already_checksummed.txt");
    assert!(matches!(
        descriptor_checksum(checksummed),
        Err(Error::DescriptorAlreadyContainsChecksum)
    ));
}
