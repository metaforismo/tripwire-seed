#![no_main]

use libfuzzer_sys::fuzz_target;
use tripwire_seed::{
    descriptor::{descriptor_checksum, with_checksum},
    fingerprint::{verify_watch_only_fingerprint, watch_only_fingerprint},
    wallet::{TripwireSummary, validate_tripwire_summary},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = descriptor_checksum(text);
        let _ = with_checksum(text);
    }

    let Ok(summary) = serde_json::from_slice::<TripwireSummary>(data) else {
        return;
    };

    let validation = validate_tripwire_summary(&summary);
    let fingerprint = match watch_only_fingerprint(&summary) {
        Ok(fingerprint) => fingerprint,
        Err(error) => panic!("decoded public summary failed to fingerprint: {error}"),
    };

    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(fingerprint, fingerprint.to_ascii_lowercase());

    if validation.is_ok() {
        assert!(verify_watch_only_fingerprint(&fingerprint, &summary).is_ok());
        assert!(
            verify_watch_only_fingerprint(&fingerprint.to_ascii_uppercase(), &summary).is_ok()
        );
    }
});
