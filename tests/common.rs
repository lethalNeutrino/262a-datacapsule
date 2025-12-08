use datacapsule_capsulelib::capsule::{Capsule, Metadata};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a Metadata object from a SigningKey by extracting the verifying key bytes.
pub fn make_metadata_for_signing_key(sk: &SigningKey) -> Metadata {
    let vk = sk.verifying_key();
    let mut md = BTreeMap::new();
    md.insert(String::from("verify_key"), vk.to_bytes().to_vec());
    Metadata(md)
}

/// Produce a unique temporary store path for tests using the current time.
pub fn unique_store_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time drift")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("{}_{}", prefix, nanos));
    p
}

/// Convenience helper to create a Capsule for tests.
///
/// - `seed` is used to construct a deterministic `SigningKey`.
/// - `prefix` is used to build a unique temporary store path.
///
/// Returns the created `(Capsule, SigningKey, symmetric_key, store_path)`.
pub fn create_capsule_for_test(
    seed: [u8; 32],
    prefix: &str,
) -> anyhow::Result<(Capsule, SigningKey, Vec<u8>, PathBuf)> {
    let signing_key = SigningKey::from_bytes(&seed);
    let metadata = make_metadata_for_signing_key(&signing_key);
    let symmetric_key = (0..16).collect::<Vec<u8>>();
    let store = unique_store_path(prefix);
    let kv_store = store.as_path();

    // Capsule::create expects ownership of a SigningKey; many tests still want the
    // original signing key instance, so clone it when passing to create.
    let capsule = Capsule::create(kv_store, metadata, signing_key.clone(), symmetric_key.clone())?;

    Ok((capsule, signing_key, symmetric_key, store))
}
