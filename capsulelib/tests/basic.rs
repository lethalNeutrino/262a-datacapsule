include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));
use datacapsule_capsulelib::capsule::SHA256Hashable;
use ed25519_dalek::Signature as DalekSignature;
use serde_json;

/// Basic single-append functionality test.
#[test]
fn basic_single_append() -> anyhow::Result<()> {
    // Create capsule using helper
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([7u8; 32], "capsule_basic")?;

    // Append one record
    let data = b"hello single append".to_vec();
    let header_hash = capsule.append(vec![], data.clone())?;

    // Read record and heartbeat by header_hash
    let record = capsule.read(header_hash.clone())?;
    let hb = capsule.read_heartbeat(header_hash.clone())?;

    // Ensure the record contains a heartbeat and matches the stored heartbeat
    let rec_hb = record.heartbeat.expect("record should have heartbeat");
    let rec_hb_ser = serde_json::to_vec(&rec_hb)?;
    let hb_ser = serde_json::to_vec(&hb)?;
    assert_eq!(rec_hb_ser, hb_ser);

    // Verify seqno mapping
    let seq = record.header.seqno;
    let mapped = capsule.get_header_hash_for_seqno(seq)?;
    assert_eq!(mapped, header_hash);

    // Also ensure we can peek and get the same header at root
    let root = capsule.peek()?;
    assert_eq!(root.header.hash(), header_hash);

    Ok(())
}

/// Test that a tampered heartbeat signature is rejected by `place`.
#[test]
fn tampered_heartbeat_signature_is_rejected() -> anyhow::Result<()> {
    // Create capsule
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([9u8; 32], "capsule_tamper")?;

    // Append one record to get a legitimate header and heartbeat
    let data = b"to be tampered".to_vec();
    let header_hash = capsule.append(vec![], data.clone())?;
    let record = capsule.read(header_hash.clone())?;

    // Extract header and heartbeat
    let header = record.header.clone();
    let mut heartbeat = record.heartbeat.expect("should have heartbeat");

    // Tamper signature bytes by flipping a bit
    let mut sig_bytes = heartbeat.signature.to_bytes();
    sig_bytes[0] ^= 0x01;
    // Reconstruct signature (returns a Signature value)
    let tampered_sig: DalekSignature = DalekSignature::from_bytes(&sig_bytes);
    heartbeat.signature = tampered_sig;

    // Calling place with tampered heartbeat should fail signature verification
    let res = capsule.place(header, heartbeat, vec![]);
    assert!(res.is_err(), "tampered heartbeat signature should be rejected");

    Ok(())
}
