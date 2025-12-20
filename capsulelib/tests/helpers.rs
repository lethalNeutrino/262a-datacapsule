use anyhow::Result;
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));

use datacapsule_capsulelib::capsule::structs::RecordHeartbeatData;
use ed25519_dalek::Signature as DalekSignature;
use serde_json;

/// Test helpers for signing/verifying heartbeats and DB insert/get helper behaviors.
#[test]
fn sign_and_verify_heartbeat_helpers() -> Result<()> {
    // Create a capsule for testing (includes signing key & metadata)
    let (capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([42u8; 32], "helpers_sign_verify")?;

    // Build a heartbeat data object
    let hb_data = RecordHeartbeatData {
        seqno: 1,
        gdp_name: capsule.gdp_name(),
        header_hash: vec![0xAA; 32],
    };

    // Sign using the capsule's signing key helper
    let sig = capsule.sign_heartbeat(&hb_data)?;
    // Verify using the capsule's verify helper (reads verify_key from metadata)
    capsule.verify_heartbeat(&hb_data, &sig)?;

    // Tamper with the signature and ensure verification fails
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0x01;
    // Construct a Signature from tampered bytes and ensure verification fails
    let bad_sig = DalekSignature::from_bytes(&sig_bytes);
    let verify_result = capsule.verify_heartbeat(&hb_data, &bad_sig);
    assert!(
        verify_result.is_err(),
        "tampered signature should not verify"
    );

    Ok(())
}

#[test]
fn db_helpers_store_and_lookup() -> Result<()> {
    // Create a capsule for testing (includes partitions)
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([99u8; 32], "helpers_db")?;

    // Append a record to generate a header_hash and ensure it is stored via partition helpers.
    let payload = b"db-helper-payload".to_vec();
    let header_hash = capsule.append(vec![], payload.clone())?;

    // read_heartbeat should return the heartbeat we stored
    let hb = capsule.read_heartbeat(header_hash.clone())?;
    let rec = capsule
        .read(header_hash.clone())?
        .head()
        .cloned()
        .expect("record should include a heartbeat");
    let rec_hb = rec.heartbeat.expect("record should include a heartbeat");
    assert_eq!(serde_json::to_vec(&hb)?, serde_json::to_vec(&rec_hb)?);

    // get_header_hash_for_seqno should return the header hash for the appended seqno
    let seqno = rec.header.seqno;
    let mapped = capsule.get_header_hash_for_seqno(seqno)?;
    assert_eq!(mapped, header_hash);

    // put_header_hash_for_seqno should allow storing a mapping and then retrieving it
    let fake_seqno = seqno + 1000;
    capsule.put_header_hash_for_seqno(fake_seqno, header_hash.clone())?;
    let mapped2 = capsule.get_header_hash_for_seqno(fake_seqno)?;
    assert_eq!(mapped2, header_hash);

    Ok(())
}
