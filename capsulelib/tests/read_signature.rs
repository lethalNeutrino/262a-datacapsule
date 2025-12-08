include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));

use datacapsule_capsulelib::capsule::SHA256Hashable;
use ed25519_dalek::Signature as DalekSignature;

#[test]
fn read_rejects_invalid_heartbeat_signature() -> anyhow::Result<()> {
    // Create capsule using helper (unique store path inside)
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([13u8; 32], "capsule_read_sig")?;

    // append one record
    let header_hash = capsule.append(vec![], b"payload-for-signature-test".to_vec())?;

    // read the record and tamper the heartbeat signature in-place in the record
    let rec = capsule.read(header_hash.clone())?;
    let mut tampered = rec.clone();

    if let Some(ref mut hb) = tampered.heartbeat {
        let mut sig_bytes = hb.signature.to_bytes();
        sig_bytes[0] ^= 0x01; // flip a bit
        let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        hb.signature = DalekSignature::from_bytes(&arr);
    }

    // overwrite the stored record with the tampered one using the public keyspace
    capsule
        .keyspace
        .as_ref()
        .unwrap()
        .insert(&header_hash, serde_json::to_vec(&tampered)?)?;

    // Now reading that header should fail due to invalid heartbeat signature
    let res = capsule.read(header_hash.clone());
    assert!(
        res.is_err(),
        "read should reject record with invalid heartbeat signature"
    );

    Ok(())
}
