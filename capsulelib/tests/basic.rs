include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));
use datacapsule_capsulelib::capsule::structs::{CapsuleSnapshot, SHA256Hashable};
use ed25519_dalek::Signature as DalekSignature;
use fjall::PartitionCreateOptions;
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
    let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let tampered_sig: DalekSignature = DalekSignature::from_bytes(&arr);
    heartbeat.signature = tampered_sig;

    // Calling place with tampered heartbeat should fail signature verification
    let res = capsule.place(header, heartbeat, vec![]);
    assert!(
        res.is_err(),
        "tampered heartbeat signature should be rejected"
    );

    Ok(())
}

/// The following tests exercise the feature-gated unchecked variants.
/// They are only compiled and run when the `unchecked` feature is enabled.
#[cfg(feature = "unchecked")]
#[test]
fn read_unchecked_allows_tampered_record() -> anyhow::Result<()> {
    // Create capsule
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([21u8; 32], "capsule_read_unchecked")?;

    // Append one record
    let data = b"payload for unchecked read".to_vec();
    let header_hash = capsule.append(vec![], data.clone())?;

    // Read the record, tamper its embedded heartbeat signature, and overwrite in store
    let mut rec = capsule.read(header_hash.clone())?;
    if let Some(ref mut hb) = rec.heartbeat {
        let mut sig_bytes = hb.signature.to_bytes();
        sig_bytes[0] ^= 0x01;
        let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        hb.signature = ed25519_dalek::Signature::from_bytes(&arr);
    }
    // Overwrite the stored record with the tampered one using feature-gated API
    capsule.overwrite_record(header_hash.clone(), &rec)?;

    // Normal read should now reject due to signature verification
    let res_checked = capsule.read(header_hash.clone());
    assert!(
        res_checked.is_err(),
        "checked read should reject tampered heartbeat"
    );

    // But read_unchecked should succeed (skips signature verification)
    let res_unchecked = capsule.read_unchecked(header_hash.clone());
    assert!(
        res_unchecked.is_ok(),
        "read_unchecked should return record despite tampered signature"
    );
    let rec_unchecked = res_unchecked.unwrap();
    assert_eq!(rec_unchecked.header.hash(), header_hash);

    Ok(())
}

#[cfg(feature = "unchecked")]
#[test]
fn place_unchecked_allows_inserting_tampered_heartbeat() -> anyhow::Result<()> {
    // Create capsule
    let (mut capsule, _signing_key, _symmetric_key, _path) =
        create_capsule_for_test([22u8; 32], "capsule_place_unchecked")?;

    // Append one record to obtain a header (and header_hash)
    let data = b"payload for place_unchecked".to_vec();
    let header_hash = capsule.append(vec![], data.clone())?;
    let record = capsule.read(header_hash.clone())?;
    let header = record.header.clone();

    // Prepare a tampered heartbeat (flip signature bytes)
    let mut tampered_hb = record.heartbeat.expect("should have heartbeat");
    let mut sig_bytes = tampered_hb.signature.to_bytes();
    sig_bytes[0] ^= 0x01;
    let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    tampered_hb.signature = ed25519_dalek::Signature::from_bytes(&arr);

    // Using place (checked) should reject the tampered heartbeat
    let res_checked = capsule.place(header.clone(), tampered_hb.clone(), vec![]);
    assert!(
        res_checked.is_err(),
        "place should reject tampered heartbeat"
    );

    // But place_unchecked should allow inserting the tampered heartbeat into heartbeat partition
    let res_unchecked = capsule.place_unchecked(header.clone(), tampered_hb.clone(), vec![]);
    assert!(
        res_unchecked.is_ok(),
        "place_unchecked should allow tampered heartbeat"
    );

    // And read_heartbeat should now return the tampered heartbeat from the heartbeat partition
    let hb_read = capsule.read_heartbeat(header_hash.clone())?;
    assert_eq!(
        serde_json::to_vec(&hb_read)?,
        serde_json::to_vec(&tampered_hb)?
    );

    Ok(())
}

/// Ensure creating the same capsule twice on the same store path succeeds and returns the existing capsule.
#[test]
fn create_twice_is_ok() -> anyhow::Result<()> {
    // Use a deterministic seed and unique prefix so the test store path is unique
    let seed = [33u8; 32];
    let prefix = "capsule_create_twice";

    // First creation via helper (which calls Capsule::create internally)
    let (capsule1, signing_key, symmetric_key, store_path) = create_capsule_for_test(seed, prefix)?;

    // Prepare metadata and attempt to create again using the same store path and keys
    let metadata = make_metadata_for_signing_key(&signing_key);
    let kv_store = store_path.as_path();

    // Second create should detect existing capsule and return it (no error)
    let capsule2 = Capsule::create(
        kv_store,
        metadata,
        signing_key.clone(),
        symmetric_key.clone(),
    )?;

    // Basic sanity: both capsules should have the same metadata hash (gdp name)
    assert_eq!(
        capsule1.metadata.hash_string(),
        capsule2.metadata.hash_string()
    );

    // Also ensure peek returns a valid record for the existing capsule
    let _ = capsule2.peek()?;

    Ok(())
}

/// Snapshot flow test: create a capsule, append a record (updating snapshot), drop the capsule,
/// then `get` the capsule back from the store and verify the snapshot state (last_seqno, metadata)
/// and that the appended record can be read.
#[test]
fn snapshot_roundtrip() -> anyhow::Result<()> {
    // Unique seed and prefix to avoid collisions between tests
    let seed = [44u8; 32];
    let prefix = "capsule_snapshot_flow";

    // Create capsule using helper (this calls Capsule::create and writes initial snapshot)
    let (mut capsule, _signing_key, symmetric_key, store_path) = create_capsule_for_test(seed, prefix)?;

    // Append a record so the snapshot is updated after append
    let payload = b"snapshot payload".to_vec();
    let header_hash = capsule.append(vec![], payload.clone())?;
    let expected_seqno = capsule.last_seqno;
    let gdp_name = capsule.metadata.hash_string();

    // Drop the capsule to ensure Keyspace/partitions are closed and subsequent get reconstructs from storage
    drop(capsule);

    // Reconstruct using get; get should consult the persisted snapshot and restore last_seqno/last_pointer
    let reconstructed = Capsule::get(
        store_path.as_path(),
        gdp_name.clone(),
        symmetric_key.clone(),
    )?;

    // Snapshot should have been reflected in reconstructed capsule
    assert_eq!(reconstructed.last_seqno, expected_seqno);
    assert_eq!(reconstructed.metadata.hash_string(), gdp_name);

    // Ensure we can read the record we appended earlier
    let rec = reconstructed.read(header_hash.clone())?;
    assert_eq!(rec.header.hash(), header_hash);

    Ok(())
}

/// Verify that the persisted snapshot is updated after append().
#[test]
fn snapshot_updated_on_append() -> anyhow::Result<()> {
    // Create a test capsule
    let seed = [99u8; 32];
    let prefix = "capsule_snapshot_update";

    let (mut capsule, _signing_key, _symmetric_key, _store_path) = create_capsule_for_test(seed, prefix)?;
    let gdp_name = capsule.metadata.hash_string();

    // Append a record which should trigger snapshot update in append()
    let header_hash = capsule.append(vec![], b"update snapshot payload".to_vec())?;

    // Open the snapshots partition directly from the capsule keyspace and read the snapshot
    let ks = capsule
        .keyspace
        .as_ref()
        .expect("keyspace should be present on capsule");
    let snaps = ks.open_partition(
        "capsule_snapshots",
        PartitionCreateOptions::default().max_memtable_size(8 * 1024 * 1024),
    )?;
    let snap_bytes = snaps.get(gdp_name.as_bytes())?.expect("snapshot should exist");
    let snap: CapsuleSnapshot = serde_json::from_slice(&snap_bytes)?;

    assert_eq!(snap.last_seqno, capsule.last_seqno);
    assert_eq!(snap.last_pointer.0, capsule.last_pointer.0);
    assert_eq!(snap.last_pointer.1, capsule.last_pointer.1);

    // Also ensure the appended record is readable
    let rec = capsule.read(header_hash.clone())?;
    assert_eq!(rec.header.hash(), header_hash);

    Ok(())
}
