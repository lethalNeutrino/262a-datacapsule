include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));

use datacapsule_capsulelib::capsule::structs::{
    Record, RecordContainer, RecordHeader, SHA256Hashable,
};
use serde_json;

/// Verify that bulk append returns header-hashes in the same order as records and
/// that each returned header-hash corresponds to the decrypted payload we originally provided.
#[test]
fn bulk_append_order_and_contents() -> anyhow::Result<()> {
    let sizes = [1usize, 10usize, 100usize];

    for &size in sizes.iter() {
        // Create capsule for this test run
        let (mut capsule, signing_key, _symmetric, _path) =
            create_capsule_for_test([55u8; 32], &format!("bulk_append_{}", size))?;

        // Build a RecordContainer with `size` records
        let mut container = RecordContainer {
            records: Vec::new(),
        };

        for i in 0..size {
            let header = RecordHeader {
                seqno: capsule.last_seqno + i + 1,
                gdp_name: capsule.gdp_name(),
                prev_ptr: None,
                hash_ptrs: Vec::new(),
                data_hash: format!("data_hash_{}", i),
            };
            let record = Record {
                header: header.clone(),
                heartbeat: None,
                body: format!("payload-{}", i).as_bytes().to_vec(),
            };
            container.records.push(record);
        }

        // Ensure the capsule has a signing key so append_container can sign the heartbeat.
        capsule.sign_key = Some(signing_key.clone());

        // Perform bulk append and verify returned header-hash count
        let header_hashes = capsule.append_container(container)?;
        assert_eq!(
            header_hashes.len(),
            size,
            "expected {} header hashes for size {}",
            size,
            size
        );

        // Verify order and contents: read back each returned header-hash in order and
        // compare decrypted payloads to the original payloads.
        for (i, hh) in header_hashes.iter().enumerate() {
            let rec_container = capsule.read(hh.clone())?;
            let rec = rec_container
                .records
                .first()
                .cloned()
                .expect("record should be present");
            // Header hash should match the returned hh
            assert_eq!(
                &rec.header.hash(),
                hh,
                "header hash mismatch at index {}",
                i
            );
            // Decrypted body should equal the original payload
            let expected = format!("payload-{}", i).as_bytes().to_vec();
            assert_eq!(rec.body, expected, "payload mismatch at index {}", i);
        }
    }

    Ok(())
}

/// Ensure that append_container signs the latest record (last in the container).
#[test]
fn bulk_append_latest_contains_heartbeat() -> anyhow::Result<()> {
    // Pick a moderate size for this test
    let size = 5usize;

    let (mut capsule, signing_key, _symmetric, _path) =
        create_capsule_for_test([77u8; 32], "bulk_append_latest_heartbeat")?;

    let mut container = RecordContainer {
        records: Vec::new(),
    };
    for i in 0..size {
        let header = RecordHeader {
            seqno: capsule.last_seqno + i + 1,
            gdp_name: capsule.gdp_name(),
            prev_ptr: None,
            hash_ptrs: Vec::new(),
            data_hash: format!("data_hash_{}", i),
        };
        let record = Record {
            header: header.clone(),
            heartbeat: None,
            body: format!("payload-{}", i).as_bytes().to_vec(),
        };
        container.records.push(record);
    }

    // Provide the signing key so the last record's heartbeat can be signed
    capsule.sign_key = Some(signing_key.clone());

    let header_hashes = capsule.append_container(container)?;
    assert_eq!(header_hashes.len(), size);

    // The last returned header-hash should correspond to the last record appended
    let last_hh = header_hashes
        .last()
        .cloned()
        .expect("expected at least one header hash");

    // Read the stored record and assert it contains a heartbeat
    let rec_container = capsule.read(last_hh.clone())?;
    let rec = rec_container
        .records
        .first()
        .cloned()
        .expect("record should be present");
    assert!(
        rec.heartbeat.is_some(),
        "latest record should have a heartbeat"
    );

    // Also verify the heartbeat stored in the heartbeat partition matches the embedded heartbeat
    let stored_hb = capsule.read_heartbeat(last_hh.clone())?;
    let rec_hb = rec.heartbeat.expect("heartbeat should be present");
    assert_eq!(
        serde_json::to_vec(&stored_hb)?,
        serde_json::to_vec(&rec_hb)?,
        "heartbeat in partition should match embedded heartbeat"
    );

    Ok(())
}
