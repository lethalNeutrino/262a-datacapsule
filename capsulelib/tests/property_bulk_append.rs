include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));

use datacapsule_capsulelib::capsule::structs::{
    Record, RecordContainer, RecordHeader, RecordHeartbeat, SHA256Hashable,
};
use proptest::prelude::*;

/// Property test: generate random lists of payloads (varying sizes) and verify:
/// 1) `append_container` returns header-hashes in the same order as records provided,
/// 2) `read(hh)` returns the decrypted payload that exactly matches the original payload,
/// 3) the last record appended has a heartbeat and it matches the heartbeat partition entry.
proptest! {
    #![proptest_config(ProptestConfig {
        // Allow a moderate number of cases and complexity.
        cases: 50,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_bulk_append_roundtrip(payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..256), 1..50)) {
        // Create a test capsule for this run.
        let (mut capsule, signing_key, _symmetric, _path) = create_capsule_for_test([123u8; 32], "prop_bulk_append").unwrap();

        // Build a RecordContainer using the random payloads. Keep the expected header hashes.
        let mut container = RecordContainer { records: Vec::new() };
        let mut expected_hashes: Vec<Vec<u8>> = Vec::new();

        for (i, payload) in payloads.iter().cloned().enumerate() {
            // Assign seqno values relative to the capsule's current last_seqno.
            let header = RecordHeader {
                seqno: capsule.last_seqno + i + 1,
                gdp_name: capsule.gdp_name(),
                prev_ptr: None,
                hash_ptrs: Vec::new(),
                data_hash: payload.hash_string(),
            };
            expected_hashes.push(header.hash());

            let rec = Record {
                header: header.clone(),
                heartbeat: None,
                body: payload,
            };
            container.records.push(rec);
        }

        // Ensure capsule has signing key set so append_container will sign the last heartbeat.
        capsule.sign_key = Some(signing_key.clone());

        // Append the container and collect header-hashes returned by the function.
        let returned_hashes = capsule.append_container(container).unwrap();

        // 1) The returned order should match the expected header hashes order.
        prop_assert_eq!(returned_hashes.len(), expected_hashes.len());
        // Clone to avoid moving `returned_hashes` since we use it later in this test.
        prop_assert_eq!(returned_hashes.clone(), expected_hashes);

        // 2) For each returned header hash, read back the record and verify the decrypted body
        // exactly matches the original payload at the same position.
        for (i, hh) in returned_hashes.iter().enumerate() {
            let rc = capsule.read(hh.clone()).unwrap();
            let rec = rc.head().cloned().expect("record present");

            // Compare decrypted body to the original randomized payload we constructed earlier.
            prop_assert_eq!(rec.body.as_slice(), payloads[i].as_slice(), "payload mismatch at index {}", i);
        }

        // 3) Verify the last record has a heartbeat and that the heartbeat stored in
        //    the heartbeat partition matches the embedded heartbeat.
        let last_hh = returned_hashes.last().cloned().unwrap();
        let rc_last = capsule.read(last_hh.clone()).unwrap();
        let rec_last = rc_last.head().cloned().expect("last record present");
        prop_assert!(rec_last.heartbeat.is_some(), "latest record should have heartbeat");

        let hb_in_partition: RecordHeartbeat = capsule.read_heartbeat(last_hh.clone()).unwrap();
        let embedded_hb = rec_last.heartbeat.expect("heartbeat embedded");
        // Compare serialized form for equality
        prop_assert_eq!(serde_json::to_vec(&hb_in_partition).unwrap(), serde_json::to_vec(&embedded_hb).unwrap());
    }
}
