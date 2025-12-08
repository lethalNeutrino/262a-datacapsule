include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/common.rs"));
use datacapsule_capsulelib::capsule::SHA256Hashable;
use uuid::Uuid;

/// A heavier integration test that performs many appends, creates some
/// branching hash pointers, and exercises seqno -> header-hash mappings.
#[test]
fn complex_heavy_appends_and_seqno_checks() -> anyhow::Result<()> {
    // Create a capsule for the test with a deterministic signing key seed
    let (mut capsule, _signing_key, _symmetric_key, _store_path) =
        create_capsule_for_test([11u8; 32], "capsule_complex_heavy")?;

    // Perform many non-trivial appends (vary payload and include some hash_ptrs).
    // We'll keep the header hashes in-memory to validate pointers and mappings.
    let mut header_hashes: Vec<Vec<u8>> = Vec::new();
    let total = 50usize;

    for i in 1..=total {
        // Non-trivial payload
        let body = format!("heavy payload {} - {}", i, Uuid::new_v4()).into_bytes();

        // Create up to two backward pointers to recent headers (simulating DAG-ish pointers)
        let mut hash_ptrs = Vec::new();
        if let Some(last) = header_hashes.last() {
            hash_ptrs.push((i - 1, last.clone()));
        }
        if header_hashes.len() >= 2 {
            hash_ptrs.push((i - 2, header_hashes[header_hashes.len() - 2].clone()));
        }

        // Append and record the header hash returned
        let hh = capsule.append(hash_ptrs.clone(), body.clone())?;
        // Basic immediate checks
        let rec = capsule.read(hh.clone())?;
        assert_eq!(rec.header.seqno, i);
        assert_eq!(rec.header.hash_ptrs.len(), hash_ptrs.len());

        header_hashes.push(hh);
    }

    // Peek root and walk back using prev_ptr, verifying heartbeats match and seqno mappings are correct.
    let root = capsule.peek()?;
    let mut current_hash = root.header.hash();

    let mut seen_seqnos = Vec::new();
    loop {
        let record = capsule.read(current_hash.clone())?;
        let hb = capsule.read_heartbeat(current_hash.clone())?;

        // Heartbeat embedded in record must match the one stored in heartbeat partition
        let rec_hb = record.heartbeat.expect("record should have a heartbeat");
        assert_eq!(serde_json::to_vec(&rec_hb)?, serde_json::to_vec(&hb)?);

        // Seqno -> header-hash mapping must point to this header hash
        let seq = record.header.seqno;
        let mapped = capsule.get_header_hash_for_seqno(seq)?;
        assert_eq!(mapped, current_hash);

        seen_seqnos.push(seq);

        // Follow prev_ptr
        if let Some(prev) = record.header.prev_ptr {
            current_hash = prev.1;
        } else {
            break;
        }
    }

    // Ensure we saw metadata seqno 0 and all appended seqnos
    assert!(seen_seqnos.contains(&0usize));
    for seqno in 1..=total {
        let hh = capsule.get_header_hash_for_seqno(seqno)?;
        // seqno 1 maps to header_hashes[0]
        assert_eq!(hh, header_hashes[seqno - 1]);
    }

    // Exercise explicit put_header_hash_for_seqno and reading it back
    let fake_hash = vec![0xABu8; 32];
    capsule.put_header_hash_for_seqno(9999, fake_hash.clone())?;
    let got = capsule.get_header_hash_for_seqno(9999)?;
    assert_eq!(got, fake_hash);

    Ok(())
}
