use std::collections::BTreeMap;
use std::env;
use std::str;

use capsuleclient::Connection;
use capsulelib::capsule::structs::{
    Metadata, Record, RecordContainer, RecordHeader, SHA256Hashable,
};
use ed25519_dalek::SigningKey;
use futures::executor::LocalPool;
use log::{debug, info};

/// Build a payload of exactly `size` bytes that includes the index `i` for variety.
fn build_payload(i: usize, size: usize) -> Vec<u8> {
    // Start with a human readable prefix including the index so different records vary.
    let prefix = format!("payload-{}-", i);
    let mut v = prefix.into_bytes();
    if v.len() >= size {
        v.truncate(size);
        return v;
    }
    // Fill the remainder with a repeating pattern.
    let mut j = 0u8;
    while v.len() < size {
        v.push(b'a' + (j % 26));
        j = j.wrapping_add(1);
    }
    v
}

/// Example: write many records in configurable-sized batches using the
/// RecordContainer / append_container API on the local capsule.
/// Configuration via environment variables:
///   BATCH_SIZE: number of records per batch (default: 5)
///   TOTAL_RECORDS: total records to append (default: 50)
///   PAYLOAD_SIZE: payload size of each record in bytes (default: 128)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // Read configuration from env vars with sensible defaults.
    let batch_size: usize = env::var("BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let total: usize = env::var("TOTAL_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let payload_size: usize = env::var("PAYLOAD_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(128);

    info!(
        "bench_batches_payload: batch_size={}, total={}, payload_size={}",
        batch_size, total, payload_size
    );

    let data_path = ".fjall_data";

    // deterministic signing key for example
    let signing_key_seed = [0u8; 32];
    let generated_signing_key = SigningKey::from_bytes(&signing_key_seed);
    let generated_verify_key = generated_signing_key.verifying_key();
    let generated_verify_key_bytes = generated_verify_key.to_bytes();

    let metadata_map: BTreeMap<String, Vec<u8>> = BTreeMap::from([(
        String::from("verify_key"),
        generated_verify_key_bytes.to_vec(),
    )]);

    let metadata = Metadata(metadata_map);

    // Minimal symmetric key (16 bytes)
    let encryption_key = (0..16).collect::<Vec<u8>>();

    // Create a connection (this also sets up a local node & pool)
    let mut connection = Connection::new()?;

    // Create a capsule writer (this creates the local capsule as source-of-truth).
    let mut capsule_writer = connection.create(
        data_path,
        metadata,
        generated_signing_key,
        encryption_key.clone(),
    )?;

    // We'll accumulate header hashes returned from append_container.
    let mut returned_hashes: Vec<Vec<u8>> = Vec::new();

    let mut next_seq_index = 0usize;

    // Create batches and write them using the capsule's RecordContainer API.
    while next_seq_index < total {
        let mut container = RecordContainer {
            records: Vec::new(),
        };

        // Build a batch sized slice for this iteration
        let end = std::cmp::min(next_seq_index + batch_size, total);
        for i in next_seq_index..end {
            // seqno assigned relative to capsule last_seqno as expected by append_container
            let header = RecordHeader {
                seqno: capsule_writer.local_capsule.last_seqno + (i - next_seq_index) + 1,
                gdp_name: capsule_writer.local_capsule.gdp_name(),
                prev_ptr: None,
                hash_ptrs: Vec::new(),
                data_hash: build_payload(i, payload_size).hash_string(),
            };

            let rec = Record {
                header: header.clone(),
                heartbeat: None,
                body: build_payload(i, payload_size),
            };
            container.records.push(rec);
        }

        // Persist the batch locally (this will sign the last heartbeat and store records).
        let hashes = capsule_writer.local_capsule.append_container(container)?;
        debug!("appended batch of {} records", hashes.len());
        returned_hashes.extend(hashes);

        // advance
        next_seq_index = end;
    }

    // Create a reader using the same connection (uses local cache in these examples).
    let mut capsule_reader =
        connection.get(capsule_writer.local_capsule.gdp_name(), encryption_key)?;

    // Print a few sample records to verify payload size and content.
    for hh in returned_hashes.iter().take(5) {
        match capsule_reader.read(hh.clone()) {
            Ok(rec) => {
                info!(
                    "sample seqno={} size={} preview='{}'",
                    rec.header.seqno,
                    rec.body.len(),
                    // show only a prefix safely as UTF-8 may be valid
                    str::from_utf8(&rec.body[..std::cmp::min(64, rec.body.len())])
                        .unwrap_or("<binary>")
                );
            }
            Err(e) => {
                eprintln!("failed to read back record: {}", e);
            }
        }
    }

    // Run the local pool a bit (the examples often spin until externally terminated).
    let mut pool = LocalPool::new();
    for _ in 0..10 {
        connection
            .node
            .borrow_mut()
            .spin_once(std::time::Duration::from_millis(50));
        pool.run_until_stalled();
    }

    Ok(())
}
