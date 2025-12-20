use std::collections::BTreeMap;
use std::env;

use capsuleclient::Connection;
use capsulelib::capsule::structs::{
    Metadata, Record, RecordContainer, RecordHeader, SHA256Hashable,
};
use ed25519_dalek::SigningKey;
use futures::executor::LocalPool;
use log::{debug, info};

fn build_payload(i: usize) -> Vec<u8> {
    format!("batched payload {}!", i).into_bytes()
}

/// Example: write many records in configurable-sized batches using the
/// RecordContainer / append_container API on the local capsule.
/// This mirrors the single-write bench but groups records together before
/// calling `append_container`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    // Allow configuring batch size and total count via env vars for convenience.
    // Defaults: batch_size=5, total=50
    let batch_size: usize = env::var("BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let total: usize = env::var("TOTAL_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    info!("batch_size={}, total={}", batch_size, total);

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

    // Create a connection (this also sets up a local in-memory node & pool)
    let mut connection = Connection::new()?;

    // Create a capsule writer (this creates the local capsule as source-of-truth).
    let mut capsule_writer = connection.create(
        data_path,
        metadata,
        generated_signing_key,
        encryption_key.clone(),
    )?;

    // We'll accumulate header hashes returned from append_container and also
    // read back the records to verify they decrypt correctly.
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
            // seqno assigned relative to capsule last_seqno as is expected by append_container
            let header = RecordHeader {
                seqno: capsule_writer.local_capsule.last_seqno + (i - next_seq_index) + 1,
                gdp_name: capsule_writer.local_capsule.gdp_name(),
                prev_ptr: None,
                hash_ptrs: Vec::new(),
                data_hash: build_payload(i).hash_string(),
            };

            let rec = Record {
                header: header.clone(),
                heartbeat: None,
                body: build_payload(i),
            };
            container.records.push(rec);
        }

        // Ensure signing key present so append_container can sign the last record heartbeat.
        // The local capsule_create above already set a signing key, but ensure writer has it.
        // (create returned a writer with local_capsule that already has keys populated.)

        // Use the local capsule append_container API directly so we persist the batch.
        // This returns the list of header-hashes for the appended records in order.
        let hashes = capsule_writer.local_capsule.append_container(container)?;
        debug!("appended batch of {} records", hashes.len());
        returned_hashes.extend(hashes);

        // advance
        next_seq_index = end;
    }

    // Create a reader using the same connection (uses local cache in these examples).
    let mut capsule_reader =
        connection.get(capsule_writer.local_capsule.gdp_name(), encryption_key)?;

    // Verify readback of appended records (local-cache path)
    // for hh in returned_hashes.iter() {
    //     // NetworkCapsuleReader::read returns a `Record` for local-cache reads.
    //     match capsule_reader.read(hh.clone()) {
    //         Ok(rec) => {
    //             // print seqno and a utf8 preview if possible
    //             let data_preview = String::from_utf8_lossy(&rec.body);
    //             info!("read seqno={} data={}", rec.header.seqno, data_preview);
    //         }
    //         Err(e) => {
    //             eprintln!("failed to read back record: {}", e);
    //         }
    //     }
    // }

    // Run the local pool a bit (the examples in this repo often spin until externally terminated).
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
