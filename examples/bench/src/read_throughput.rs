use std::collections::BTreeMap;
use std::env;
use std::str;
use std::time::{Duration, Instant};

use capsuleclient::Connection;
use capsulelib::capsule::structs::{Metadata, RecordHeader, SHA256Hashable};
use ed25519_dalek::SigningKey;
use log::{info, warn};

/// Simple read-throughput benchmark for the local capsule reader.
///
/// Behavior:
/// 1. Creates a capsule with a deterministic signing key.
/// 2. Appends `TOTAL_RECORDS` simple payloads (one append per record).
/// 3. Performs `READ_ITERATIONS` sequential reads over the recorded header-hash list,
///    measuring elapsed time and computing throughput as reads/sec.
///
/// Usage:
///   cargo run --example read_throughput -- <total_records> <read_iterations>
///
/// Defaults:
///   total_records = 1000
///   read_iterations = 1000
fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    let total_records: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let read_iterations: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);

    info!(
        "read_throughput: total_records={} read_iterations={}",
        total_records, read_iterations
    );

    // Basic deterministic keys used for examples/tests
    let signing_key_seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_seed);
    let verify_key_bytes = signing_key.verifying_key().to_bytes();

    let metadata_map: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([(String::from("verify_key"), verify_key_bytes.to_vec())]);
    let metadata = Metadata(metadata_map);

    // Minimal symmetric key (16 bytes)
    let symmetric_key = (0..16).collect::<Vec<u8>>();

    // Create the network client connection (local node + pools used by examples)
    let mut connection = Connection::new()?;

    // Create writer capsule (this also creates the local capsule snapshot)
    let mut writer =
        connection.create(".fjall_data", metadata, signing_key, symmetric_key.clone())?;

    // Append records and store header hashes for later reads
    let mut header_hashes: Vec<Vec<u8>> = Vec::with_capacity(total_records);
    for i in 0..total_records {
        let payload = format!("throughput payload {}", i).into_bytes();
        let hh = writer.append(vec![], payload)?;
        header_hashes.push(hh);
        if (i + 1) % 100 == 0 || i + 1 == total_records {
            info!("appended {}/{} records", i + 1, total_records);
        }
    }

    // Create reader which uses the same local capsule/cache
    let mut reader = connection.get(writer.local_capsule.gdp_name(), symmetric_key)?;

    // Warm up: iterate once over the header list to prime caches
    for hh in header_hashes.iter() {
        match reader.read(hh.clone()) {
            Ok(_r) => { /* ignore */ }
            Err(e) => warn!("warmup read error: {}", e),
        }
    }

    // Timed reads: read header_hashes in a round-robin fashion for read_iterations
    let start = Instant::now();
    for iter in 0..read_iterations {
        let idx = iter % header_hashes.len();
        let hh = &header_hashes[idx];
        match reader.read(hh.clone()) {
            Ok(r) => {
                // Optionally sanity-check seqno or content for debug builds
                if r.header.seqno == 0 {
                    warn!("unexpected seqno 0 for hash read");
                }
            }
            Err(e) => {
                warn!("read error at iter {}: {}", iter, e);
            }
        }
    }
    let elapsed = start.elapsed();

    // Compute throughput metrics
    let total_ops = read_iterations as f64;
    let secs = elapsed.as_secs_f64();
    let ops_per_sec = total_ops / secs;

    println!("Read throughput results:");
    println!("  total_reads = {}", read_iterations);
    println!("  total_time = {:.3} secs", secs);
    println!("  reads/sec = {:.2}", ops_per_sec);

    // Print a short sample record content as verification
    if let Some(sample_hh) = header_hashes.get(0) {
        if let Ok(r) = reader.read(sample_hh.clone()) {
            println!(
                "Sample record seqno={} data_preview='{}'",
                r.header.seqno,
                str::from_utf8(&r.body).unwrap_or("<binary>")
            );
        }
    }

    Ok(())
}
