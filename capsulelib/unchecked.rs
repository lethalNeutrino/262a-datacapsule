#![cfg(feature = "unchecked")]

// Standalone feature-gated unchecked utilities for benchmarking/testing.
//
// This module is included as a child `pub mod unchecked { #[path = "unchecked.rs"] ... }`
// of `capsule.rs`. It implements the unchecked helpers that skip signature
// verification and other safety checks.
//
// These helpers are intended for benchmarks or tooling only and must remain
// behind the `unchecked` feature gate.

use super::*;
use anyhow::{Result, bail};
use serde_json;

/// Read a record without verifying heartbeat signatures. Intended for benchmarks
/// or debugging where signature checks should be skipped.
impl Capsule {
    pub fn read_unchecked(&self, header_hash: Vec<u8>) -> Result<Record> {
        let record_bytes = self
            .keyspace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("keyspace partition not opened"))?
            .get(&header_hash)?
            .ok_or_else(|| anyhow::anyhow!("record not found for header hash"))?
            .to_vec();

        let mut record: Record = serde_json::from_slice(&record_bytes)?;

        log::debug!(
            "retrieved record data (encrypted): {}",
            record
                .body
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        let iv: [u8; 16] = [record.header.seqno.to_le_bytes(), [0x0_u8; 8]]
            .concat()
            .try_into()
            .unwrap();

        log::debug!("Decryption Key: {:?}", self.symmetric_key);
        log::debug!("Decryption IV: {:?}", iv);

        let mut cipher = Aes128Ctr64LE::new(self.symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut record.body);

        log::info!("retrieved {:?}", record);
        log::info!(
            "retrieved record data (decrypted) {:?}",
            record
                .body
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // NOTE: Intentionally do not verify the heartbeat signature in this unchecked variant.

        Ok(record)
    }

    /// Insert a heartbeat into the per-capsule heartbeat partition without verifying
    /// its signature. Intended for benchmarks/testing.
    /// Unchecked placement that inserts the heartbeat into the heartbeat partition
    /// without verifying its signature. Intended for benchmarks/testing.
    pub fn place_unchecked(
        &self,
        header: RecordHeader,
        heartbeat: RecordHeartbeat,
        _data: Vec<u8>,
    ) -> Result<()> {
        if let Some(hb_space) = &self.heartbeat_keyspace {
            let header_hash = header.hash();
            hb_space.insert(&header_hash, serde_json::to_vec(&heartbeat)?)?;
        } else {
            // Mirror the checked API behavior and return an error when partition isn't opened.
            bail!("heartbeat partition not opened");
        }
        Ok(())
    }

    /// Overwrite the stored record bytes for `header_hash` with the provided `record`.
    /// Intended for tests/benchmarks to simulate corrupted storage or tampering.
    pub fn overwrite_record(&self, header_hash: Vec<u8>, record: &Record) -> Result<()> {
        let items = self
            .keyspace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("keyspace partition not opened"))?;
        items.insert(&header_hash, serde_json::to_vec(record)?)?;
        Ok(())
    }
}
