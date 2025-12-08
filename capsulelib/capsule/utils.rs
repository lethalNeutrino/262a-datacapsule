use super::structs::{Capsule, Metadata, RecordHeartbeat, RecordHeartbeatData, SHA256Hashable};
use ed25519_dalek::{Signature, Signer, SigningKey};
use fjall::{Keyspace, Partition, PartitionCreateOptions, PartitionHandle};

use anyhow::{Result, bail};

/// Helper: sign a RecordHeartbeatData with a provided SigningKey.
pub fn sign_heartbeat_with_key(
    sign_key: &SigningKey,
    data: &RecordHeartbeatData,
) -> Result<Signature> {
    let sig = sign_key.sign(serde_json::to_vec(data)?.as_ref());
    Ok(sig)
}

/// Helper: verify a RecordHeartbeat using the verify_key stored in Metadata.
/// This centralizes the logic to read the verify_key bytes, build a VerifyingKey,
/// and verify the signature over the serde_json-serialized heartbeat data.
pub fn verify_heartbeat_with_metadata(
    metadata: &Metadata,
    data: &RecordHeartbeatData,
    signature: &Signature,
) -> Result<()> {
    let vk_bytes = metadata
        .0
        .get("verify_key")
        .ok_or_else(|| anyhow::anyhow!("metadata must contain 'verify_key'"))?;

    let vk_arr: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("verify_key must be 32 bytes"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_arr)?;

    let msg = serde_json::to_vec(data)?;
    if let Err(e) = ed25519_dalek::Verifier::verify(&verifying_key, &msg, signature) {
        bail!("invalid heartbeat signature: {}", e);
    }
    Ok(())
}

pub fn init_partitions(
    keyspace: &Keyspace,
    gdp_name: &str,
) -> Result<(Partition, Partition, Partition)> {
    let items = keyspace.open_partition(
        gdp_name,
        PartitionCreateOptions::default().max_memtable_size(64 * 1024 * 1024),
    )?;

    // Create a separate partition for heartbeats for this capsule. Name it
    // by appending a suffix to the capsule name to keep it unique.
    let heartbeat_partition_name = format!("{}-heartbeats", gdp_name);
    let heartbeat_items = keyspace.open_partition(
        heartbeat_partition_name.as_str(),
        PartitionCreateOptions::default().max_memtable_size(32 * 1024 * 1024),
    )?;

    // Create a separate partition for seqno->header mappings
    let seqno_partition_name = format!("{}-seqnos", gdp_name);
    let seqno_items = keyspace.open_partition(
        seqno_partition_name.as_str(),
        PartitionCreateOptions::default().max_memtable_size(16 * 1024 * 1024),
    )?;

    Ok((items, heartbeat_items, seqno_items))
}

/// Lightweight helper for inserting into a partition handle (centralized for clarity).
pub fn partition_insert(part: &PartitionHandle, key: &[u8], value: Vec<u8>) -> Result<()> {
    part.insert(key, value)?;
    Ok(())
}

impl Capsule {
    #[inline]
    pub fn gdp_name(&self) -> String {
        self.metadata.hash_string()
    }

    /// Sign a RecordHeartbeatData using the capsule's signing key.
    pub fn sign_heartbeat(&self, data: &RecordHeartbeatData) -> Result<Signature> {
        let sk = self
            .sign_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("signing key not available"))?;
        sign_heartbeat_with_key(sk, data)
    }

    /// Verify a RecordHeartbeatData and Signature using this capsule's metadata verify_key.
    pub fn verify_heartbeat(
        &self,
        data: &RecordHeartbeatData,
        signature: &Signature,
    ) -> Result<()> {
        verify_heartbeat_with_metadata(&self.metadata, data, signature)
    }

    /// Read heartbeat stored in the heartbeat partition by header hash.
    pub fn read_heartbeat(&self, header_hash: Vec<u8>) -> Result<RecordHeartbeat> {
        let hb_bytes = self
            .heartbeat_partition
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("heartbeat partition not opened"))?
            .get(&header_hash)?
            .ok_or_else(|| anyhow::anyhow!("heartbeat not found for header hash"))?;
        let hb: RecordHeartbeat = serde_json::from_slice(&hb_bytes)?;
        Ok(hb)
    }

    /// Return the header hash stored for the given seqno (persistent mapping).
    pub fn get_header_hash_for_seqno(&self, seqno: usize) -> Result<Vec<u8>> {
        let seq_space = self
            .seqno_partition
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("seqno partition not opened"))?;
        let key = seqno.to_be_bytes().to_vec();
        let v = seq_space
            .get(&key)?
            .ok_or_else(|| anyhow::anyhow!("no header hash for seqno {}", seqno))?;
        Ok(v.to_vec())
    }

    /// Store (seqno -> header_hash) mapping into the seqno partition.
    pub fn put_header_hash_for_seqno(&self, seqno: usize, header_hash: Vec<u8>) -> Result<()> {
        let seq_space = self
            .seqno_partition
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("seqno partition not opened"))?;
        let key = seqno.to_be_bytes().to_vec();
        partition_insert(seq_space, &key, header_hash)?;
        Ok(())
    }

    // Helper: insert heartbeat into heartbeat partition if opened.
    pub fn insert_into_heartbeat_partition_opt(&self, key: &[u8], value: Vec<u8>) -> Result<()> {
        if let Some(hb_space) = &self.heartbeat_partition {
            partition_insert(hb_space, key, value)?;
        }
        Ok(())
    }

    // Helper: insert seqno -> header_hash into seqno partition if opened.
    pub fn insert_into_seqno_partition_opt(
        &self,
        seqno: usize,
        header_hash: Vec<u8>,
    ) -> Result<()> {
        if let Some(seq_space) = &self.seqno_partition {
            let key = seqno.to_be_bytes().to_vec();
            partition_insert(seq_space, &key, header_hash)?;
        }
        Ok(())
    }
}
