use ed25519_dalek::Signature;
use ed25519_dalek::SigningKey;
use fjall::Keyspace;
use fjall::PartitionHandle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

// struct MissingMetadataKey;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Metadata(pub BTreeMap<String, Vec<u8>>);
pub type HashPointer = (usize, Vec<u8>);

pub trait SHA256Hashable {
    fn hash(&self) -> Vec<u8>;
    fn hash_string(&self) -> String {
        self.hash()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

impl SHA256Hashable for Metadata {
    fn hash(&self) -> Vec<u8> {
        // compute SHA256 hash of metadata deterministically (BTreeMap is ordered)
        let mut hasher = Sha256::new();
        for (k, v) in &self.0 {
            hasher.update(k.as_bytes());
            hasher.update(v);
        }
        hasher.finalize().to_vec()
    }
}

impl SHA256Hashable for HashPointer {
    fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.to_be_bytes());
        hasher.update(&self.1);
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Record {
    pub header: RecordHeader,
    pub heartbeat: Option<RecordHeartbeat>,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RecordHeader {
    pub seqno: usize,
    pub gdp_name: String,
    pub prev_ptr: Option<HashPointer>,
    pub hash_ptrs: Vec<HashPointer>,
}

impl SHA256Hashable for RecordHeader {
    fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.seqno.to_be_bytes());
        hasher.update(&self.gdp_name);
        hasher.update(self.prev_ptr.as_ref().map_or(vec![], |p| p.hash()));
        for hash_ptr in &self.hash_ptrs {
            hasher.update(hash_ptr.hash());
        }
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordHeartbeatData {
    pub seqno: usize,
    pub gdp_name: String,
    pub header_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordHeartbeat {
    pub data: RecordHeartbeatData,
    pub signature: Signature,
}

struct RecordContainer {
    records: Vec<(Option<RecordHeartbeat>, RecordHeader, Vec<u8>)>,
}

/// Snapshot of the capsule persisted to the keyspace. This struct intentionally
/// excludes non-serializable items such as the in-memory `SigningKey`. It stores
/// the capsule's metadata, symmetric key, and the last sequence pointer so the
/// capsule can be reconstructed from storage.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CapsuleSnapshot {
    pub metadata: Metadata,
    pub symmetric_key: Vec<u8>,
    pub last_seqno: usize,
    pub last_pointer: HashPointer,
}

#[derive(Default, Clone)]
pub struct Capsule {
    pub metadata: Metadata,
    pub symmetric_key: Vec<u8>,
    /// Optional in-memory signing key used by writers. This is not serialized
    /// into the snapshot; callers that re-open a snapshot and require signing
    /// capabilities should set this field after reconstructing the capsule.
    pub sign_key: Option<SigningKey>,
    pub last_seqno: usize,
    pub last_pointer: HashPointer,
    pub keyspace: Option<Keyspace>,
    pub record_partition: Option<PartitionHandle>,
    // Per-capsule heartbeat partition
    pub heartbeat_partition: Option<PartitionHandle>,
    // Per-capsule seqno -> header hash partition
    pub seqno_partition: Option<PartitionHandle>,
    /// Optional key used in the keyspace for storing the serialized `CapsuleSnapshot`.
    /// When present, callers should update the snapshot key after creating the capsule
    /// so it can be persisted/updated as appends occur.
    pub snapshot_key: Option<Vec<u8>>,
}
