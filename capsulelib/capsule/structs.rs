use ed25519_dalek::Signature;
use ed25519_dalek::SigningKey;
use fjall::Keyspace;
use fjall::PartitionHandle;
use indexmap::IndexMap;
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

pub trait Validate {
    fn valid(&self) -> bool;
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

pub type RecordBody = Vec<u8>;

impl SHA256Hashable for RecordBody {
    fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self);
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
    pub data_hash: String,
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RecordContainer {
    /// Ordered collection of records. The last element, if any, is considered
    /// the "head" (i.e. the most recent record).
    pub records: Vec<Record>,
}

impl RecordContainer {
    /// Return a reference to the head (last record) if present.
    pub fn head(&self) -> Option<&Record> {
        self.records.last()
    }

    /// Consume the container and return the head (last record) if present.
    pub fn into_head(self) -> Option<Record> {
        self.records.into_iter().last()
    }

    /// Build an index map of header-hash -> Record for all records in the container.
    /// This preserves the previous ability to obtain a map keyed by header hash.
    pub fn to_index_map(&self) -> IndexMap<Vec<u8>, Record> {
        let mut map: IndexMap<Vec<u8>, Record> = IndexMap::new();
        for rec in &self.records {
            map.insert(rec.header.hash(), rec.clone());
        }
        map
    }
}

impl Validate for RecordContainer {
    fn valid(&self) -> bool {
        // Basic validation placeholder; keep returning true for now to preserve
        // previous behavior. More thorough checks can be added here if desired.
        if self.records.is_empty() {
            return false;
        }
        if self.records[0].body.hash_string() != self.records[0].header.data_hash {
            return false;
        }
        for r in self.records.windows(2).rev() {
            if r[1].body.hash_string() != r[1].header.data_hash {
                return false;
            }
            match r[1].header.prev_ptr.clone() {
                None => return false,
                Some(prev) => {
                    if prev.1 != r[0].header.hash() {
                        return false;
                    }
                }
            }
        }

        true
    }
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
