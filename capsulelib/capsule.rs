use aes::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use fjall::{Config, PartitionHandle};
use fjall::{PartitionCreateOptions, PersistMode};
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

use anyhow::{Result, bail};

struct MissingMetadataKey;

pub type HashPointer = (usize, Vec<u8>);

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Metadata(pub BTreeMap<String, Vec<u8>>);

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub header: RecordHeader,
    pub heartbeat: Option<RecordHeartbeat>,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Default)]
pub struct Capsule {
    metadata: Metadata,
    symmetric_key: Vec<u8>,
    sign_key: Option<SigningKey>,
    last_seqno: usize,
    last_pointer: HashPointer,
    keyspace: Option<PartitionHandle>,
    // Per-capsule heartbeat partition
    heartbeat_keyspace: Option<PartitionHandle>,
}

impl Capsule {
    #[inline]
    pub fn gdp_name(&self) -> String {
        self.metadata.hash_string()
    }

    pub fn place(
        &self,
        header: RecordHeader,
        heartbeat: RecordHeartbeat,
        _data: Vec<u8>,
    ) -> Result<()> {
        // Ensure metadata contains the verify key
        let vk_bytes = self
            .metadata
            .0
            .get("verify_key")
            .ok_or_else(|| anyhow::anyhow!("metadata must contain 'verify_key'"))?;

        // Construct a VerifyingKey from the stored bytes (ensure it's 32 bytes)
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &vk_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("verify_key must be 32 bytes"))?
        )?;

        // Serialize the heartbeat data to the same form that was signed
        let msg = serde_json::to_vec(&heartbeat.data)?;

        // Verify the signature on the heartbeat.data
        if let Err(e) = ed25519_dalek::Verifier::verify(&verifying_key, &msg, &heartbeat.signature)
        {
            bail!("invalid heartbeat signature: {}", e);
        }

        // Insert heartbeat into the per-capsule heartbeat partition at the same key
        // used for the record (hash of header)
        if let Some(hb_space) = &self.heartbeat_keyspace {
            let header_hash = header.hash();
            hb_space.insert(&header_hash, serde_json::to_vec(&heartbeat)?)?;
        }

        Ok(())
    }

    pub fn create<P: AsRef<Path>>(
        kv_store_path: P,
        metadata: Metadata,
        sign_key: SigningKey,
        symmetric_key: Vec<u8>,
    ) -> Result<Self> {
        if !metadata.0.contains_key(&String::from("verify_key")) {
            bail!("metadata must contain 'verify_key'");
        }

        let keyspace = Config::new(&kv_store_path)
            .max_write_buffer_size(128 * 1024 * 1024)
            .open()?;
        keyspace.persist(PersistMode::SyncAll)?;

        // Create a partition of the keyspace for a DataCapsule
        let gdp_name: &str = &metadata.hash_string();
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

        // Create Header
        let metadata_header = RecordHeader {
            seqno: 0,
            gdp_name: gdp_name.to_string(),
            prev_ptr: None,
            hash_ptrs: Vec::new(),
        };

        let metadata_header_hash = metadata_header.hash();

        // Create Heartbeat
        let metadata_heartbeat_data = RecordHeartbeatData {
            seqno: 0,
            gdp_name: gdp_name.to_string(),
            header_hash: metadata_header_hash.clone(),
        };

        // Sign the metadata heartbeat
        let heartbeat_data_signature =
            sign_key.sign(serde_json::to_vec(&metadata_heartbeat_data)?.as_ref());

        let metadata_heartbeat = RecordHeartbeat {
            data: metadata_heartbeat_data,
            signature: heartbeat_data_signature,
        };

        // Encrypt metadata
        let iv = [0x0; 16];
        let mut metadata_bytes = serde_json::to_vec(&metadata.0)?;
        let mut cipher = Aes128Ctr64LE::new(symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut metadata_bytes);

        // Create initial record + insert into Fjall
        let metadata_record = Record {
            header: metadata_header.clone(),
            heartbeat: Some(metadata_heartbeat.clone()),
            body: metadata_bytes,
        };

        // Store metadata record in the capsule partition under the capsule name key,
        // and also store the heartbeat in the heartbeat partition under the same key.
        // Additionally store both under the metadata header hash so they can be looked
        // up by header hash as well.
        items.insert(gdp_name, serde_json::to_vec(&metadata_record)?)?;
        heartbeat_items.insert(gdp_name, serde_json::to_vec(&metadata_heartbeat)?)?;
        // also store under metadata header hash
        items.insert(&metadata_header_hash, serde_json::to_vec(&metadata_record)?)?;
        heartbeat_items.insert(&metadata_header_hash, serde_json::to_vec(&metadata_heartbeat)?)?;

        // Return created capsule
        Ok(Capsule {
            metadata: metadata.clone(),
            sign_key: Some(sign_key),
            symmetric_key,
            last_pointer: (0, metadata_header.hash()),
            keyspace: Some(items),
            heartbeat_keyspace: Some(heartbeat_items),
            ..Default::default()
        })
    }

    pub fn get<P: AsRef<Path>>(
        kv_store_path: P,
        gdp_name: String,
        symmetric_key: Vec<u8>,
        sign_key: SigningKey,
    ) -> Result<Self> {
        let keyspace = Config::new(&kv_store_path)
            .max_write_buffer_size(128 * 1024 * 1024)
            .open()?;
        keyspace.persist(PersistMode::SyncAll)?;

        // Open capsule partition
        let items = keyspace.open_partition(
            gdp_name.as_str(),
            PartitionCreateOptions::default().max_memtable_size(64 * 1024 * 1024),
        )?;

        // Open corresponding heartbeat partition for this capsule
        let heartbeat_partition_name = format!("{}-heartbeats", gdp_name.as_str());
        let heartbeat_items = keyspace.open_partition(
            heartbeat_partition_name.as_str(),
            PartitionCreateOptions::default().max_memtable_size(32 * 1024 * 1024),
        )?;

        // Read the metadata record to reconstruct capsule metadata
        let record_data = items.get(gdp_name)?.unwrap();
        let record: Record = serde_json::from_slice(&record_data)?;

        let mut body = record.body;

        let iv = [0x0; 16];
        let mut cipher = Aes128Ctr64LE::new(symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut body);

        let metadata: Metadata = serde_json::from_slice(&body)?;

        Ok(Capsule {
            keyspace: Some(items),
            heartbeat_keyspace: Some(heartbeat_items),
            metadata,
            sign_key: Some(sign_key),
            symmetric_key,
            ..Default::default()
        })
    }

    pub fn append(&mut self, hash_ptrs: Vec<HashPointer>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        // Create Header
        let header = RecordHeader {
            seqno: self.last_seqno + 1,
            gdp_name: self.gdp_name(),
            hash_ptrs,
            prev_ptr: Some(self.last_pointer.clone()),
        };

        let header_hash = header.hash();

        // Create Heartbeat
        let heartbeat_data = RecordHeartbeatData {
            seqno: self.last_seqno + 1,
            gdp_name: self.gdp_name(),
            header_hash: header_hash.clone(),
        };

        // Sign Heartbeat
        let heartbeat_signature = self
            .sign_key
            .as_ref()
            .expect("append must be called by a writer")
            .sign(serde_json::to_vec(&heartbeat_data)?.as_ref());

        let heartbeat = RecordHeartbeat {
            data: heartbeat_data,
            signature: heartbeat_signature,
        };

        log::debug!(
            "Plaintext data: {:?}",
            data.iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );

        // Encrypt Data
        let mut hasher = Sha256::new();
        hasher.update(self.gdp_name()[..32].as_bytes());
        hasher.update((self.last_seqno + 1).to_le_bytes());
        let iv: [u8; 16] = hasher.finalize()[..16].try_into().unwrap();
        log::debug!(
            "Serialized data: {:?}",
            data.iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );
        let mut cipher = Aes128Ctr64LE::new(self.symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut data);
        debug!("Encryption Key: {:?}", self.symmetric_key);
        debug!("Encryption IV: {:?}", iv);

        log::debug!(
            "Encrypted data: {:?}",
            data.iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );

        let record = Record {
            header: header.clone(),
            heartbeat: Some(heartbeat.clone()),
            body: data,
        };

        let items = self.keyspace.as_ref().unwrap();

        // Store the record under the header hash
        items.insert(&header_hash, serde_json::to_vec(&record)?)?;

        // Also store the heartbeat in the heartbeat partition at the same key
        if let Some(hb_space) = &self.heartbeat_keyspace {
            hb_space.insert(&header_hash, serde_json::to_vec(&heartbeat)?)?;
        }

        // Update internal state
        self.last_seqno += 1;
        self.last_pointer = (header.seqno, header.hash());
        Ok(header_hash)
    }

    pub fn read(&self, header_hash: Vec<u8>) -> Result<Record> {
        let record_bytes = self
            .keyspace
            .clone()
            .unwrap()
            .get(&header_hash)
            .unwrap()
            .unwrap_or_else(|| {
                panic!(
                    "Unable to find corresponding record for hash {:?}",
                    header_hash
                )
            })
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

        debug!("Decryption Key: {:?}", self.symmetric_key);
        debug!("Decryption IV: {:?}", iv);

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

        Ok(record)
    }

    pub fn peek(&self) -> Result<Record> {
        self.read(self.last_pointer.1.clone())
    }

    pub fn read_heartbeat(&self, header_hash: Vec<u8>) -> Result<RecordHeartbeat> {
        let hb_bytes = self
            .heartbeat_keyspace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("heartbeat partition not opened"))?
            .get(&header_hash)?
            .ok_or_else(|| anyhow::anyhow!("heartbeat not found for header hash"))?;
        let hb: RecordHeartbeat = serde_json::from_slice(&hb_bytes)?;
        Ok(hb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn heartbeats_traversal() -> anyhow::Result<()> {
        // unique store path per test run
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut store_path = std::env::temp_dir();
        store_path.push(format!("datacapsule_test_{}", nanos));
        let kv_store = store_path.as_path();

        // create signing key and metadata
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key();
        let mut md = BTreeMap::new();
        md.insert(String::from("verify_key"), vk.to_bytes().to_vec());
        let metadata = Metadata(md);

        let symmetric_key = (0..16).collect::<Vec<u8>>();

        let mut capsule = Capsule::create(kv_store, metadata, signing_key, symmetric_key.clone())?;

        // append several records
        for i in 1..=4 {
            let data = format!("payload {}", i).into_bytes();
            capsule.append(vec![], data)?;
        }

        // peek root and traverse back via prev_ptr verifying heartbeats match
        let root = capsule.peek()?;
        let mut current_hash = root.header.hash();

        loop {
            let record = capsule.read(current_hash.clone())?;
            let hb = capsule.read_heartbeat(current_hash.clone())?;
            let rec_hb_ser = serde_json::to_vec(&record.heartbeat.clone().unwrap())?;
            let hb_ser = serde_json::to_vec(&hb)?;
            assert_eq!(rec_hb_ser, hb_ser);

            if let Some(prev) = record.header.prev_ptr {
                current_hash = prev.1;
            } else {
                break;
            }
        }

        Ok(())
    }
}
