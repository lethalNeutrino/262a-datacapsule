pub mod structs;
mod utils;
use aes::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use fjall::Config;
use fjall::{PartitionCreateOptions, PersistMode};
use log::debug;
use sha2::{Digest, Sha256};
use std::path::Path;
use structs::{
    Capsule, HashPointer, Metadata, Record, RecordHeader, RecordHeartbeat, RecordHeartbeatData,
    SHA256Hashable,
};
use utils::{
    init_partitions, partition_insert, sign_heartbeat_with_key, verify_heartbeat_with_metadata,
};

pub type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

use anyhow::{Result, bail};

impl Capsule {
    /// Server-side function to open a container upon getting a create request
    pub fn open<P: AsRef<Path>>(
        kv_store_path: P,
        metadata: Metadata,
        metadata_header: RecordHeader,
        metadata_heartbeat: RecordHeartbeat,
        symmetric_key: Vec<u8>,
    ) -> Result<Self> {
        // Implement the logic to open a capsule from storage
        // This could involve reading metadata, keys, and other necessary data
        // For now, we'll just return a default capsule
        if !metadata.0.contains_key(&String::from("verify_key")) {
            bail!("metadata must contain 'verify_key'");
        }

        let keyspace = Config::new(&kv_store_path)
            .max_write_buffer_size(128 * 1024 * 1024)
            .open()?;
        keyspace.persist(PersistMode::SyncAll)?;

        // Create a partition of the keyspace for a DataCapsule
        let gdp_name: &str = &metadata.hash_string();
        let (items, heartbeat_items, seqno_items) = init_partitions(&keyspace, gdp_name)?;

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
        let metadata_header_hash = metadata_header.hash();

        // Store metadata record in the capsule partition under the metadata header hash key,
        // and also store the heartbeat in the heartbeat partition under the same key.
        partition_insert(
            &items,
            &metadata_header_hash,
            serde_json::to_vec(&metadata_record)?,
        )?;
        partition_insert(
            &heartbeat_items,
            &metadata_header_hash,
            serde_json::to_vec(&metadata_heartbeat)?,
        )?;

        // Store seqno -> header mapping for seqno 0
        let seq0_key = 0usize.to_be_bytes().to_vec();
        partition_insert(&seqno_items, &seq0_key, metadata_header_hash.clone())?;

        Ok(Capsule {
            symmetric_key,
            keyspace: Some(keyspace),
            record_partition: Some(items),
            heartbeat_partition: Some(heartbeat_items),
            seqno_partition: Some(seqno_items),
            last_seqno: 0,
            ..Default::default()
        })
    }

    /// Server-side function to place a capsule into a specified location
    pub fn place(
        &mut self,
        header: RecordHeader,
        heartbeat: RecordHeartbeat,
        _data: Vec<u8>,
    ) -> Result<()> {
        // Verify heartbeat signature using helper (reads verify_key from metadata)
        verify_heartbeat_with_metadata(&self.metadata, &heartbeat.data, &heartbeat.signature)?;

        // Insert heartbeat into the per-capsule heartbeat partition at the same key
        // used for the record (hash of header)
        let header_hash = header.hash();
        self.insert_into_heartbeat_partition_opt(&header_hash, serde_json::to_vec(&heartbeat)?)?;

        if header.seqno > self.last_seqno {
            self.last_seqno = header.seqno;
            self.last_pointer = (header.seqno, header.hash())
        }

        // Return created capsule
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
        let (items, heartbeat_items, seqno_items) = init_partitions(&keyspace, gdp_name)?;

        // Create Header (will be used to check for existing capsule)
        let metadata_header = RecordHeader {
            seqno: 0,
            gdp_name: gdp_name.to_string(),
            prev_ptr: None,
            hash_ptrs: Vec::new(),
        };

        let metadata_header_hash = metadata_header.hash();

        // If a metadata record already exists for this header hash, treat the capsule
        // as existing and return the opened capsule (attach the signing key).
        if let Some(_) = items.get(&metadata_header_hash)? {
            // Capsule already exists on disk; open it via `get` and attach the sign_key.
            let mut existing = Capsule::get(kv_store_path, gdp_name.to_string(), symmetric_key)?;
            existing.sign_key = Some(sign_key);
            return Ok(existing);
        }

        // Create Heartbeat (new capsule path)
        let metadata_heartbeat_data = RecordHeartbeatData {
            seqno: 0,
            gdp_name: gdp_name.to_string(),
            header_hash: metadata_header_hash.clone(),
        };

        // Sign the metadata heartbeat (use helper)
        let heartbeat_data_signature =
            sign_heartbeat_with_key(&sign_key, &metadata_heartbeat_data)?;

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

        // Store metadata record in the capsule partition under the metadata header hash key,
        // and also store the heartbeat in the heartbeat partition under the same key.
        partition_insert(
            &items,
            &metadata_header_hash,
            serde_json::to_vec(&metadata_record)?,
        )?;
        partition_insert(
            &heartbeat_items,
            &metadata_header_hash,
            serde_json::to_vec(&metadata_heartbeat)?,
        )?;

        // Store seqno -> header mapping for seqno 0
        let seq0_key = 0usize.to_be_bytes().to_vec();
        partition_insert(&seqno_items, &seq0_key, metadata_header_hash.clone())?;

        // Return created capsule
        Ok(Capsule {
            metadata: metadata.clone(),
            sign_key: Some(sign_key),
            symmetric_key,
            last_seqno: 0,
            last_pointer: (0, metadata_header.hash()),
            keyspace: Some(keyspace),
            record_partition: Some(items),
            heartbeat_partition: Some(heartbeat_items),
            seqno_partition: Some(seqno_items),
        })
    }

    pub fn get<P: AsRef<Path>>(
        kv_store_path: P,
        gdp_name: String,
        symmetric_key: Vec<u8>,
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

        // Open corresponding seqno partition for this capsule
        let seqno_partition_name = format!("{}-seqnos", gdp_name.as_str());
        let seqno_items = keyspace.open_partition(
            seqno_partition_name.as_str(),
            PartitionCreateOptions::default().max_memtable_size(16 * 1024 * 1024),
        )?;

        // Compute metadata header hash (seqno 0, gdp_name, no prev/hash_ptrs)
        let metadata_header = RecordHeader {
            seqno: 0,
            gdp_name: gdp_name.clone(),
            prev_ptr: None,
            hash_ptrs: Vec::new(),
        };
        let metadata_header_hash = metadata_header.hash();

        let record_data = items.get(&metadata_header_hash)?.unwrap();
        let record: Record = serde_json::from_slice(&record_data)?;

        let mut body = record.body;

        let iv = [0x0; 16];
        let mut cipher = Aes128Ctr64LE::new(symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut body);

        let metadata: Metadata = serde_json::from_slice(&body)?;

        Ok(Capsule {
            record_partition: Some(items),
            heartbeat_partition: Some(heartbeat_items),
            seqno_partition: Some(seqno_items),
            metadata,
            symmetric_key,
            last_seqno: 0,
            last_pointer: (0, metadata_header_hash.clone()),
            ..Default::default()
        })
    }

    fn derive_record_iv(gdp_name: &str, seqno: usize) -> [u8; 16] {
        // Derive a deterministic IV for record encryption/decryption.
        // This mirrors the previous append behavior (sha256 over the first 32 bytes
        // of the gdp_name and the seqno in little-endian) so both writer and reader
        // derive the same IV.
        let mut hasher = Sha256::new();
        let name_bytes = gdp_name.as_bytes();
        let to_hash = if name_bytes.len() >= 32 {
            &name_bytes[..32]
        } else {
            name_bytes
        };
        hasher.update(to_hash);
        hasher.update(seqno.to_le_bytes());
        hasher.finalize()[..16].try_into().unwrap()
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

        // Sign Heartbeat (use helper)
        let heartbeat_signature = sign_heartbeat_with_key(
            self.sign_key
                .as_ref()
                .expect("append must be called by a writer"),
            &heartbeat_data,
        )?;

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
        let iv: [u8; 16] = Self::derive_record_iv(&self.gdp_name(), self.last_seqno + 1);
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

        let items = self.record_partition.as_ref().unwrap();

        // Store the record under the header hash
        partition_insert(items, &header_hash, serde_json::to_vec(&record)?)?;

        // Also store the heartbeat in the heartbeat partition at the same key (optional)
        self.insert_into_heartbeat_partition_opt(&header_hash, serde_json::to_vec(&heartbeat)?)?;

        // Also store seqno -> header_hash mapping (optional)
        self.insert_into_seqno_partition_opt(header.seqno, header_hash.clone())?;

        // Update internal state
        self.last_seqno += 1;
        self.last_pointer = (header.seqno, header.hash());
        Ok(header_hash)
    }

    pub fn read(&self, header_hash: Vec<u8>) -> Result<Record> {
        let record_bytes = self
            .record_partition
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

        let iv: [u8; 16] =
            Self::derive_record_iv(record.header.gdp_name.as_str(), record.header.seqno);

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

        // Verify heartbeat signature (if present) using the capsule's stored verify_key.
        if let Some(hb) = &record.heartbeat {
            // Verify heartbeat signature using helper (reads verify_key from metadata)
            verify_heartbeat_with_metadata(&self.metadata, &hb.data, &hb.signature)?;
        }

        Ok(record)
    }
    pub fn peek(&self) -> Result<Record> {
        self.read(self.last_pointer.1.clone())
    }
}

/// Feature-gated unchecked utilities live in their own module. This keeps the main
/// implementation free of benchmarking/testing helpers unless the `unchecked` feature
/// is explicitly enabled.
#[cfg(feature = "unchecked")]
#[path = "unchecked.rs"]
pub mod unchecked;
