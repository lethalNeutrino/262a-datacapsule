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
    Capsule, CapsuleSnapshot, HashPointer, Metadata, Record, RecordHeader, RecordHeartbeat,
    RecordHeartbeatData, SHA256Hashable,
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
        debug!("metadata is {:?}", &metadata_record);
        debug!("inserting metadata at {:?}", &metadata_header_hash);
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
        keyspace.persist(PersistMode::SyncAll)?;

        Ok(Capsule {
            symmetric_key,
            metadata,
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
            data_hash: metadata.hash_string(),
        };

        let metadata_header_hash = metadata_header.hash();

        // If a metadata record already exists under the metadata header hash,
        // attempt to reconstruct the capsule from a persisted snapshot if present.
        if let Some(_) = items.get(&metadata_header_hash)? {
            // Try to read a snapshot partition/key. We store snapshots in a dedicated partition.
            let snapshots = keyspace.open_partition(
                "capsule_snapshots",
                PartitionCreateOptions::default().max_memtable_size(8 * 1024 * 1024),
            )?;
            if let Some(snapshot_bytes) = snapshots.get(gdp_name.as_bytes())? {
                let snapshot: CapsuleSnapshot = serde_json::from_slice(&snapshot_bytes)?;
                // Reopen partitions and reconstruct the Capsule using snapshot info
                let mut existing = Capsule::get(
                    kv_store_path,
                    gdp_name.to_string(),
                    snapshot.symmetric_key.clone(),
                )?;
                existing.sign_key = Some(sign_key);
                existing.snapshot_key = Some(gdp_name.as_bytes().to_vec());
                return Ok(existing);
            }
            // If no snapshot present, fall back to `get` behavior
            let mut existing =
                Capsule::get(kv_store_path, gdp_name.to_string(), symmetric_key.clone())?;
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

        // Persist a snapshot of the capsule state into a global snapshots partition
        // so the capsule can be reconstructed quickly by `get`.
        let snapshots = keyspace.open_partition(
            "capsule_snapshots",
            PartitionCreateOptions::default().max_memtable_size(8 * 1024 * 1024),
        )?;
        let snapshot = CapsuleSnapshot {
            metadata: metadata.clone(),
            symmetric_key: symmetric_key.clone(),
            last_seqno: 0,
            last_pointer: (0, metadata_header.hash()),
        };
        partition_insert(
            &snapshots,
            gdp_name.as_bytes(),
            serde_json::to_vec(&snapshot)?,
        )?;

        keyspace.persist(PersistMode::SyncAll)?;
        // Return created capsule (attach snapshot_key so future appends update it)
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
            snapshot_key: Some(gdp_name.as_bytes().to_vec()),
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

        // Attempt to read a persisted snapshot first; if present reconstruct the capsule quickly.
        let snapshots = keyspace.open_partition(
            "capsule_snapshots",
            PartitionCreateOptions::default().max_memtable_size(8 * 1024 * 1024),
        )?;
        if let Some(snap_bytes) = snapshots.get(gdp_name.as_bytes())? {
            let snap: CapsuleSnapshot = serde_json::from_slice(&snap_bytes)?;
            // Open partitions for the capsule
            let items = keyspace.open_partition(
                gdp_name.as_str(),
                PartitionCreateOptions::default().max_memtable_size(64 * 1024 * 1024),
            )?;
            let heartbeat_partition_name = format!("{}-heartbeats", gdp_name.as_str());
            let heartbeat_items = keyspace.open_partition(
                heartbeat_partition_name.as_str(),
                PartitionCreateOptions::default().max_memtable_size(32 * 1024 * 1024),
            )?;
            let seqno_partition_name = format!("{}-seqnos", gdp_name.as_str());
            let seqno_items = keyspace.open_partition(
                seqno_partition_name.as_str(),
                PartitionCreateOptions::default().max_memtable_size(16 * 1024 * 1024),
            )?;

            return Ok(Capsule {
                record_partition: Some(items),
                heartbeat_partition: Some(heartbeat_items),
                seqno_partition: Some(seqno_items),
                metadata: snap.metadata,
                symmetric_key: snap.symmetric_key,
                last_seqno: snap.last_seqno,
                last_pointer: snap.last_pointer,
                keyspace: Some(keyspace),
                snapshot_key: Some(gdp_name.as_bytes().to_vec()),
                ..Default::default()
            });
        }

        // Fallback: reconstruct metadata by reading the metadata record stored at seqno 0.
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
            data_hash: gdp_name.clone(),
        };
        let metadata_header_hash = metadata_header.hash();
        debug!("looking for metadata at {:?}", &metadata_header_hash);

        let record_data = items.get(&metadata_header_hash)?.unwrap();
        let record: Record = serde_json::from_slice(&record_data)?;

        let mut body = record.body;

        let iv = [0x0; 16];
        let mut cipher = Aes128Ctr64LE::new(symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut body);

        let metadata: Metadata = serde_json::from_slice(&body)?;

        // If no snapshot existed, default last_seqno/last_pointer to metadata (seqno 0)
        Ok(Capsule {
            record_partition: Some(items),
            heartbeat_partition: Some(heartbeat_items),
            seqno_partition: Some(seqno_items),
            metadata,
            symmetric_key,
            last_seqno: 0,
            last_pointer: (0, metadata_header_hash),
            keyspace: Some(keyspace),
            ..Default::default()
        })
    }

    fn derive_record_iv(gdp_name: &str, seqno: usize) -> [u8; 16] {
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

        // Create Header
        let header = RecordHeader {
            seqno: self.last_seqno + 1,
            gdp_name: self.gdp_name(),
            hash_ptrs,
            prev_ptr: Some(self.last_pointer.clone()),
            data_hash: data.clone().hash_string(),
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

        // Update the persisted snapshot so later `get` calls can reconstruct quickly.
        if let Some(ks) = &self.keyspace {
            let snapshots = ks.open_partition(
                "capsule_snapshots",
                PartitionCreateOptions::default().max_memtable_size(8 * 1024 * 1024),
            )?;
            let snapshot = CapsuleSnapshot {
                metadata: self.metadata.clone(),
                symmetric_key: self.symmetric_key.clone(),
                last_seqno: self.last_seqno,
                last_pointer: self.last_pointer.clone(),
            };
            partition_insert(
                &snapshots,
                self.gdp_name().as_bytes(),
                serde_json::to_vec(&snapshot)?,
            )?;
        }

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

    /// Check whether a record with the given header hash exists in this capsule's record partition.
    /// Returns `Ok(true)` if present, `Ok(false)` if absent, or an `Err` if the partition is not opened
    /// or if the underlying store operation fails.
    pub fn has_header_hash(&self, header_hash: &[u8]) -> Result<bool> {
        let items = self
            .record_partition
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("record partition not opened"))?;
        // `get` returns an Option; propagate any underlying error from the keyspace API.
        Ok(items.get(header_hash)?.is_some())
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
