use aes::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use fjall::{Config, PartitionHandle};
use fjall::{PartitionCreateOptions, PersistMode};
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::{collections::BTreeMap, path::Path};

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

use anyhow::{Result, bail};

struct MissingMetadataKey;

pub type HashPointer = (usize, Vec<u8>);
pub type Metadata = BTreeMap<String, Vec<u8>>;

trait SHA256Hashable {
    fn hash(&self) -> Vec<u8>;
    fn hash_string(&self) -> String {
        self.hash()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
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

impl SHA256Hashable for Metadata {
    fn hash(&self) -> Vec<u8> {
        // compute SHA256 hash of metadata deterministically (BTreeMap is ordered)
        let mut hasher = Sha256::new();
        for (k, v) in self {
            hasher.update(k.as_bytes());
            hasher.update(v);
        }
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub header: RecordHeader,
    pub heartbeat: RecordHeartbeat,
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
pub struct Capsule<P>
where
    P: AsRef<Path> + Default,
{
    metadata: BTreeMap<String, Vec<u8>>,
    symmetric_key: Vec<u8>,
    sign_key: Option<SigningKey>,
    last_seqno: usize,
    last_pointer: HashPointer,
    store_path: P,
    keyspace: Option<PartitionHandle>,
}

impl<P> Capsule<P>
where
    P: AsRef<Path> + Default,
{
    #[inline]
    pub fn gdp_name(&self) -> String {
        self.metadata.hash_string()
    }

    pub fn create(
        kv_store_path: P,
        metadata: BTreeMap<String, Vec<u8>>,
        sign_key: SigningKey,
        symmetric_key: Vec<u8>,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        if !metadata.contains_key(&String::from("verify_key")) {
            bail!("metadata must contain 'verify_key'");
        }

        let keyspace = Config::new(&kv_store_path)
            .max_write_buffer_size(128 * 1024 * 1024)
            .open()?;
        // keyspace.set_max_memtable_size(32 * 1_024 * 1_024);
        // Config::new().
        keyspace.persist(PersistMode::SyncAll)?;

        // Create a partition of the keyspace for a DataCapsule
        let gdp_name: &str = &metadata.hash_string();
        let items = keyspace.open_partition(
            gdp_name,
            PartitionCreateOptions::default().max_memtable_size(64 * 1024 * 1024),
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
            header_hash: metadata_header_hash,
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
        let mut metadata_bytes = serde_json::to_vec(&metadata)?;
        let mut cipher = Aes128Ctr64LE::new(symmetric_key.as_slice().into(), &iv.into());
        cipher.apply_keystream(&mut metadata_bytes);

        // Create initial record + insert into Fjall
        let metadata_record = Record {
            header: metadata_header.clone(),
            heartbeat: metadata_heartbeat,
            body: metadata_bytes,
        };

        items.insert(gdp_name, serde_json::to_vec(&metadata_record)?)?;

        // Return created capsule
        Ok(Capsule {
            metadata: metadata.clone(),
            store_path: kv_store_path,
            sign_key: Some(sign_key),
            symmetric_key,
            last_pointer: (0, metadata_header.hash()),
            keyspace: Some(items),
            ..Default::default()
        })
    }

    pub fn get(kv_store_path: P, gdp_name: String, symmetric_key: Vec<u8>) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let keyspace = Config::new(kv_store_path).open()?;
        let items = keyspace.open_partition(&gdp_name, PartitionCreateOptions::default())?;
        let metadata_bytes_vec = items
            .get(&gdp_name)?
            .expect("The GDP name provided does not map to a capsule in the provided database.")
            .to_vec();

        let metadata_bytes = metadata_bytes_vec.as_slice();
        let metadata: BTreeMap<String, Vec<u8>> = serde_json::from_slice(metadata_bytes)?;

        Ok(Capsule {
            metadata: metadata.clone(),
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
        // JONAH LET US KNOW IF THIS IS TREAM
        let iv: [u8; 16] = [(self.last_seqno + 1).to_le_bytes(), [0x0_u8; 8]]
            .concat()
            .try_into()
            .unwrap();
        // let mut data_bytes = serde_json::to_vec(&data)?;
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
            heartbeat,
            body: data,
        };

        // let keyspace = Config::new(&self.store_path).open()?;
        // let items =
        //     keyspace.open_partition(self.gdp_name().as_str(), PartitionCreateOptions::default())?;
        let items = self.keyspace.as_ref().unwrap();

        items.insert(&header_hash, serde_json::to_vec(&record)?)?;

        // Update internal state
        self.last_seqno += 1;
        self.last_pointer = (header.seqno, header.hash());
        Ok(header_hash)
    }

    pub fn read(&self, header_hash: Vec<u8>) -> Result<Record> {
        let keyspace = Config::new(&self.store_path).open()?;
        let items =
            keyspace.open_partition(self.gdp_name().as_str(), PartitionCreateOptions::default())?;

        let record_bytes = items
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
}
