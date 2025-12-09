use crate::Topic;
use anyhow::Result;
use capsulelib::capsule::structs::{Capsule, HashPointer, Record, RecordHeartbeat};
use capsulelib::requests::DataCapsuleRequest;

pub struct NetworkCapsuleWriter {
    pub uuid: String,
    pub topic: Topic,
    pub local_capsule: Capsule,
}

impl NetworkCapsuleWriter {
    pub fn append(&mut self, hash_ptrs: Vec<HashPointer>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        let header_hash = self.local_capsule.append(hash_ptrs, data)?;
        let record = self.local_capsule.peek()?;
        let capsule_name = self.local_capsule.gdp_name();
        let request = DataCapsuleRequest::Append {
            reply_to: self.uuid.clone(),
            capsule_name,
            record,
        };

        self.topic.publisher.publish(&r2r::std_msgs::msg::String {
            data: serde_json::to_string(&request)?,
        })?;

        Ok(header_hash)
    }
}

pub struct NetworkCapsuleReader {
    pub uuid: String,
    pub connection: Topic,
    pub local_capsule: Capsule,
}

impl NetworkCapsuleReader {
    pub fn read(&mut self, header_hash: Vec<u8>) -> Result<Record> {
        let record = self.local_capsule.read(header_hash)?;
        let request = DataCapsuleRequest::Read {
            reply_to: self.uuid.clone(),
            capsule_name: self.local_capsule.gdp_name(),
            header_hash,
        };

        // self.connection.publisher
        Ok(record)
    }

    pub fn latest_heartbeat() -> Result<RecordHeartbeat> {
        todo!()
    }
}
