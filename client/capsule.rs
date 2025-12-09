use crate::Topic;
use anyhow::Result;
use capsulelib::capsule::structs::{Capsule, HashPointer};
use capsulelib::requests::DataCapsuleRequest;

pub struct NetworkCapsuleWriter {
    pub connection: Topic,
    pub local_capsule: Capsule,
}

impl NetworkCapsuleWriter {
    pub fn append(&mut self, hash_ptrs: Vec<HashPointer>, mut data: Vec<u8>) -> Result<()> {
        let header_hash = self.local_capsule.append(hash_ptrs, data)?;
        let record = self.local_capsule.peek()?;
        let capsule_name = self.local_capsule.gdp_name();
        let request = DataCapsuleRequest::Append {
            capsule_name,
            record,
        };

        self.connection
            .publisher
            .publish(&r2r::std_msgs::msg::String {
                data: serde_json::to_string(&request)?,
            })?;

        Ok(())
    }
}

pub struct NetworkCapsuleReader {
    pub connection: Topic,
    pub local_capsule: Capsule,
}

impl NetworkCapsuleReader {
    pub fn latest_heartbeat() -> Result<Heartbeat> {}
}
