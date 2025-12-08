use crate::capsule::structs::{Metadata, Record, RecordHeader, RecordHeartbeat};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum DataCapsuleRequest {
    Create {
        metadata: Metadata,
        heartbeat: RecordHeartbeat,
        header: RecordHeader,
    },
    Append {
        capsule_name: String,
        record: Record,
    },
    Read {
        capsule_name: String,
        header_hash: Vec<u8>,
    },
    Ack,
}
