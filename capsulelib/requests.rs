use crate::capsule::structs::{Metadata, Record, RecordHeader, RecordHeartbeat};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
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
    Get {
        capsule_name: String,
    },
    Read {
        capsule_name: String,
        header_hash: Vec<u8>,
    },
    Ack,
    AppendAck {
        header_hash: String,
    },
    GetResponse {
        metadata: Metadata,
        heartbeat: RecordHeartbeat,
        header: RecordHeader,
    },
    ReadResponse,
}
