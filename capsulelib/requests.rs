use crate::capsule::structs::{Metadata, Record, RecordHeader, RecordHeartbeat};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum DataCapsuleRequest {
    Create {
        reply_to: String,
        metadata: Metadata,
        heartbeat: RecordHeartbeat,
        header: RecordHeader,
    },
    Append {
        reply_to: String,
        capsule_name: String,
        record: Record,
    },
    Get {
        reply_to: String,
        capsule_name: String,
    },
    Read {
        reply_to: String,
        capsule_name: String,
        header_hash: Vec<u8>,
    },
    CreateAck,
    AppendAck {
        header_hash: String,
    },
    GetResponse {
        metadata: Metadata,
        heartbeat: RecordHeartbeat,
        header: RecordHeader,
    },
    ReadResponse {
        record: Record,
    },
}
