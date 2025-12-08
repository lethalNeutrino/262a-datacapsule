use crate::capsule::{Metadata, RecordHeader, RecordHeartbeat, Record};
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
}
