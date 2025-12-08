use crate::capsule::Metadata;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum DataCapsuleRequest {
    Create { metadata: Metadata },
}
