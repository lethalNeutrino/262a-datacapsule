use crate::Topic;
use anyhow::Result;
use capsulelib::{Capsule, Metadata};
use futures::{Stream, executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile, WrappedTypesupport};
use std::collections::HashMap;

struct NetworkCapsuleWriter
// where
//     S: WrappedTypesupport + 'static,
//     P: WrappedTypesupport + 'static,
{
    connection: Topic,
    local_capsule: Capsule,
}

struct NetworkCapsuleReader
// where
//     S: WrappedTypesupport + 'static,
//     P: WrappedTypesupport + 'static
{
    connection: Topic,
    local_capsule: Capsule,
}
