use crate::Topic;
use capsulelib::Capsule;

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
