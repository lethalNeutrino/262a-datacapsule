use crate::Topic;
use capsulelib::capsule::Capsule;

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
