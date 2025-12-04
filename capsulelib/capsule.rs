type Metadata<'a> = HashMap<String, &'a [u8]>;
type HashPointer<'a> = (usize, &'a [u8]);

struct Datacapsule<'a> {
    metadata: Metadata<'a>,
}

struct User {
    name: String,
    public_key: &'a [u8],
    private_key: &'a [u8],
}

struct Record<'a> {
    header: RecordHeader<'a>,
    heartbeat: RecordHeartbeat<'a>,
    body: &'a [u8],
}

struct RecordHeader<'a> {
    seqno: usize,
    GDPname: &'a [u8],
    prev_ptr: HashPointer<'a>,
    hash_ptrs: Vec<HashPointer<'a>>,
}

struct RecordHeartbeat<'a> {
    seqno: usize,
    GDPname: &'a [u8],
    hash_ptr: HashPointer<'a>,
    signature: &'a [u8],
}

struct RecordContainer<'a> {
    records: Vec<(Option<RecordHeartbeat<'a>>, RecordHeader<'a>, &'a [u8])>,
}

pub struct Capsule<'a> {
    metadata: Metadata<'a>,

    GDPname: &'a [u8],
}
