use crate::Topic;
use anyhow::Result;
use capsulelib::capsule::structs::{
    Capsule, HashPointer, Record, RecordContainer, RecordHeartbeat, SHA256Hashable,
};
use capsulelib::requests::DataCapsuleRequest;
use futures::{StreamExt, executor::LocalPool, task::LocalSpawnExt};

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

pub struct NetworkCapsuleWriter {
    pub uuid: String,
    pub topic: Topic,
    pub local_capsule: Capsule,
}

impl NetworkCapsuleWriter {
    pub fn append(&mut self, hash_ptrs: Vec<HashPointer>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        let header_hash = self.local_capsule.append(hash_ptrs, data)?;
        let record = self.local_capsule.peek()?;
        let capsule_name = self.local_capsule.gdp_name();

        // Build a RecordContainer: place the single record as the head (last element).
        let record_container = RecordContainer {
            records: vec![record.clone()],
        };

        let request = DataCapsuleRequest::Append {
            reply_to: self.uuid.clone(),
            capsule_name,
            record_container,
        };

        self.topic.publisher.publish(&r2r::std_msgs::msg::String {
            data: serde_json::to_string(&request)?,
        })?;

        Ok(header_hash)
    }
}

pub struct NetworkCapsuleReader {
    pub uuid: String,
    pub connection: Topic,
    pub local_capsule: Capsule,
    pub node: Rc<RefCell<r2r::Node>>,
}

impl NetworkCapsuleReader {
    pub fn read(&mut self, header_hash: Vec<u8>) -> Result<Record> {
        // If we already have the header locally, return it immediately.
        if self.local_capsule.has_header_hash(header_hash.as_ref())? {
            // Capsule::read returns a RecordContainer where the first element is
            // the requested node. Extract that first element rather than the
            // container \"head\" (which represents the latest/heartbeat record).
            let container = self.local_capsule.read(header_hash)?;
            return container
                .records
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("record not found in container"));
        }

        // Prepare the read request.
        let request = DataCapsuleRequest::Read {
            reply_to: self.uuid.clone(),
            capsule_name: self.local_capsule.gdp_name(),
            header_hash,
        };

        // Holder to receive the Record from the spawned task.
        // let record_holder: Rc<RefCell<Option<Record>>> = Rc::new(RefCell::new(None));
        // let holder_for_task = Rc::clone(&record_holder);

        // Take ownership of the subscriber so the spawned local task can drive it.
        // Replace it with an empty placeholder so the Topic stays valid.
        // let real_sub = std::mem::replace(
        //     &mut self.connection.subscriber,
        //     Box::new(futures::stream::empty::<r2r::std_msgs::msg::String>()),
        // );

        // // Create a local pool to run the listener task.
        // let mut pool = LocalPool::new();
        // let spawner = pool.spawner();

        // // Spawn a local task that listens for ReadResponse messages and stores the Record.
        // spawner.spawn_local(async move {
        //     real_sub
        //         .for_each(move |msg| {
        //             match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
        //                 Ok(DataCapsuleRequest::ReadResponse { records }) => {
        //                     // For now take the first record from the container (future: handle multiple)
        //                     if let Some(rec) = records.into_iter().next() {
        //                         *holder_for_task.borrow_mut() = Some(rec);
        //                     }
        //                 }
        //                 Ok(_) => {
        //                     // ignore other messages
        //                 }
        //                 Err(e) => {
        //                     println!("Failed to parse message in read listener: {}", e);
        //                 }
        //             };
        //             futures::future::ready(())
        //         })
        //         .await;
        // })?;

        // Publish the request.
        self.connection
            .publisher
            .publish(&r2r::std_msgs::msg::String {
                data: serde_json::to_string(&request)?,
            })?;

        // The networked/read-via-ROS path is not implemented in this client helper.
        // Previously this returned a placeholder `Record::default()` which can silently
        // hide logic errors. Return an explicit error so callers know this path is
        // unimplemented and can handle it (or rely on local cache).
        Err(anyhow::anyhow!(
            "networked capsule read is not implemented in NetworkCapsuleReader"
        ))
    }

    pub fn latest_heartbeat() -> Result<RecordHeartbeat> {
        todo!()
    }
}
