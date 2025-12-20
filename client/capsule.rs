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

    /// Persist a batch of records locally (signing the last heartbeat) and publish
    /// the same RecordContainer to the network so servers can persist the records too.
    /// Returns the header hashes produced by the local append_container call.
    pub fn append_container_network(
        &mut self,
        mut container: RecordContainer,
    ) -> Result<Vec<Vec<u8>>> {
        // Persist locally first, which will sign the heartbeat of the last record
        // and store all records in the capsule partition.
        let returned_hashes = self.local_capsule.append_container(container.clone())?;

        // Publish the same container to the network so servers can persist it.
        let request = DataCapsuleRequest::Append {
            reply_to: self.uuid.clone(),
            capsule_name: self.local_capsule.gdp_name(),
            record_container: container,
        };

        self.topic.publisher.publish(&r2r::std_msgs::msg::String {
            data: serde_json::to_string(&request)?,
        })?;

        Ok(returned_hashes)
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
        let record_holder: Rc<RefCell<Option<Record>>> = Rc::new(RefCell::new(None));
        let holder_for_task = Rc::clone(&record_holder);

        // Take ownership of the subscriber so the spawned local task can drive it.
        // Replace it with an empty placeholder so the Topic stays valid.
        let real_sub = std::mem::replace(
            &mut self.connection.subscriber,
            Box::new(futures::stream::empty::<r2r::std_msgs::msg::String>()),
        );

        // Create a local pool to run the listener task.
        let mut pool = LocalPool::new();
        let spawner = pool.spawner();

        // Spawn a local task that listens for ReadResponse messages and stores the Record.
        spawner.spawn_local(async move {
            real_sub
                .for_each(move |msg| {
                    match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                        Ok(DataCapsuleRequest::ReadResponse { record_container }) => {
                            // For now take the first record from the container (future: handle multiple)
                            *holder_for_task.borrow_mut() =
                                Some(record_container.records[0].clone());
                            // if let Some(rec) = records.into_iter().next() {
                            //     *holder_for_task.borrow_mut() = Some(rec);
                            // }
                        }
                        Ok(_) => {
                            // ignore other messages
                        }
                        Err(e) => {
                            println!("Failed to parse message in read listener: {}", e);
                        }
                    };
                    futures::future::ready(())
                })
                .await;
        })?;

        // Publish the request.
        self.connection
            .publisher
            .publish(&r2r::std_msgs::msg::String {
                data: serde_json::to_string(&request)?,
            })?;

        // Wait for a ReadResponse from the network listener spawned above.
        // We'll wait up to a timeout while spinning the shared node handle and
        // running the local task pool so the spawned listener can process messages.
        use std::time::{Duration, Instant};
        let timeout = Duration::from_secs(5);
        let start = Instant::now();
        while record_holder.borrow().is_none() && start.elapsed() < timeout {
            // spin node and run pool briefly
            {
                let mut nb = self.node.borrow_mut();
                nb.spin_once(Duration::from_millis(50));
            }
            pool.run_until_stalled();
        }

        // If a record was received, return it.
        if let Some(rec) = record_holder.borrow_mut().take() {
            return Ok(rec);
        }

        Err(anyhow::anyhow!("no ReadResponse received within timeout"))
    }

    pub fn latest_heartbeat() -> Result<RecordHeartbeat> {
        todo!()
    }
}
