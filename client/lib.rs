use anyhow::Result;
<<<<<<< Updated upstream
use capsulelib::Metadata;
use futures::{Stream, executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile, WrappedTypesupport};
=======
use futures::{executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile};
>>>>>>> Stashed changes
use std::collections::HashMap;

struct Connection<S, P>
where
    S: WrappedTypesupport + 'static,
    P: WrappedTypesupport + 'static,
{
    subscriber: Box<dyn Stream<Item = S> + Unpin>,
    publisher: Publisher<P>,
}

<<<<<<< Updated upstream
impl<S, P> Connection<S, P>
where
    S: WrappedTypesupport + 'static,
    P: WrappedTypesupport + 'static,
{
    /// Connects to the server
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let mut node = r2r::Node::create(ctx, "node", "namespace")?;
        let subscriber = node.subscribe::<S>("/chatter_client", QosProfile::default())?;
        let publisher = node.create_publisher::<P>("/chatter_server", QosProfile::default())?;
        Ok(Connection {
            subscriber: Box::new(subscriber),
            publisher,
        })
    }

    pub fn create(self, metadata: Metadata) -> Result<()> {
        Ok(())
    }
=======
impl User<'_> {
    pub fn new(
        name: String,
        sign_key: &[u8],
        verify_key: &[u8],
        symmetric_key: &[u8],
        db_filepath: String,
    ) -> Self {
        User::default()
        // User {
        //     name,
        //     sign_key,
        //     verify_key,
        //     symmetric_key,
        //     db_filepath,
        // }
    }
}

pub fn create() -> Result<()> {
    Ok(())
}

/// Connects to
pub fn init() -> Result<(impl Stream<Item = T> + Unpin, Publisher<T>)>
where
    T: WrappedTypesupport,
{
    let ctx = r2r::Context::create()?;
    let mut node = r2r::Node::create(ctx, "node", "namespace")?;
    let subscriber =
        node.subscribe::<r2r::std_msgs::msg::String>("/chatter", QosProfile::default())?;
    let publisher =
        node.create_publisher::<r2r::std_msgs::msg::String>("/chatter", QosProfile::default())?;
    (subscriber, publisher)
>>>>>>> Stashed changes
}
