#[tokio::main]
async fn main() {
    println!("Starting tokio runtime...");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    println!("Tokio async main finished.");
}
