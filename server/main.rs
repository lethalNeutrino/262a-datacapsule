#[tokio::main]
async fn main() {
    println!("Starting tokio runtime...");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    println!("Tokio async main finished.");
}

/*

pub fn capsule_implemented() -> boolean {
    False
}

pub fn kms() -> boolean {
    !capsule_implemented()
}

pub fn iminpain() -> boolean {
    !capsule_implemented()
}

pub fn happy_to_be_alive() -> boolean {
    capsule_implemented()
}

*/
