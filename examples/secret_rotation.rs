use anyhow::Result;
use iroh::{Endpoint, SecretKey};
use iroh_gossip::{api::Event, net::Gossip};
use sha2::Digest;

// Imports from distrubuted-topic-tracker
use distributed_topic_tracker::{
    AutoDiscoveryBuilder, AutoDiscoveryGossip, SecretRotation, TopicId,
};


#[derive(Debug, Clone, Copy)]
struct MySecretRotation;

impl SecretRotation for MySecretRotation {
    fn get_unix_minute_secret(
        &self,
        topic_hash: [u8; 32],
        unix_minute: u64,
        initial_secret_hash: [u8; 32],
    ) -> [u8; 32] {
        let mut hash = sha2::Sha512::new();
        hash.update(topic_hash);
        hash.update(unix_minute.to_be_bytes());
        hash.update(initial_secret_hash);
        hash.update(b"as long as you return 32 bytes this is a valid secret rotation function");
        hash.finalize()[..32].try_into().expect("hashing failed")
    }
}

impl Default for MySecretRotation {
    fn default() -> Self {
        Self {}
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    // Generate a new random secret key
    let secret_key = SecretKey::generate(rand::rngs::OsRng);

    // Set up endpoint with discovery enabled
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .bind()
        .await?;

    // Initialize gossip with auto-discovery
    let gossip = Gossip::builder()
        .spawn_with_auto_discovery::<MySecretRotation>(endpoint.clone(), None)
        .await?;

    // Set up protocol router
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.gossip.clone())
        .spawn();

    let topic_id = TopicId::new("my-iroh-gossip-topic".to_string());
    let initial_secret = b"my-initial-secret".to_vec();

    // Split into sink (sending) and stream (receiving)
    let (sink, mut stream) = gossip
        .subscribe_and_join_with_auto_discovery(topic_id, &initial_secret)
        .await?
        .split();

    // Spawn listener for incoming messages
    tokio::spawn(async move {
        while let Ok(event) = stream.recv().await {
            if let Event::Received(msg) = event {
                println!(
                    "\nMessage from {}: {}",
                    &msg.delivered_from.to_string()[0..8],
                    String::from_utf8(msg.content.to_vec()).unwrap()
                );
            } else if let Event::NeighborUp(peer) = event {
                println!("\nJoined by {}", &peer.to_string()[0..8]);
            }
        }
    });

    // Main input loop for sending messages
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        print!("\n> ");
        stdin.read_line(&mut buffer).unwrap();
        sink.broadcast(buffer.clone().replace("\n", "").into())
            .await
            .unwrap();
        print!(" - (sent)\n");
        buffer.clear();
    }
}
