use anyhow::Result;
use futures_lite::StreamExt;
use iroh::{Endpoint, SecretKey};
use iroh_gossip::net::Gossip;

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
        .spawn_with_auto_discovery(endpoint.clone())
        .await?;

    // Set up protocol router
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.gossip.clone())
        .spawn();

    // Create topic from passphrase
    let topic = Topic::from_passphrase("my-iroh-gossip-topic");

    // Split into sink (sending) and stream (receiving) 
    let (mut sink, mut stream) = gossip.subscribe_and_join(topic.into()).await?.split();

    // Spawn listener for incoming messages
    tokio::spawn(async move {
        while let Some(event) = stream.next().await {

            if let Ok(Event::Received(msg)) = event {
                println!(
                    "Message from {}: {}",
                    &msg.delivered_from.to_string()[0..8],
                    String::from_utf8(msg.content.to_vec()).unwrap()
                );
            } else if let Ok(Event::NeighborUp(peer)) = event {
                println!("Joined by {}",&peer.to_string()[0..8]);                
            }
        }
    });

    // Main input loop for sending messages
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        print!("> ");
        stdin.read_line(&mut buffer).unwrap();
        sink.broadcast(buffer.clone().replace("\n","").into()).await.unwrap();
        buffer.clear();
    }
}