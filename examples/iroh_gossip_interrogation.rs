use futures::StreamExt as _;
use iroh::{Endpoint, protocol::Router};
use iroh_gossip::{ALPN, net::Gossip};

use iroh_gossip::api::Event;
use std::collections::HashSet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .spawn();

    let topic_id = iroh_gossip::proto::TopicId::from([1u8; 32]);
    let bootstrap_peers: Vec<iroh::NodeId> = vec![]; // Add real peer NodeIds
    let topic = gossip.subscribe(topic_id, bootstrap_peers).await?;
    let (_sender, mut receiver) = topic.split();
    let mut connected_peers: HashSet<iroh::NodeId> = HashSet::new();

    while let Some(event_result) = receiver.next().await {
        match event_result? {
            Event::NeighborUp(peer_id) => {
                connected_peers.insert(peer_id);
                println!(
                    "Peer connected: {}. Total peers: {}",
                    peer_id,
                    connected_peers.len()
                );
            }
            Event::NeighborDown(peer_id) => {
                connected_peers.remove(&peer_id);
                println!(
                    "Peer disconnected: {}. Total peers: {}",
                    peer_id,
                    connected_peers.len()
                );
            }
            Event::Received(message) => {
                println!("Message from {}", message.delivered_from);
            }
            Event::Lagged => {
                println!("Lagged behind in processing events");
            }
        }
    }

    router.shutdown().await?;
    Ok(())
}
