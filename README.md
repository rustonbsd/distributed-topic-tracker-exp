# distributed-topic-tracker

Decentralized, rate-limited auto-discovery and bootstrap for [iroh-gossip](https://github.com/n0-computer/iroh-gossip),
backed by the BitTorrent mainline DHT and rotating shared secrets.
No centralized components.

- Zero servers. Uses public DHT + encrypted payloads.
- Deterministic, per-minute discovery keys.
- Rate-limited publishing to reduce DHT load.
- Bubble detection and merging to heal partitions.

Links:
- Protocol details (spec): PROTOCOL.md
- Architecture (illustrative): ARCHITECTURE.md
- Feedback issue: https://github.com/rustonbsd/distributed-topic-tracker-exp/issues/5

Status: preparing for production. API may evolve; protocol is defined.

## Features

- Fully decentralized bootstrap for iroh-gossip
- Ed25519-based signing; shared-secret-based encryption
- DHT rate limiting (caps per-minute records)
- Resilient bootstrap with retries and jitter
- Background publisher with bubble detection and peer merging

## Quick start

Add dependencies (names subject to final crate publish):

```toml
[dependencies]
iroh = "*"
iroh-gossip = "*"
distributed-topic-tracker = { git = "https://github.com/rustonbsd/distributed-topic-tracker", branch = "main" }
```

Minimal example:

```rust
use anyhow::Result;
use iroh::{Endpoint, SecretKey};
use iroh_gossip::{api::Event, net::Gossip};

// Crate imports
use distributed_topic_tracker::{
    AutoDiscoveryBuilder, AutoDiscoveryGossip, DefaultSecretRotation, TopicId,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Generate a fresh node key
    let secret_key = SecretKey::generate(rand::rngs::OsRng);

    // Endpoint with discovery enabled
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .bind()
        .await?;

    // Gossip with auto-discovery
    let gossip = Gossip::builder()
        .spawn_with_auto_discovery::<DefaultSecretRotation>(endpoint.clone(), None)
        .await?;

    // Protocol router
    let _router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.gossip.clone())
        .spawn();

    // Topic and initial shared secret (pre-agreed out of band)
    let topic_id = TopicId::new("my-iroh-gossip-topic".to_string());
    let initial_secret = b"my-initial-secret".to_vec();

    // Join + subscribe
    let (sink, mut stream) = gossip
        .subscribe_and_join_with_auto_discovery(topic_id, &initial_secret)
        .await?
        .split();

    // Listener for incoming events
    tokio::spawn(async move {
        while let Ok(event) = stream.recv().await {
            if let Event::Received(msg) = event {
                let from = &msg.delivered_from.to_string();
                let from_short = &from[0..8];
                let body = String::from_utf8(msg.content.to_vec()).unwrap();
                println!("\nMessage from {}: {}", from_short, body);
            } else if let Event::NeighborUp(peer) = event {
                let peer_short = &peer.to_string()[0..8];
                println!("\nJoined by {}", peer_short);
            }
        }
    });

    // Simple stdin loop
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        print!("\n> ");
        stdin.read_line(&mut buffer).unwrap();
        let msg = buffer.clone().replace('\n', "");
        sink.broadcast(msg.into()).await.unwrap();
        print!(" - (sent)\n");
        buffer.clear();
    }
}
```

## Configuration (defaults)

- DHT get timeout: 10 s
- Publish retries: 3 attempts
- Retry jitter: 0–2000 ms
- Per-minute record cap: 10 (MAX_BOOTSTRAP_RECORDS)
- Join pacing: 100 ms between attempts, 500 ms final wait
- Publisher backoff: 1–60 s (exponential), success jitter: 0–60 s
- Bubble detection:
  - Small cluster: fewer than 4 neighbors
  - Message overlap: non-overlapping recent message hashes

See PROTOCOL.md for exact procedures.

## Security model (summary)

- Public discovery index: deterministic, per-minute Ed25519 keypair derived
  from topic and time.
- Content confidentiality: records encrypted using a key derived from a
  rotating shared secret.
- Authentication and integrity: records signed by publisher's node key.
- Replay and access control: per-minute binding and secret rotation.

Details: PROTOCOL.md.

## Architecture

- Bootstrap loop queries DHT, decrypts, verifies, and connects to discovered
  peers with pacing.
- Publisher runs in the background post-join to publish activity and merge
  bubbles.
- Records encode topic, time window, publisher, active peers, and recent
  message proofs.

See ARCHITECTURE.md for diagrams and flows.

## Roadmap

- Finalize crate name and publish to crates.io
- Doc tests and examples
- Optimize configuration settings
- Add more examples

## Contributing

- Try it, then drop feedback:
  https://github.com/rustonbsd/distributed-topic-tracker-exp/issues/5
- PRs, issue and success reports welcome.

License: to be added (e.g., MIT/Apache-2.0).