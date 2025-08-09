use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use ed25519_dalek::ed25519::signature::SignerMut;
use futures::StreamExt as _;
use iroh::Endpoint;
use iroh_gossip::{
    api::{Event},
    proto::DeliveryScope,
};
use mainline::{async_dht::AsyncDht, MutableItem};
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use sha2::Digest;

use ed25519_dalek_hpke::{Ed25519hpkeDecryption, Ed25519hpkeEncryption};
use tokio::{
    time::{sleep, timeout},
};

pub const MAX_JOIN_PEERS_COUNT: usize = 30;
pub const MAX_BOOTSTRAP_RECORDS: usize = 10;
pub const SECRET_ROTATION: DefaultSecretRotation = DefaultSecretRotation;

static DHT: Lazy<ArcSwap<mainline::async_dht::AsyncDht>> = Lazy::new(|| {
    ArcSwap::from_pointee(
        mainline::Dht::builder().build().expect("failed to create dht").as_async()
    )
});

fn get_dht() -> Arc<AsyncDht> {
    DHT.load_full()
}

async fn reset_dht() {
    let n_dht = mainline::Dht::builder()
                .build()
                .expect("failed to create dht");
    DHT.store(Arc::new(n_dht.as_async()));
}

#[derive(Debug, Clone)]
pub struct EncryptedRecord {
    encrypted_record: Vec<u8>,
    encrypted_decryption_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    topic: [u8; 32],
    unix_minute: u64,
    node_id: [u8; 32],
    active_peers: [[u8; 32]; 5],
    last_message_hashes: [[u8; 32]; 5],
    signature: [u8; 64],
}

pub struct Gossip<R: SecretRotation + Default + Clone + Send + 'static> {
    pub gossip: iroh_gossip::net::Gossip,
    endpoint: iroh::Endpoint,
    secret_rotation_function: R,
}

#[derive(Debug)]
pub struct Topic<R: SecretRotation + Default + Clone + Send + 'static> {
    topic_id: TopicId,
    gossip_sender: GossipSender,
    gossip_receiver: GossipReceiver,
    initial_secret_hash: [u8; 32],
    secret_rotation_function: R,
    node_id: iroh::NodeId,
}

#[derive(Debug, Clone)]
pub struct TopicId {
    _raw: String,
    hash: [u8; 32], // sha512( raw )[..32]
}

#[derive(Debug, Clone)]
pub struct GossipReceiver {
    gossip_event_forwarder: tokio::sync::broadcast::Sender<iroh_gossip::api::Event>,
    action_req: tokio::sync::broadcast::Sender<InnerActionRecv>,
    last_message_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct GossipSender {
    action_req: tokio::sync::broadcast::Sender<InnerActionSend>,
}

#[derive(Debug, Clone)]
enum InnerActionRecv {
    ReqNeighbors(tokio::sync::broadcast::Sender<HashSet<iroh::NodeId>>),
    ReqIsJoined(tokio::sync::broadcast::Sender<bool>),
}

#[derive(Debug, Clone)]
enum InnerActionSend {
    ReqSend(Vec<u8>, tokio::sync::broadcast::Sender<bool>),
    ReqJoinPeers(Vec<iroh::NodeId>, tokio::sync::broadcast::Sender<bool>),
}

impl EncryptedRecord {
    pub fn decrypt(
        &self,
        decryption_key: &ed25519_dalek::SigningKey
    ) -> Result<Record> {
        let one_time_key_bytes: [u8; 32] = decryption_key
            .decrypt(&self.encrypted_decryption_key)?.as_slice()
            .try_into()?;
        let one_time_key = ed25519_dalek::SigningKey::from_bytes(&one_time_key_bytes);

        let decrypted_record = one_time_key.decrypt(&self.encrypted_record)?;
        let record = Record::from_bytes(decrypted_record)?;
        Ok(record)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let encrypted_record_len = self.encrypted_record.len() as u32;
        buf.extend_from_slice(&encrypted_record_len.to_le_bytes());
        buf.extend_from_slice(&self.encrypted_record);
        buf.extend_from_slice(&self.encrypted_decryption_key);
        buf
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self> {
        let (encrypted_record_len, buf) = buf.split_at(4);
        let encrypted_record_len = u32::from_le_bytes(encrypted_record_len.try_into()?);
        let (encrypted_record, encrypted_decryption_key) =
            buf.split_at(encrypted_record_len as usize);

        Ok(Self {
            encrypted_record: encrypted_record.to_vec(),
            encrypted_decryption_key: encrypted_decryption_key.to_vec(),
        })
    }
}

impl Record {
    pub fn sign(
        topic: [u8; 32],
        unix_minute: u64,
        node_id: [u8; 32],
        active_peers: [[u8; 32]; 5],
        last_message_hashes: [[u8; 32]; 5],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&topic);
        signature_data.extend_from_slice(&unix_minute.to_le_bytes());
        signature_data.extend_from_slice(&node_id);
        for active_peer in active_peers {
            signature_data.extend_from_slice(&active_peer);
        }
        for last_message_hash in last_message_hashes {
            signature_data.extend_from_slice(&last_message_hash);
        }
        let mut signing_key = signing_key.clone();
        let signature = signing_key.sign(&signature_data);
        Self {
            topic,
            unix_minute,
            node_id,
            active_peers,
            last_message_hashes,
            signature: signature.to_bytes(),
        }
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self> {
        let (topic, buf) = buf.split_at(32);
        let (unix_minute, buf) = buf.split_at(8);
        let (node_id, mut buf) = buf.split_at(32);

        let mut active_peers: [[u8; 32]; 5] = [[0; 32]; 5];
        for i in 0..active_peers.len() {
            let (active_peer, _buf) = buf.split_at(32);
            active_peers[i] = active_peer.try_into()?;
            buf = _buf;
        }
        let mut last_message_hashes: [[u8; 32]; 5] = [[0; 32]; 5];
        for i in 0..last_message_hashes.len() {
            let (last_message_hash, _buf) = buf.split_at(32);
            last_message_hashes[i] = last_message_hash.try_into()?;
            buf = _buf;
        }

        let (signature, buf) = buf.split_at(64);

        if !buf.is_empty() {
            bail!("buffer not empty after reconstruction")
        }

        Ok(Self {
            topic: topic.try_into()?,
            unix_minute: u64::from_le_bytes(unix_minute.try_into()?),
            node_id: node_id.try_into()?,
            active_peers: active_peers.try_into()?,
            last_message_hashes: last_message_hashes.try_into()?,
            signature: signature.try_into()?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.topic);
        buf.extend_from_slice(&self.unix_minute.to_le_bytes());
        buf.extend_from_slice(&self.node_id);
        for active_peer in self.active_peers {
            buf.extend_from_slice(&active_peer);
        }
        for last_message_hash in self.last_message_hashes {
            buf.extend_from_slice(&last_message_hash);
        }
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn verify(&self, actual_topic: &[u8; 32], actual_unix_minute: u64) -> Result<()> {
        if self.topic != *actual_topic {
            bail!("topic mismatch")
        }
        if self.unix_minute != actual_unix_minute {
            println!(
                "Failed: unix_minute: {}, actual_unix_minute: {}",
                self.unix_minute, actual_unix_minute
            );
            bail!("unix minute mismatch")
        }

        let record_bytes = self.to_bytes();
        let signature_data = record_bytes[..record_bytes.len() - 64].to_vec();
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        let node_id = ed25519_dalek::VerifyingKey::from_bytes(&self.node_id)?;

        node_id.verify_strict(signature_data.as_slice(), &signature)?;

        Ok(())
    }

    pub fn encrypt(&self, encryption_key: &ed25519_dalek::SigningKey) -> EncryptedRecord {
        let one_time_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let p_key = one_time_key.verifying_key();
        let data_enc = p_key.encrypt(&self.to_bytes()).expect("encryption failed");
        let key_enc = encryption_key
            .verifying_key()
            .encrypt(&one_time_key.to_bytes())
            .expect("encryption failed");

        EncryptedRecord {
            encrypted_record: data_enc,
            encrypted_decryption_key: key_enc,
        }
    }
}

impl GossipSender {
    pub fn new(gossip_sender: iroh_gossip::api::GossipSender) -> Self {
        let (action_req_tx, mut action_req_rx) =
            tokio::sync::broadcast::channel::<InnerActionSend>(1024);

        tokio::spawn({
            let gossip_sender = gossip_sender;
            async move {
                loop {
                    match action_req_rx.recv().await {
                        Ok(inner_action) => match inner_action {
                            InnerActionSend::ReqSend(data, tx) => {
                                let res = gossip_sender.broadcast(data.into()).await;
                                tx.send(res.is_ok()).expect("broadcast failed");
                            }
                            InnerActionSend::ReqJoinPeers(peers, tx) => {
                                let res = gossip_sender.join_peers(peers).await;
                                tx.send(res.is_ok()).expect("broadcast failed");
                            }
                        },
                        Err(_) => break,
                    }
                }
            }
        });

        Self {
            action_req: action_req_tx,
        }
    }

    pub async fn broadcast(&self, data: Vec<u8>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(InnerActionSend::ReqSend(data, tx))
            .expect("broadcast failed");

        match rx.recv().await {
            Ok(true) => Ok(()),
            Ok(false) => bail!("broadcast failed"),
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn join_peers(
        &self,
        peers: Vec<iroh::NodeId>,
        max_peers: Option<usize>,
    ) -> Result<()> {
        let mut peers = peers;
        if let Some(max_peers) = max_peers {
            peers.shuffle(&mut rand::thread_rng());
            peers.truncate(max_peers);
        }

        let (tx, mut rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(InnerActionSend::ReqJoinPeers(peers, tx))
            .expect("broadcast failed");

        match rx.recv().await {
            Ok(true) => Ok(()),
            Ok(false) => bail!("join peers failed"),
            Err(_) => panic!("broadcast failed"),
        }
    }
}

impl GossipReceiver {
    pub fn new(gossip_receiver: iroh_gossip::api::GossipReceiver) -> Self {
        let (gossip_forward_tx, mut gossip_forward_rx) =
            tokio::sync::broadcast::channel::<iroh_gossip::api::Event>(1024);
        let (action_req_tx, mut action_req_rx) =
            tokio::sync::broadcast::channel::<InnerActionRecv>(1024);

        tokio::spawn({
            async move {
                while let Ok(_) = gossip_forward_rx.recv().await {}
            }
        });

        let self_ref = Self {
            gossip_event_forwarder: gossip_forward_tx,
            action_req: action_req_tx,
            last_message_hashes: vec![],
        };
        tokio::spawn({
            let mut self_ref = self_ref.clone();
            async move {
                let mut gossip_receiver = gossip_receiver;
                loop {
                    tokio::select! {
                        Ok(inner_action) = action_req_rx.recv() => {
                            match inner_action {
                                InnerActionRecv::ReqNeighbors(tx) => {
                                    let neighbors = gossip_receiver.neighbors().collect::<HashSet<iroh::NodeId>>();
                                    tx.send(neighbors).expect("broadcast failed");
                                },
                                InnerActionRecv::ReqIsJoined(tx) => {
                                    let is_joined = gossip_receiver.is_joined();
                                    tx.send(is_joined).expect("broadcast failed");
                                }
                            }
                        }
                        gossip_event_res = gossip_receiver.next() => {
                            if let Some(Ok(gossip_event)) = gossip_event_res {
                                if let Event::Received(msg) = gossip_event.clone() {
                                    if let DeliveryScope::Swarm(_) = msg.scope {
                                        let hash = sha2::Sha512::digest(&msg.content);
                                        self_ref.last_message_hashes.push(hash[..32].try_into().expect("hashing failed"));
                                        while self_ref.last_message_hashes.len() > 5 {
                                            self_ref.last_message_hashes.pop();
                                        }
                                    }
                                }
                                self_ref.gossip_event_forwarder.send(gossip_event).expect("broadcast failed");
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        });

        self_ref
    }

    pub async fn neighbors(&mut self) -> HashSet<iroh::NodeId> {
        let (neighbors_tx, mut neighbors_rx) =
            tokio::sync::broadcast::channel::<HashSet<iroh::NodeId>>(1);
        tokio::spawn({
            let action_req = self.action_req.clone();
            async move {
                action_req
                    .send(InnerActionRecv::ReqNeighbors(neighbors_tx))
                    .expect("broadcast failed");
            }
        });

        match neighbors_rx.recv().await {
            Ok(neighbors) => neighbors,
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn is_joined(&mut self) -> bool {
        let (is_joined_tx, mut is_joined_rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(InnerActionRecv::ReqIsJoined(is_joined_tx))
            .expect("broadcast failed");
        match is_joined_rx.recv().await {
            Ok(is_joined) => is_joined,
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn recv(&mut self) -> Result<Event> {
        self.gossip_event_forwarder
            .subscribe()
            .recv()
            .await
            .map_err(|err| anyhow::anyhow!(err))
    }

    pub fn last_message_hashes(&self) -> Vec<[u8; 32]> {
        self.last_message_hashes.clone()
    }
}

impl TopicId {
    pub fn new(raw: String) -> Self {
        let mut raw_hash = sha2::Sha512::new();
        raw_hash.update(raw.as_bytes());

        Self {
            _raw: raw,
            hash: raw_hash.finalize()[..32]
                .try_into()
                .expect("hashing 'raw' failed"),
        }
    }
}

// State: new, split, spawn_publisher
impl<R: SecretRotation + Default + Clone + Send + 'static> Topic<R> {
    pub async fn new(
        topic_id: TopicId,
        endpoint: &iroh::Endpoint,
        node_signing_key: &ed25519_dalek::SigningKey,
        gossip: iroh_gossip::net::Gossip,
        initial_secret: &Vec<u8>,
        secret_rotation_function: Option<R>,
    ) -> Result<Self> {

        // Create secret_hash
        let mut initial_secret_hash = sha2::Sha512::new();
        initial_secret_hash.update(initial_secret);
        let initial_secret_hash: [u8; 32] = initial_secret_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed");

        // Bootstrap to get gossip tx/rx
        let (gossip_tx, gossip_rx) = Self::bootstrap(
            topic_id.clone(),
            endpoint,
            node_signing_key,
            gossip,
            initial_secret_hash,
            secret_rotation_function.clone(),
        )
        .await?;

        // Spawn publisher
        let _join_handler = Self::spawn_publisher(
            topic_id.clone(),
            secret_rotation_function.clone(),
            initial_secret_hash,
            endpoint.node_id().clone(),
            gossip_rx.clone(),
            gossip_tx.clone(),
            node_signing_key.clone(),
        );

        Ok(Self {
            topic_id,
            gossip_sender: gossip_tx,
            gossip_receiver: gossip_rx,
            initial_secret_hash: initial_secret_hash,
            secret_rotation_function: secret_rotation_function.unwrap_or_default(),
            node_id: endpoint.node_id().clone(),
        })
    }

    pub fn split(&self) -> (GossipSender, GossipReceiver) {
        (self.gossip_sender.clone(), self.gossip_receiver.clone())
    }
}

// Procedures: Bootstrap, Publishing, Publisher
impl<R: SecretRotation + Default + Clone + Send + 'static> Topic<R> {
    pub async fn bootstrap(
        topic_id: TopicId,
        endpoint: &iroh::Endpoint,
        node_signing_key: &ed25519_dalek::SigningKey,
        gossip: iroh_gossip::net::Gossip,
        initial_secret_hash: [u8; 32],
        secret_rotation_function: Option<R>,
    ) -> Result<(GossipSender, GossipReceiver)> {
        let gossip_topic: iroh_gossip::api::GossipTopic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from(topic_id.hash), vec![])
            .await?;
        let (gossip_sender, gossip_receiver) = gossip_topic.split();
        let (gossip_sender, mut gossip_receiver) = (
            GossipSender::new(gossip_sender),
            GossipReceiver::new(gossip_receiver),
        );

        let mut last_published_unix_minute = 0;
        loop {
            // Check if we are connected to at least one node
            if gossip_receiver.is_joined().await {
                return Ok((gossip_sender, gossip_receiver));
            }

            // On the first try we check the prev unix minute, after that the current one
            let unix_minute = crate::unix_minute(if last_published_unix_minute == 0 {
                -1
            } else {
                0
            });

            // Unique, verified records for the unix minute
            let records = Topic::get_unix_minute_records(
                &topic_id.clone(),
                unix_minute,
                secret_rotation_function.clone(),
                initial_secret_hash,
                &endpoint.node_id(),
            )
            .await;

            // If there are no records, invoke the publish_proc (the publishing procedure)
            // continue the loop after
            if records.is_empty() {
                if unix_minute != last_published_unix_minute {
                    if Self::publish_proc(
                        unix_minute,
                        &topic_id,
                        secret_rotation_function.clone(),
                        initial_secret_hash,
                        endpoint.node_id().clone(),
                        node_signing_key,
                        HashSet::new(),
                        vec![],
                    )
                    .await
                    .is_ok()
                    {
                        last_published_unix_minute = unix_minute;
                        println!(
                            "published record topic {}, c_topic_key {}",
                            z32::encode(&topic_id.hash),
                            z32::encode(
                                Topic::<R>::signing_keypair(&topic_id, unix_minute)
                                    .verifying_key()
                                    .as_bytes()
                            )
                        );
                    }
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            // We found records

            // Collect node ids from active_peers and record.node_id (of publisher)
            let bootstrap_nodes = records
                .iter()
                .map(|record| {
                    let mut v = vec![record.node_id];
                    for peer in record.active_peers {
                        if peer != [0; 32] {
                            v.push(peer);
                        }
                    }
                    v
                })
                .flatten()
                .filter_map(|node_id| match iroh::NodeId::from_bytes(&node_id) {
                    Ok(node_id) => Some(node_id),
                    Err(_) => None,
                })
                .collect::<HashSet<_>>();

            println!(
                "bootstrap -> found {} records, topic {}, c_topic_key {}",
                records.len(),
                z32::encode(&topic_id.hash),
                z32::encode(
                    Topic::<R>::signing_keypair(&topic_id, unix_minute)
                        .verifying_key()
                        .as_bytes()
                )
            );

            // Maybe in the meantime someone connected to us via one of our published records
            // we don't want to disrup the gossip rotations any more then we have to
            // so we check again before joining new peers
            if gossip_receiver.is_joined().await {
                return Ok((gossip_sender, gossip_receiver));
            }

            // Instead of throwing everything into join_peers() at once we go node_id by node_id
            // again to disrupt as little nodes peer neighborhoods as possible.
            for node_id in bootstrap_nodes.iter() {
                match gossip_sender.join_peers(vec![node_id.clone()], None).await {
                    Ok(_) => {
                        sleep(Duration::from_millis(100)).await;
                        if gossip_receiver.is_joined().await {
                            break;
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }

            // If we are still not connected to anyone:
            // give it the default iroh-gossip connection timeout before the final is_joined() check
            if !gossip_receiver.is_joined().await {
                sleep(Duration::from_millis(500)).await;
            }

            // If we are connected: return
            if gossip_receiver.is_joined().await {
                return Ok((gossip_sender, gossip_receiver));
            } else {
                // If we are not connected: check if we should publish a record this minute
                if unix_minute != last_published_unix_minute {
                    if Self::publish_proc(
                        unix_minute,
                        &topic_id,
                        secret_rotation_function.clone(),
                        initial_secret_hash,
                        endpoint.node_id().clone(),
                        node_signing_key,
                        HashSet::new(),
                        vec![],
                    )
                    .await
                    .is_ok()
                    {
                        last_published_unix_minute = unix_minute;
                        println!(
                            "bootstrap -> published record topic {}, c_topic_key {}",
                            z32::encode(&topic_id.hash),
                            z32::encode(
                                Topic::<R>::signing_keypair(&topic_id, unix_minute)
                                    .verifying_key()
                                    .as_bytes()
                            )
                        );
                    }
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
    }

    // publishing procedure: if more then MAX_BOOTSTRAP_RECORDS are written, don't write.
    // returns all valid records found from nodes already connected to the iroh-gossip network.
    async fn publish_proc(
        unix_minute: u64,
        topic_id: &TopicId,
        secret_rotation_function: Option<R>,
        initial_secret_hash: [u8; 32],
        node_id: iroh::NodeId,
        node_signing_key: &ed25519_dalek::SigningKey,
        neighbors: HashSet<iroh::NodeId>,
        last_message_hashes: Vec<[u8; 32]>,
    ) -> Result<HashSet<Record>> {
        // Get verified records that have active_peers or last_message_hashes set (active participants)
        let records = Topic::<R>::get_unix_minute_records(
            &topic_id.clone(),
            unix_minute,
            secret_rotation_function.clone(),
            initial_secret_hash,
            &node_id,
        )
        .await
        .iter()
        .filter(|&record| {
            record
                .active_peers
                .iter()
                .filter(|&peer| peer.eq(&[0u8; 32]))
                .count()
                > 0
                || record
                    .last_message_hashes
                    .iter()
                    .filter(|&hash| hash.eq(&[0u8; 32]))
                    .count()
                    > 0
        })
        .cloned()
        .collect::<HashSet<_>>();

        // Don't publish if there are more then MAX_BOOTSTRAP_RECORDS already written
        // that either have active_peers or last_message_hashes set (active participants)
        if records.len() >= MAX_BOOTSTRAP_RECORDS {
            return Ok(records);
        }

        // Publish own records
        let mut active_peers: [[u8; 32]; 5] = [[0; 32]; 5];
        for (i, peer) in neighbors.iter().take(5).enumerate() {
            active_peers[i] = peer.as_bytes().clone();
        }

        let mut last_message_hashes_array = [[0u8; 32]; 5];
        for (i, hash) in last_message_hashes.iter().take(5).enumerate() {
            last_message_hashes_array[i] = *hash;
        }

        let record = Record::sign(
            topic_id.hash,
            unix_minute,
            node_id.as_bytes().clone(),
            active_peers,
            last_message_hashes_array,
            &node_signing_key,
        );
        Topic::<R>::publish_unix_minute_record(
            unix_minute,
            &topic_id.clone(),
            secret_rotation_function.clone(),
            initial_secret_hash,
            record,
            Some(3),
        )
        .await?;

        Ok(records)
    }

    // Runs after bootstrap to keep anouncing the topic on mainline and help identify and merge network bubbles
    fn spawn_publisher(
        topic_id: TopicId,
        secret_rotation_function: Option<R>,
        initial_secret_hash: [u8; 32],
        node_id: iroh::NodeId,
        gossip_receiver: GossipReceiver,
        gossip_sender: GossipSender,
        node_signing_key: ed25519_dalek::SigningKey,
    ) -> tokio::task::JoinHandle<()> {
        let mut gossip_receiver = gossip_receiver;

        tokio::spawn(async move {
            let mut backoff = 1;
            loop {
                let unix_minute = crate::unix_minute(0);

                // Run publish_proc() (publishing procedure that is aware of MAX_BOOTSTRAP_RECORDS already written)
                if let Ok(records) = Topic::<R>::publish_proc(
                    unix_minute,
                    &topic_id.clone(),
                    Some(secret_rotation_function.clone().unwrap_or_default()),
                    initial_secret_hash,
                    node_id.clone(),
                    &node_signing_key,
                    gossip_receiver.neighbors().await,
                    gossip_receiver.last_message_hashes(),
                )
                .await
                {
                    // Cluster size as bubble indicator
                    let neighbors = gossip_receiver.neighbors().await;
                    if neighbors.len() < 4 && !records.is_empty() {
                        let node_ids = records
                            .iter()
                            .map(|record| {
                                record
                                    .active_peers
                                    .iter()
                                    .filter_map(|&active_peer| {
                                        if active_peer == [0; 32]
                                            || neighbors.contains(&active_peer)
                                            || active_peer.eq(record.node_id.to_vec().as_slice())
                                            || active_peer.eq(node_id.as_bytes())
                                        {
                                            None
                                        } else if let Ok(node_id) =
                                            iroh::NodeId::from_bytes(&active_peer)
                                        {
                                            Some(node_id)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .flatten()
                            .collect::<HashSet<_>>();
                        if gossip_sender
                            .join_peers(
                                node_ids.iter().cloned().collect::<Vec<_>>(),
                                Some(MAX_JOIN_PEERS_COUNT),
                            )
                            .await
                            .is_ok()
                        {
                            //println!("group-merger -> joined peer {}", node_id);
                        }
                    }

                    // Message overlap indicator
                    if gossip_receiver.last_message_hashes().len() >= 1 {
                        let peers_to_join = records
                            .iter()
                            .filter_map(|record| {
                                if !record.last_message_hashes.iter().all(|last_message_hash| {
                                    *last_message_hash != [0; 32]
                                        && gossip_receiver
                                            .last_message_hashes()
                                            .contains(&last_message_hash)
                                }) {
                                    Some(record)
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        if !peers_to_join.is_empty() {
                            let node_ids = peers_to_join
                                .iter()
                                .filter_map(|&record| {
                                    let mut peers = vec![];
                                    if let Ok(node_id) = iroh::NodeId::from_bytes(&record.node_id) {
                                        peers.push(node_id);
                                    }
                                    for active_peer in record.active_peers {
                                        if active_peer == [0; 32] {
                                            continue;
                                        }
                                        if let Ok(node_id) = iroh::NodeId::from_bytes(&active_peer)
                                        {
                                            peers.push(node_id);
                                        }
                                    }
                                    Some(peers)
                                })
                                .flatten()
                                .collect::<HashSet<_>>();

                            if gossip_sender
                                .join_peers(
                                    node_ids.iter().cloned().collect::<Vec<_>>(),
                                    Some(MAX_JOIN_PEERS_COUNT),
                                )
                                .await
                                .is_ok()
                            {
                                println!(
                                    "bouble detected: no-message-overlap -> joined {} peers",
                                    node_ids.len()
                                );
                            }
                        }
                    }
                } else {
                    sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).max(60);
                    continue;
                }
                println!(
                    "published record topic {}, c_topic_key {}",
                    z32::encode(&topic_id.hash),
                    z32::encode(
                        Topic::<R>::signing_keypair(&topic_id.clone(), unix_minute)
                            .verifying_key()
                            .as_bytes()
                    )
                );
                backoff = 1;
                sleep(Duration::from_secs(rand::random::<u64>() % 60)).await;
            }
        })
    }
}

// Basic building blocks
impl<R: SecretRotation + Default + Clone + Send + 'static> Topic<R> {
    fn signing_keypair(topic_id: &TopicId, unix_minute: u64) -> ed25519_dalek::SigningKey {
        let mut sign_keypair_hash = sha2::Sha512::new();
        sign_keypair_hash.update(topic_id.hash);
        sign_keypair_hash.update(unix_minute.to_le_bytes());
        let sign_keypair_seed: [u8; 32] = sign_keypair_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed");
        ed25519_dalek::SigningKey::from_bytes(&sign_keypair_seed)
    }

    fn encryption_keypair(
        topic_id: &TopicId,
        secret_rotation_function: &R,
        initial_secret_hash: [u8; 32],
        unix_minute: u64,
    ) -> ed25519_dalek::SigningKey {
        let enc_keypair_seed = secret_rotation_function.get_unix_minute_secret(
            topic_id.hash,
            unix_minute,
            initial_secret_hash,
        );
        ed25519_dalek::SigningKey::from_bytes(&enc_keypair_seed)
    }

    // salt = hash (topic + unix_minute)
    fn salt(topic_id: &TopicId, unix_minute: u64) -> [u8; 32] {
        let mut slot_hash = sha2::Sha512::new();
        slot_hash.update(topic_id.hash);
        slot_hash.update(unix_minute.to_le_bytes());
        slot_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed")
    }

    async fn get_unix_minute_records(
        topic_id: &TopicId,
        unix_minute: u64,
        secret_rotation_function: Option<R>,
        initial_secret_hash: [u8; 32],
        node_id: &iroh::NodeId,
    ) -> HashSet<Record> {
        let topic_sign = Topic::<R>::signing_keypair(&topic_id, unix_minute);
        let encryption_key = Topic::<R>::encryption_keypair(
            &topic_id,
            &secret_rotation_function.clone().unwrap_or_default(),
            initial_secret_hash,
            unix_minute,
        );
        let salt = Topic::<R>::salt(&topic_id, unix_minute);

        // Get records, decrypt and verify
        let dht = get_dht();

        let records_iter = match timeout(
            Duration::from_secs(10),
            dht.get_mutable(topic_sign.verifying_key().as_bytes(), Some(&salt), None)
                .collect::<Vec<_>>(),
        )
        .await
        {
            Ok(records) => records,
            Err(_) => vec![],
        };

        let records = records_iter
            .iter()
            .filter_map(|record| {
                match EncryptedRecord::from_bytes(record.value().to_vec()) {
                    Ok(encrypted_record) => match encrypted_record.decrypt(&encryption_key) {
                        Ok(record) => match record.verify(&topic_id.hash, unix_minute) {
                            Ok(_) => match record.node_id.eq(node_id.as_bytes()) {
                                true => {
                                    None
                                }
                                false => Some(record),
                            },
                            Err(_) => None,
                        },
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            })
            .collect::<HashSet<_>>();
        records
    }

    async fn publish_unix_minute_record(
        unix_minute: u64,
        topic_id: &TopicId,
        secret_rotation_function: Option<R>,
        initial_secret_hash: [u8; 32],
        record: Record,
        retry_count: Option<usize>,
    ) -> Result<()> {
        let sign_key = Topic::<R>::signing_keypair(&topic_id.clone(), unix_minute);
        let salt = Topic::<R>::salt(&topic_id, unix_minute);
        let encryption_key = Topic::<R>::encryption_keypair(
            &topic_id.clone(),
            &secret_rotation_function.clone().unwrap_or_default(),
            initial_secret_hash,
            unix_minute,
        );
        let encrypted_record = record.encrypt(&encryption_key);

        for i in 0..retry_count.unwrap_or(3) {
            
            let dht = get_dht();

            let most_recent_result = match timeout(
                Duration::from_secs(10),
                dht.get_mutable_most_recent(
                    sign_key.clone().verifying_key().as_bytes(),
                    Some(&salt),
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => None,
            };

            let item = if let Some(mut_item) = most_recent_result {
                MutableItem::new(
                    sign_key.clone(),
                    &encrypted_record.to_bytes(),
                    mut_item.seq() + 1,
                    Some(&salt),
                )
            } else {
                MutableItem::new(
                    sign_key.clone(),
                    &encrypted_record.to_bytes(),
                    0,
                    Some(&salt),
                )
            };

            let put_result = match timeout(
                Duration::from_secs(10),
                dht.put_mutable(item.clone(), Some(item.seq())),
            )
            .await
            {
                Ok(result) => result.ok(),
                Err(_) => None
            };

            if put_result.is_some() {
                break;
            } else if i == retry_count.unwrap_or(3) - 1 {
                bail!("failed to publish record")
            }

            reset_dht().await;

            sleep(Duration::from_millis(rand::random::<u64>() % 2000)).await;
        }
        Ok(())
    }
}

pub trait AutoDiscoveryBuilder {
    #[allow(async_fn_in_trait)]
    async fn spawn_with_auto_discovery<R: SecretRotation + Default + Clone + Send + 'static>(
        self,
        endpoint: Endpoint,
        secret_rotation_function: Option<R>,
    ) -> Result<Gossip<R>>;
}

impl AutoDiscoveryBuilder for iroh_gossip::net::Builder {
    async fn spawn_with_auto_discovery<R: SecretRotation + Default + Clone + Send + 'static>(
        self,
        endpoint: Endpoint,
        secret_rotation_function: Option<R>,
    ) -> Result<Gossip<R>> {
        Ok(Gossip {
            gossip: self.spawn(endpoint.clone()),
            endpoint: endpoint.clone(),
            secret_rotation_function: secret_rotation_function.unwrap_or_default(),
        })
    }
}

pub trait AutoDiscoveryGossip<R: SecretRotation + Default + Clone + Send + 'static> {
    #[allow(async_fn_in_trait)]
    async fn subscribe_and_join_with_auto_discovery(
        &self,
        topic_id: TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<Topic<R>>;
}

// Default secret rotation function
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultSecretRotation;

pub trait SecretRotation {
    fn get_unix_minute_secret(
        &self,
        topic_hash: [u8; 32],
        unix_minute: u64,
        initial_secret_hash: [u8; 32],
    ) -> [u8; 32];
}

impl<R: SecretRotation + Default + Clone + Send + 'static> AutoDiscoveryGossip<R> for Gossip<R> {
    async fn subscribe_and_join_with_auto_discovery(
        &self,
        topic_id: TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<Topic<R>> {
        Topic::new(
            topic_id,
            &self.endpoint,
            self.endpoint.secret_key().secret(),
            self.gossip.clone(),
            initial_secret,
            Some(self.secret_rotation_function.clone()),
        )
        .await
    }
}

impl SecretRotation for DefaultSecretRotation {
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
        hash.finalize()[..32].try_into().expect("hashing failed")
    }
}

pub fn unix_minute(minute_offset: i64) -> u64 {
    ((chrono::Utc::now().timestamp() as f64 / 60.0f64).floor() as i64 + minute_offset) as u64
}