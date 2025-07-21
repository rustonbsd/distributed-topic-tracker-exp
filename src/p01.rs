use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use futures::{Stream, StreamExt as _};
use iroh::Endpoint;
use iroh_gossip::api::{ApiError, Event, GossipReceiver, GossipSender};
use primitive_types::{U256, U512};
use sha2::Digest;

use ed25519_dalek_hpke::{Ed25519hpkeDecryption, Ed25519hpkeEncryption};
use tokio::time::sleep;

pub const SLOTS_N: u8 = 5;


pub trait SecretRotation {
    fn get_unix_minute_secret(
        &self,
        topic_hash: [u8; 32],
        unix_minute: u64,
        initial_secret_hash: [u8; 32],
    ) -> [u8; 32];
}

// Default secret rotation function
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultSecretRotation;

pub struct P01Gossip<R: SecretRotation + Default + Clone> {
    gossip: iroh_gossip::net::Gossip,
    endpoint: iroh::Endpoint,
    secret_rotation_function: R,
}

#[derive(Debug)]
pub struct P01Topic<R: SecretRotation + Default + Clone> {
    topic_id: P01TopicId,
    gossip_topic: iroh_gossip::api::GossipTopic,
    initial_secret_hash: [u8; 32],
    secret_rotation_function: R,
    node_id: iroh::NodeId,
}

#[derive(Debug, Clone)]
pub struct P01TopicId {
    raw: String,
    hash: [u8; 32], // sha512( raw )[..32]
}

#[derive(Debug, Clone)]
pub struct P01GossipReceiver {
    gossip_event_forwarder: tokio::sync::broadcast::Sender<iroh_gossip::api::Event>,
    action_req: tokio::sync::broadcast::Sender<P01InnerAction>,
}

#[derive(Debug, Clone)]
enum P01InnerAction {
    ReqNeighbors(tokio::sync::broadcast::Sender<HashSet<iroh::NodeId>>),
    ReqIsJoined(tokio::sync::broadcast::Sender<bool>),
}

impl P01GossipReceiver {
    pub fn new(gossip_receiver: GossipReceiver) -> Self {
        let (gossip_forward_tx, _) =
            tokio::sync::broadcast::channel::<iroh_gossip::api::Event>(1024);
        let (action_req_tx, mut action_req_rx) =
            tokio::sync::broadcast::channel::<P01InnerAction>(1024);

        tokio::spawn({
            let gossip_forward_tx = gossip_forward_tx.clone();
            async move {
                let mut gossip_receiver = gossip_receiver;
                loop {
                    tokio::select! {
                        Ok(inner_action) = action_req_rx.recv() => {
                            match inner_action {
                                P01InnerAction::ReqNeighbors(tx) => {
                                    let neighbors = gossip_receiver.neighbors().collect::<HashSet<iroh::NodeId>>();
                                    tx.send(neighbors).expect("broadcast failed");
                                }
                                P01InnerAction::ReqIsJoined(tx) => {
                                    let is_joined = gossip_receiver.is_joined();
                                    tx.send(is_joined).expect("broadcast failed");
                                }
                            }
                        }
                        gossip_event_res = gossip_receiver.next() => {
                            if let Some(Ok(gossip_event)) = gossip_event_res {
                                gossip_forward_tx.send(gossip_event).expect("broadcast failed");
                            } else {
                                break;
                            }
                        }
                    }
                }
                println!("gossip receiver task exited");
            }
        });

        Self {
            gossip_event_forwarder: gossip_forward_tx,
            action_req: action_req_tx,
        }
    }

    pub async fn neighbors(&mut self) -> HashSet<iroh::NodeId> {
        let (neighbors_tx, mut neighbors_rx) =
            tokio::sync::broadcast::channel::<HashSet<iroh::NodeId>>(1);
        self.action_req
            .send(P01InnerAction::ReqNeighbors(neighbors_tx))
            .expect("broadcast failed");
        match neighbors_rx.recv().await {
            Ok(neighbors) => neighbors,
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn is_joined(&mut self) -> bool {
        let (is_joined_tx, mut is_joined_rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(P01InnerAction::ReqIsJoined(is_joined_tx))
            .expect("broadcast failed");
        match is_joined_rx.recv().await {
            Ok(is_joined) => is_joined,
            Err(_) => panic!("broadcast failed"),
        }
    }
}

impl Stream for P01GossipReceiver {
    type Item = Result<Event, ApiError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.gossip_event_forwarder.subscribe().try_recv() {
            Ok(event) => Poll::Ready(Some(Ok(event))),
            Err(_) => Poll::Pending,
        }
    }
}

impl P01TopicId {
    pub fn new(raw: String) -> Self {
        let mut raw_hash = sha2::Sha512::new();
        raw_hash.update(raw.as_bytes());

        Self {
            raw,
            hash: raw_hash.finalize()[..32]
                .try_into()
                .expect("hashing 'raw' failed"),
        }
    }
}

impl<R: SecretRotation + Default + Clone> P01Topic<R> {
    /*
        Bootstrap procedure (simple)
        - get all records from get_all(pubkey, salt) where pubkey is the derived signature public key from the topic and unix minute as follows: keypair_seed = hash( topic + unix_minute ) and the salt is salt = hash ("slot:" + topic + unix_minute + i) where i is a randomly picked slot from the range 0 to N-1
        - if no records found, repeat step 1 with i = (i + 1) % N
        - for all found records, decrypt with shared secret and verify the record
        - add all found records to a list of bootstrap nodes, if all collected bootstrap node lists contain more then MIN_BOOTSTRAP_NODES nodes, we join the gossip topic in iroh-gossip
        - if failed, continue with 1
        - on succes, switch to publisher mode
    */
    // 1. find bootstrap nodes
    // 2. sub to gossip topic
    // 3. start publishing
    // 4. return P01Topic
    pub async fn bootstrap(
        topic_id: P01TopicId,
        node_id: iroh::NodeId,
        gossip: iroh_gossip::net::Gossip,
        initial_secret: &Vec<u8>,
        secret_rotation_function: Option<R>,
    ) -> Result<Self> {
        let mut initial_secret_hash = sha2::Sha512::new();
        initial_secret_hash.update(initial_secret);
        let initial_secret_hash: [u8; 32] = initial_secret_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed");

        let mut slot_index = 0;
        let gossip_topic = loop {
            let dht = mainline::Dht::client()?;
            let topic_sign = P01Topic::<R>::signing_keypair(&topic_id, 0);
            let salt = P01Topic::<R>::slot_salt(&topic_id, slot_index, 0);

            slot_index = (slot_index + 1) % SLOTS_N;
            let records = dht
                .get_mutable(
                    topic_sign.verifying_key().as_bytes(),
                    Some(&salt),
                    Some((super::unix_minute(-1i64) as i64) * 60),
                )
                .filter(|record| {
                    // verify record
                    // TODO![!]
                    true
                })
                .collect::<Vec<_>>();

        

            if records.is_empty() {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            let all_node_ids = vec![];  // todo: join all node ids to bootstrap_list
            match gossip.subscribe(iroh_gossip::proto::TopicId::from(topic_id.hash), all_node_ids).await {
                Ok(gossip_topic) => break gossip_topic,
                Err(_) => {
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        };

        // become publisher here [!] todo

        Ok(Self {
            topic_id,
            gossip_topic,
            initial_secret_hash: initial_secret_hash,
            secret_rotation_function: secret_rotation_function.unwrap_or_default(),
            node_id,
        })
    }

    pub fn split(self) -> (GossipSender, P01GossipReceiver) {
        let (gossip_sender, gossip_receiver) = self.gossip_topic.split();

        (gossip_sender, P01GossipReceiver::new(gossip_receiver))
    }
}

// Static impls
impl<R: SecretRotation + Default + Clone> P01Topic<R> {
    fn signing_keypair(
        topic_id: &P01TopicId,
        unix_minute: u64,
    ) -> ed25519_dalek::SigningKey {
        let mut sign_keypair_hash = sha2::Sha512::new();
        sign_keypair_hash.update(topic_id.hash);
        sign_keypair_hash.update(unix_minute.to_le_bytes());
        let sign_keypair_seed: [u8; 32] = sign_keypair_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed");
        ed25519_dalek::SigningKey::from_bytes(&sign_keypair_seed)
    }

    fn encryption_keypair(
        topic_id: &P01TopicId,
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

    // salt = hash ("slot:" + topic + unix_minute + (hash( topic + unix_minute + my_node_id ) % SLOTS_N) )
    // index = hash( topic + unix_minute + my_node_id ) % SLOTS_N
    fn slot_index(topic_id: &P01TopicId, node_id: &iroh::NodeId, unix_minute: u64) -> u8 {
        let mut slot_index_hash = sha2::Sha512::new();
        slot_index_hash.update(topic_id.hash);
        slot_index_hash.update(unix_minute.to_le_bytes());
        slot_index_hash.update(node_id.as_bytes());
        let hash_value = U512::from_little_endian(&slot_index_hash.finalize());
        (hash_value % U256::from(SLOTS_N)).as_u32() as u8
    }

    // salt = hash ("slot:" + topic + unix_minute + i) where i is a randomly picked slot from the range 0 to SLOTS_N-1
    fn slot_salt(topic_id: &P01TopicId, index: u8, unix_minute: u64) -> [u8; 32] {
        let mut slot_hash = sha2::Sha512::new();
        slot_hash.update("slot:");
        slot_hash.update(topic_id.hash);
        slot_hash.update(unix_minute.to_le_bytes());
        slot_hash.update((index % SLOTS_N).to_le_bytes());
        slot_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed")
    }
}

pub trait AutoDiscoveryBuilder<R: SecretRotation + Default + Clone> {
    #[allow(async_fn_in_trait)]
    async fn spawn_with_auto_discovery(self, endpoint: Endpoint, secret_rotation_function: Option<R>) -> Result<P01Gossip<R>>;
}

impl<R: SecretRotation + Default + Clone> AutoDiscoveryBuilder<R> for iroh_gossip::net::Builder {
    async fn spawn_with_auto_discovery(self, endpoint: Endpoint, secret_rotation_function: Option<R>) -> Result<P01Gossip<R>> {
        Ok(P01Gossip {
            gossip: self.spawn(endpoint.clone()),
            endpoint: endpoint.clone(),
            secret_rotation_function: secret_rotation_function.unwrap_or_default(),

        })
    }
}

pub trait AutoDiscoveryGossip<R: SecretRotation + Default + Clone> {
    #[allow(async_fn_in_trait)]
    async fn subscribe_and_join_with_auto_discovery(
        &self,
        topic_id: P01TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<P01Topic<R>>;
}

impl<R: SecretRotation + Default + Clone> AutoDiscoveryGossip<R> for P01Gossip<R> {
    async fn subscribe_and_join_with_auto_discovery(
        &self,
        topic_id: P01TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<P01Topic<R>> {
        P01Topic::bootstrap(
            topic_id,
            self.endpoint.node_id(),
            self.gossip.clone(),
            initial_secret,
            Some(self.secret_rotation_function.clone()),
        ).await
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
