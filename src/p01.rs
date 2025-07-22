use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Result, bail};
use ed25519_dalek::ed25519::signature::SignerMut;
use futures::{Stream, StreamExt as _};
use iroh::Endpoint;
use iroh_gossip::api::{ApiError, Event, GossipReceiver, GossipSender};
use mainline::MutableItem;
use once_cell::sync::OnceCell;
use primitive_types::{U256, U512};
use sha2::Digest;

use ed25519_dalek_hpke::{Ed25519hpkeDecryption, Ed25519hpkeEncryption};
use tokio::{sync::Mutex, time::sleep};

pub const SLOTS_N: u8 = 3;
pub const SECRET_ROTATION: DefaultSecretRotation = DefaultSecretRotation;

// only once init dht
static DHT: OnceCell<Mutex<mainline::Dht>> = OnceCell::new();

fn get_dht() -> &'static Mutex<mainline::Dht> {
    DHT.get_or_init(|| {
        Mutex::new(
            mainline::Dht::builder()
                .request_timeout(Duration::from_millis(2000))
                .build()
                .expect("failed to create dht"),
        )
    })
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
    slot: u8,
    node_id: [u8; 32],
    active_peers: [[u8; 32]; 5],
    signature: [u8; 64],
}

pub struct P01Gossip<R: SecretRotation + Default + Clone + Send + 'static> {
    pub gossip: iroh_gossip::net::Gossip,
    endpoint: iroh::Endpoint,
    secret_rotation_function: R,
}

#[derive(Debug)]
pub struct P01Topic<R: SecretRotation + Default + Clone + Send + 'static> {
    topic_id: P01TopicId,
    gossip_sender: P01GossipSender,
    gossip_receiver: P01GossipReceiver,
    initial_secret_hash: [u8; 32],
    secret_rotation_function: R,
    node_id: iroh::NodeId,
}

#[derive(Debug, Clone)]
pub struct P01TopicId {
    _raw: String,
    hash: [u8; 32], // sha512( raw )[..32]
}

#[derive(Debug, Clone)]
pub struct P01GossipReceiver {
    gossip_event_forwarder: tokio::sync::broadcast::Sender<iroh_gossip::api::Event>,
    action_req: tokio::sync::broadcast::Sender<P01InnerActionRecv>,
}

#[derive(Debug, Clone)]
pub struct P01GossipSender {
    action_req: tokio::sync::broadcast::Sender<P01InnerActionSend>,
}

#[derive(Debug, Clone)]
enum P01InnerActionRecv {
    ReqNeighbors(tokio::sync::broadcast::Sender<HashSet<iroh::NodeId>>),
    ReqIsJoined(tokio::sync::broadcast::Sender<bool>),
}

#[derive(Debug, Clone)]
enum P01InnerActionSend {
    ReqSend(Vec<u8>, tokio::sync::broadcast::Sender<bool>),
    ReqJoinPeers(Vec<iroh::NodeId>, tokio::sync::broadcast::Sender<bool>),
}

impl EncryptedRecord {
    pub fn decrypt(&self, decryption_key: &ed25519_dalek::SigningKey) -> Result<Record> {
        let one_time_key_bytes = decryption_key
            .decrypt(&self.encrypted_decryption_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to convert one time key bytes to array"))?;
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
        slot: u8,
        node_id: [u8; 32],
        active_peers: [[u8; 32]; 5],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&topic);
        signature_data.extend_from_slice(&unix_minute.to_le_bytes());
        signature_data.extend_from_slice(&slot.to_le_bytes());
        signature_data.extend_from_slice(&node_id);
        for active_peer in active_peers {
            signature_data.extend_from_slice(&active_peer);
        }
        let mut signing_key = signing_key.clone();
        let signature = signing_key.sign(&signature_data);
        Self {
            topic,
            unix_minute,
            slot,
            node_id,
            active_peers,
            signature: signature.to_bytes(),
        }
    }

    pub fn from_bytes(buf: Vec<u8>) -> Result<Self> {
        let (topic, buf) = buf.split_at(32);
        let (unix_minute, buf) = buf.split_at(8);
        let (slot, buf) = buf.split_at(1);
        let (node_id, mut buf) = buf.split_at(32);

        let active_peer_count = ((buf.len() - 64) as f32 / 32f32).floor() as usize;
        let mut active_peers: [[u8; 32]; 5] = [[0; 32]; 5];
        for i in 0..active_peer_count {
            let (active_peer, _buf) = buf.split_at(32);
            active_peers[i] = active_peer.try_into()?;
            buf = _buf;
        }

        let (signature, buf) = buf.split_at(64);

        if !buf.is_empty() {
            bail!("buffer not empty after reconstruction")
        }

        Ok(Self {
            topic: topic.try_into()?,
            unix_minute: u64::from_le_bytes(unix_minute.try_into()?),
            slot: slot[0],
            node_id: node_id.try_into()?,
            active_peers: active_peers.try_into()?,
            signature: signature.try_into()?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.topic);
        buf.extend_from_slice(&self.unix_minute.to_le_bytes());
        buf.extend_from_slice(&[self.slot]);
        buf.extend_from_slice(&self.node_id);
        for active_peer in self.active_peers {
            buf.extend_from_slice(&active_peer);
        }
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn verify(
        &self,
        actual_topic: &[u8; 32],
        actual_unix_minute: u64,
        actual_slot: u8,
    ) -> Result<()> {
        if self.topic != *actual_topic {
            bail!("topic mismatch")
        }
        if self.unix_minute != actual_unix_minute {
            bail!("unix minute mismatch")
        }
        if self.slot != actual_slot {
            bail!("slot mismatch")
        }

        let record_bytes = self.to_bytes();
        let signature_data = record_bytes[..record_bytes.len() - 64].to_vec();
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        let node_id = ed25519_dalek::VerifyingKey::from_bytes(&self.node_id)?;

        node_id.verify_strict(signature_data.as_slice(), &signature)?;
        if self
            .active_peers
            .iter()
            .filter(|&active_peer| active_peer.eq(&[0; 32]))
            .count()
            == 0
        {
            bail!("active peers contains zero node id")
        }
        Ok(())
    }

    pub fn encrypt(&self, encryption_key: &ed25519_dalek::SigningKey) -> EncryptedRecord {
        let one_time_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let p_key = one_time_key.verifying_key();

        let mut data = Vec::new();
        data.extend_from_slice(&self.topic);
        data.extend_from_slice(&self.unix_minute.to_le_bytes());
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(&self.node_id);
        for active_peer in self.active_peers {
            data.extend_from_slice(&active_peer);
        }
        data.extend_from_slice(&self.signature);

        let data_enc = p_key.encrypt(data.as_slice()).expect("encryption failed");
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

impl P01GossipSender {
    pub fn new(gossip_sender: GossipSender) -> Self {
        let (action_req_tx, mut action_req_rx) =
            tokio::sync::broadcast::channel::<P01InnerActionSend>(1024);

        tokio::spawn({
            let mut gossip_sender = gossip_sender;
            async move {
                loop {
                    match action_req_rx.recv().await {
                        Ok(inner_action) => match inner_action {
                            P01InnerActionSend::ReqSend(data, tx) => {
                                let res = gossip_sender.broadcast(data.into()).await;
                                tx.send(res.is_ok()).expect("broadcast failed");
                            }
                            P01InnerActionSend::ReqJoinPeers(peers, tx) => {
                                let res = gossip_sender.join_peers(peers).await;
                                tx.send(res.is_ok()).expect("broadcast failed");
                            }
                        },
                        Err(_) => break,
                    }
                }
                println!("gossip sender task exited");
            }
        });

        Self {
            action_req: action_req_tx,
        }
    }

    pub async fn broadcast(&self, data: Vec<u8>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(P01InnerActionSend::ReqSend(data, tx))
            .expect("broadcast failed");

        match rx.recv().await {
            Ok(true) => Ok(()),
            Ok(false) => bail!("broadcast failed"),
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn join_peers(&self, peers: Vec<iroh::NodeId>) -> Result<()> {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<bool>(1);
        self.action_req
            .send(P01InnerActionSend::ReqJoinPeers(peers, tx))
            .expect("broadcast failed");

        match rx.recv().await {
            Ok(true) => Ok(()),
            Ok(false) => bail!("join peers failed"),
            Err(_) => panic!("broadcast failed"),
        }
    }
}

impl P01GossipReceiver {
    pub fn new(gossip_receiver: GossipReceiver) -> Self {
        let (gossip_forward_tx, mut gossip_forward_rx) =
            tokio::sync::broadcast::channel::<iroh_gossip::api::Event>(1024);
        let (action_req_tx, mut action_req_rx) =
            tokio::sync::broadcast::channel::<P01InnerActionRecv>(1024);

        tokio::spawn({
            async move {
                while let Ok(_) = gossip_forward_rx.recv().await { }
                println!("gossip forwarder task exited");
            }
        });

        tokio::spawn({
            let gossip_forward_tx = gossip_forward_tx.clone();
            async move {
                let mut gossip_receiver = gossip_receiver;
                loop {
                    tokio::select! {
                        Ok(inner_action) = action_req_rx.recv() => {
                            match inner_action {
                                P01InnerActionRecv::ReqNeighbors(tx) => {
                                    let neighbors = gossip_receiver.neighbors().collect::<HashSet<iroh::NodeId>>();
                                    tx.send(neighbors).expect("broadcast failed");
                                },
                                P01InnerActionRecv::ReqIsJoined(tx) => {
                                    let is_joined = gossip_receiver.is_joined();
                                    tx.send(is_joined).expect("broadcast failed");
                                }
                            }
                        }
                        gossip_event_res = gossip_receiver.next() => {
                            if let Some(Ok(gossip_event)) = gossip_event_res {
                                println!("gossip receiver task -> received event: {:?}", gossip_event);
                                println!("receivers: {:?}", gossip_forward_tx.send(gossip_event).expect("broadcast failed"));
                            } else {
                                println!("gossip receiver task exited");
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
        tokio::spawn({
            let action_req = self.action_req.clone();
            async move {
                action_req
                    .send(P01InnerActionRecv::ReqNeighbors(neighbors_tx))
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
            .send(P01InnerActionRecv::ReqIsJoined(is_joined_tx))
            .expect("broadcast failed");
        match is_joined_rx.recv().await {
            Ok(is_joined) => is_joined,
            Err(_) => panic!("broadcast failed"),
        }
    }

    pub async fn recv(&mut self) -> Result<Event> {
        self.gossip_event_forwarder.subscribe().recv().await.map_err(|err| anyhow::anyhow!(err))
    }
}

impl P01TopicId {
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

impl<R: SecretRotation + Default + Clone + Send + 'static> P01Topic<R> {
    /*
        Bootstrap procedure (simple)
        - get all records from get_all(pubkey, salt) where pubkey is the derived signature public key from the topic and unix minute as follows: keypair_seed = hash( topic + unix_minute ) and the salt is salt = hash ("slot:" + topic + unix_minute + i) where i is a randomly picked slot from the range 0 to N-1
        - if no records found, repeat step 1 with i = (i + 1) % N
        - for all found records, decrypt with shared secret and verify the record
        - add all found records to a list of bootstrap nodes, if all collected bootstrap node lists contain more then MIN_BOOTSTRAP_NODES nodes, we join the gossip topic in iroh-gossip
        - if failed, publish your own record and then continue with 1
        - on succes, switch to publisher mode
    */
    // 1. find bootstrap nodes
    // 2. sub to gossip topic
    // 3. start publishing
    // 4. return P01Topic
    pub async fn bootstrap(
        topic_id: P01TopicId,
        endpoint: &iroh::Endpoint,
        node_signing_key: &ed25519_dalek::SigningKey,
        gossip: iroh_gossip::net::Gossip,
        initial_secret: &Vec<u8>,
        secret_rotation_function: Option<R>,
    ) -> Result<Self> {
        let gossip_topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from(topic_id.hash), vec![])
            .await?;
        let (gossip_sender, gossip_receiver) = gossip_topic.split();
        let (gossip_sender, mut gossip_receiver) = (
            P01GossipSender::new(gossip_sender),
            P01GossipReceiver::new(gossip_receiver),
        );

        let mut initial_secret_hash = sha2::Sha512::new();
        initial_secret_hash.update(initial_secret);
        let initial_secret_hash: [u8; 32] = initial_secret_hash.finalize()[..32]
            .try_into()
            .expect("hashing failed");

        let mut last_published_unix_minute = 0;
        let (gossip_sender, gossip_receiver) = loop {
            {
                if gossip_receiver.is_joined().await {
                    break (gossip_sender, gossip_receiver);
                }
            }

            let unix_minute = super::unix_minute(0);
            let topic_sign = P01Topic::<R>::signing_keypair(&topic_id, unix_minute);
            let encryption_key = P01Topic::<R>::encryption_keypair(
                &topic_id,
                &secret_rotation_function.clone().unwrap_or_default(),
                initial_secret_hash,
                unix_minute,
            );

            let mut i: u8 = 0;
            let records = loop {
                let salt = P01Topic::<R>::slot_salt(&topic_id, i, unix_minute);

                // Get records, decrypt and verify
                //println!("bootstrap -> checking slothash {}, signkey {}",z32::encode(&salt),z32::encode(topic_sign.verifying_key().as_bytes()));
                let dht = get_dht().lock().await;
                let records = dht
                    .get_mutable(topic_sign.verifying_key().as_bytes(), Some(&salt), None)
                    .filter_map(|record| {
                        //println!("bootstrap -> found record with seq {}", record.seq());

                        match EncryptedRecord::from_bytes(record.value().to_vec()) {
                            Ok(encrypted_record) => match encrypted_record.decrypt(&encryption_key)
                            {
                                Ok(record) => match record.verify(&topic_id.hash, unix_minute, i) {
                                    Ok(_) => match record
                                        .node_id
                                        .eq(endpoint.clone().node_id().as_bytes())
                                    {
                                        true => {
                                            //println!("bootstrap -> found own record");
                                            None
                                        }
                                        false => Some(record),
                                    },
                                    Err(_) => {
                                        println!("bootstrap -> failed to verify record");
                                        None
                                    }
                                },
                                Err(_) => {
                                    println!("bootstrap -> failed to decrypt record");
                                    None
                                }
                            },
                            Err(_) => {
                                println!("bootstrap -> failed to decode record");
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                drop(dht);
                println!("bootstrap -> found {} records in slot {}", records.len(), i);

                if !records.is_empty() {
                    break records;
                }
                if unix_minute != last_published_unix_minute {
                    if Self::publish(
                        unix_minute,
                        &topic_id,
                        secret_rotation_function.clone(),
                        initial_secret_hash,
                        endpoint.node_id().clone(),
                        node_signing_key,
                        HashSet::new(),
                    )
                    .await
                    .is_ok()
                    {
                        last_published_unix_minute = unix_minute;
                        println!("published record {}", unix_minute);
                    } else {
                        println!("failed to publish record");
                    }
                }
                i += 1;
                if i >= SLOTS_N {
                    break vec![];
                }
            };
            if records.is_empty() {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            let all_node_ids = records
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
                .collect::<HashSet<_>>();
            println!("bootstrap -> found {} node ids", all_node_ids.len());

            let bootstrap_nodes = all_node_ids
                .iter()
                .filter_map(|node_id| match iroh::NodeId::from_bytes(node_id) {
                    Ok(node_id) => Some(node_id),
                    Err(_) => None,
                })
                .collect::<Vec<iroh::NodeId>>();

            if gossip_receiver.is_joined().await {
                break (gossip_sender, gossip_receiver);
            }

            if gossip_sender.join_peers(bootstrap_nodes).await.is_err() {
                if unix_minute != last_published_unix_minute {
                    if Self::publish(
                        unix_minute,
                        &topic_id,
                        secret_rotation_function.clone(),
                        initial_secret_hash,
                        endpoint.node_id().clone(),
                        node_signing_key,
                        HashSet::new(),
                    )
                    .await
                    .is_ok()
                    {
                        last_published_unix_minute = unix_minute;
                        println!("bootstrap -> published record {}", unix_minute);
                    }
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            break (gossip_sender, gossip_receiver);
        };

        println!("bootstrap -> connected to gossip topic");
        let p01_topic = Self {
            topic_id,
            gossip_sender: gossip_sender,
            gossip_receiver: gossip_receiver,
            initial_secret_hash: initial_secret_hash,
            secret_rotation_function: secret_rotation_function.unwrap_or_default(),
            node_id: endpoint.node_id().clone(),
        };

        let _join_handler = p01_topic.spawn_publisher(node_signing_key.clone());

        Ok(p01_topic)
    }

    /*
       Publishing procedure (simple)
       - get all records from get_all(pubkey, salt) where pubkey is the derived signature public key from the topic and unix minute as follows: keypair_seed = hash( topic + unix_minute )
       - decrypt all records withe the shared secret
       - verify the records
       - if 1 <= valid records found, sleep for some time then repeat 1
       - if only invalid record or no records found, write your own record into your slot for the current unix minute.
       - sleep for some time then repeat 1
    */
    async fn publish(
        unix_minute: u64,
        topic_id: &P01TopicId,
        secret_rotation_function: Option<R>,
        initial_secret_hash: [u8; 32],
        node_id: iroh::NodeId,
        node_signing_key: &ed25519_dalek::SigningKey,
        neighbors: HashSet<iroh::NodeId>,
    ) -> Result<()> {
        let topic_hash = topic_id.hash;
        let sign_key = P01Topic::<R>::signing_keypair(&topic_id.clone(), unix_minute);
        let salt_index = P01Topic::<R>::slot_index(&topic_id.clone(), &node_id, unix_minute);
        let salt_slot = P01Topic::<R>::slot_salt(&topic_id.clone(), salt_index, unix_minute);
        let decryption_key = P01Topic::<R>::encryption_keypair(
            &topic_id.clone(),
            &secret_rotation_function.clone().unwrap_or_default(),
            initial_secret_hash,
            unix_minute,
        );

        let dht = get_dht().lock().await;
        let records = dht
            .get_mutable(sign_key.verifying_key().as_bytes(), Some(&salt_slot), None)
            .filter_map(
                |record| match EncryptedRecord::from_bytes(record.value().to_vec()) {
                    Ok(enc_record) => match enc_record.decrypt(&decryption_key) {
                        Ok(record) => match record.verify(&topic_hash, unix_minute, salt_index) {
                            Ok(_) => {
                                if !record.node_id.eq(node_id.as_bytes()) {
                                    Some(record)
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        },
                        Err(_) => None,
                    },
                    Err(_) => None,
                },
            )
            .collect::<HashSet<_>>();
        drop(dht);

        if records.len() >= 1 {
            //println!("fake publish");
            return Ok(());
        }

        // Publish own records
        let mut active_peers: [[u8; 32]; 5] = [[0; 32]; 5];
        for (i, peer) in neighbors.iter().take(5).enumerate() {
            active_peers[i] = peer.as_bytes().clone();
            //println!("publishing active peer {}", peer);
        }

        let record = Record::sign(
            topic_hash,
            unix_minute,
            salt_index,
            node_id.as_bytes().clone(),
            active_peers,
            &node_signing_key,
        );

        let encrypted_record = record.encrypt(&decryption_key);
        //println!("publish -> slothash {}, signkey {}",z32::encode(&salt_slot),z32::encode(sign_key.verifying_key().as_bytes()));

        let dht = get_dht().lock().await;
        let item = if let Some(mut_item) =
            dht.get_mutable_most_recent(sign_key.verifying_key().as_bytes(), Some(&salt_slot))
        {
            //println!("publish -> found existing record with seq {}",mut_item.seq());
            MutableItem::new(
                sign_key,
                &encrypted_record.to_bytes(),
                mut_item.seq() + 1,
                Some(&salt_slot),
            )
        } else {
            MutableItem::new(sign_key, &encrypted_record.to_bytes(), 0, Some(&salt_slot))
        };

        if let Err(err) = dht.put_mutable(item.clone(), Some(item.seq())) {
            //println!("failed to publish record: {}", err);
            bail!("failed to publish record")
        }
        drop(dht);

        Ok(())
    }

    fn spawn_publisher(
        &self,
        node_signing_key: ed25519_dalek::SigningKey,
    ) -> tokio::task::JoinHandle<()> {
        let topic_id = self.topic_id.clone();
        let secret_rotation_function = self.secret_rotation_function.clone();
        let initial_secret_hash = self.initial_secret_hash;
        let node_id = self.node_id;
        let mut gossip_receiver = self.gossip_receiver.clone();
        let node_signing_key = node_signing_key.clone();

        tokio::spawn(async move {
            let mut backoff = 1;
            loop {
                if let Err(_) = P01Topic::<R>::publish(
                    super::unix_minute(0),
                    &topic_id,
                    Some(secret_rotation_function.clone()),
                    initial_secret_hash,
                    node_id,
                    &node_signing_key,
                    gossip_receiver.neighbors().await,
                )
                .await
                {
                    println!("failed to publish record");
                    sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).max(60);
                    continue;
                }
                println!("published record");
                backoff = 1;
                sleep(Duration::from_secs(rand::random::<u64>() % 60)).await;
            }
        })
    }

    pub fn split(&self) -> (P01GossipSender, P01GossipReceiver) {
        (self.gossip_sender.clone(), self.gossip_receiver.clone())
    }
}

// Static impls
impl<R: SecretRotation + Default + Clone + Send + 'static> P01Topic<R> {
    fn signing_keypair(topic_id: &P01TopicId, unix_minute: u64) -> ed25519_dalek::SigningKey {
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

pub trait AutoDiscoveryBuilder {
    #[allow(async_fn_in_trait)]
    async fn spawn_with_auto_discovery<R: SecretRotation + Default + Clone + Send + 'static>(
        self,
        endpoint: Endpoint,
        secret_rotation_function: Option<R>,
    ) -> Result<P01Gossip<R>>;
}

impl AutoDiscoveryBuilder for iroh_gossip::net::Builder {
    async fn spawn_with_auto_discovery<R: SecretRotation + Default + Clone + Send + 'static>(
        self,
        endpoint: Endpoint,
        secret_rotation_function: Option<R>,
    ) -> Result<P01Gossip<R>> {
        Ok(P01Gossip {
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
        topic_id: P01TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<P01Topic<R>>;
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

impl<R: SecretRotation + Default + Clone + Send + 'static> AutoDiscoveryGossip<R> for P01Gossip<R> {
    async fn subscribe_and_join_with_auto_discovery(
        &self,
        topic_id: P01TopicId,
        initial_secret: &Vec<u8>,
    ) -> Result<P01Topic<R>> {
        P01Topic::bootstrap(
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
