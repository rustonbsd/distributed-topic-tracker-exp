# Architecture

This document explains how the library operates. It complements the spec
(PROTOCOL.md) with high-level structure, data flows, and failure handling.

Contents:
- System overview
- Bootstrapping
- Publishing
- Bubble detection and merging
- Data model
- Failure modes
- Tuning

## System overview

Components:
- iroh endpoint and gossip
- Auto-discovery (bootstrap loop)
- Publisher (background task)
- DHT client (mutable records)
- Crypto (signing, encryption, secret rotation)

```mermaid
flowchart LR
  subgraph App
    A[Your App]
  end

  subgraph Iroh
    E[Endpoint]
    G[Gossip]
  end

  subgraph AutoDiscovery
    B[Bootstrap Loop]
    P[Publisher]
  end

  subgraph DHT
    D[(Mainline DHT)]
  end

  A --> E --> G
  G <---> B
  G <---> P
  B <--> D
  P <--> D
```

Node lifecycle:
- Start iroh endpoint
- Start gossip
- Auto-discovery:
  - Join topic, attempt bootstrap, connect
  - Spawn publisher on success

State machine:

```mermaid
stateDiagram-v2
  [*] --> Idle
  Idle --> Discovering
  Discovering --> Joining
  Joining --> Joined
  Joined --> Publishing
  Publishing --> Joined : backoff or success loop
  Discovering --> Discovering : retry/jitter
  Joining --> Discovering : no peers
```

## Bootstrapping

Goal: connect to at least one topic peer.

Sequence:

```mermaid
sequenceDiagram
  participant Node
  participant DHT
  participant Gossip

  Node->>Gossip: subscribe(topic_hash)
  Node->>DHT: get_mutable(signing_pub, salt, 10s)
  DHT-->>Node: encrypted records (0..N)
  Node->>Node: decrypt, verify, filter(not self)
  alt candidates exist
    loop each candidate
      Node->>Gossip: join_peers([node_id])
      Node->>Node: sleep 100ms
      Gossip-->>Node: NeighborUp?
    end
    Node->>Node: final wait 500ms
  else no candidates
    Node->>Node: maybe publish own (rate-limited)
  end
  Node->>Node: joined? if yes, spawn publisher
```

Key points:
- First iteration: also check previous unix minute.
- Pacing avoids bursts and “bubbles.”
- Keep trying until joined.

Pseudocode:

```text
loop:
  if joined(): return sender, receiver

  minute = first_attempt ? -1 : 0
  recs = get_unix_minute_records(minute)

  if recs.is_empty():
    maybe_publish_this_minute()
    sleep(100ms)
    continue

  for peer in extract_bootstrap_nodes(recs):
    if joined(): break
    join_peer(peer)
    sleep(100ms)

  sleep(500ms)
  if joined(): return
  maybe_publish_this_minute()
  sleep(100ms)
```

## Publishing

Goal: publish active participation without overloading DHT.

Flow:

```mermaid
flowchart TD
  A[Start Cycle] --> B[Get minute=now]
  B --> C[Discover existing records]
  C --> D[Filter active participants]
  D --> E{>= 10 active?}
  E -- Yes --> F[Stop rate-limited]
  E -- No --> G[Build record: peers + msg hashes]
  G --> H[Sign + Encrypt]
  H --> I[Publish with retries + jitter]
  I --> J[Return records, including own on success]
```

Pseudocode:

```text
records = get_unix_minute_records(now)
active = filter_active(records)
if active.len >= 10: return records

rec = make_record(neighbors(<=5), last_hashes(<=5))
enc = encrypt(sign(rec))
publish_with_retry(enc, retries=3, jitter=0..2000ms)
return records + [rec_if_success]
```

## Bubble detection and merging

Signal 1: small cluster \(neighbors < 4\).
- Extract peer ids from discovered records.
- Exclude zeros, self, current neighbors.
- Join up to MAX_JOIN_PEERS_COUNT.

Signal 2: non-overlapping message sets.
- Compare local last_message_hashes with others.
- If disjoint, collect publisher + peers from those records.
- Attempt joins to bridge partitions.

Decision graph:

```mermaid
flowchart LR
  A[Post-Publish Records] --> B{neighbors < 4?}
  B -- Yes --> C[Join peers from records]
  B -- No --> D{local_msgs >= 1?}
  D -- No --> E[Sleep random 0..60s]
  D -- Yes --> F{overlap with others?}
  F -- No --> G[Join from non-overlap records]
  F -- Yes --> E
```

## Data model

Record (summary):
- topic hash (32)
- unix_minute (u64)
- node_id (publisher)
- active_peers[5] (node ids)
- last_message_hashes[5]
- signature (64)

EncryptedRecord:
- encrypted_record (Vec)
- encrypted_decryption_key (Vec)

Diagram:

```mermaid
classDiagram
  class Record {
    +topic: [u8;32]
    +unix_minute: u64
    +node_id: [u8;32]
    +active_peers: [[u8;32];5]
    +last_message_hashes: [[u8;32];5]
    +signature: [u8;64]
  }

  class EncryptedRecord {
    +encrypted_record: Vec<u8>
    +encrypted_decryption_key: Vec<u8>
  }
```

Key derivation:

```mermaid
flowchart TD
  T[topic_hash] --> A[SHA512 topic+minute]
  M[unix_minute] --> A
  A --> S[signing_keypair seed -> Ed25519]
  A --> L[salt = first 32 bytes]

  T --> R[secret_rotation topic,minute,initial_secret_hash]
  M --> R
  R --> E[encryption_keypair seed -> Ed25519]
```

## Failure modes

- DHT get timeout:
  - Return empty set; continue loop.
- Decrypt/verify failure:
  - Drop record; proceed.
- Publish failure:
  - Exponential backoff (1..60 s), then retry.
- Join failure:
  - Continue to next peer; final 500 ms wait; loop.

## Tuning

- Per-minute cap \(N_{active} \ge 10\) gates publishing.
- Pacing (100 ms) reduces bursts.
- Backoff (1..60 s) stabilizes DHT load.
- Message window size (5 peers, 5 hashes) is a trade-off:
  - Larger window = better visibility, larger records.
  - Smaller window = lower bandwidth, less overlap detection.

Parameters:
- MAX_BOOTSTRAP_RECORDS
- MAX_JOIN_PEERS_COUNT
- DHT timeout
- Retry count and jitter
- Join pacing and final wait
- Publisher backoff and success jitter