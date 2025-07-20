# Core Problems

## 1. Discovery Mechanism

- **Goal:** provide new node with valid node record from within gossip swarm without having to parse through to many records
- **Core Question:** "Where do I look?"
- **Solution-1:** mainline mutable records from ed25519 derived `keypairs` and `salt`. Multiple record versions can be recovered from a single `get_all(pubkey, salt)` call (a vec of `MutableItem` is returned). Key derivation is coupled to the topic name and the current unix minute = `floor(unixtime/60)` to prevent replay attacks and stale record graveyarding.
  
## 2. Record Identity
- **Goal:** prove that a record was written by the node it claims to be from
- **Core Question:** "How do I verify the author of a record?"
- **Solution-1:** ed25519 signature over record content tied to current unix miunte to prevent replay attacks.

## 3. Security / Proof of Mainnet Connectivity
- **Goal:** prove that the node in the record has established and maintained live, interactive connections with a random, statistically significant sample of the honest-majority network
- **Core Question:** "Is this node a citizen of the real network, or just an island or a sybil?"
- **Solution-1:** proof of relay, in a nutshell you show the output of a procedure involvingthe messages you have received so that joining nodes can compare to what other nodes have as their message flow without copying someone else's message flow, then go from there.
- **Solution-2:** proof of liveness, you have the 5 active peers (every node tries to have 5 acrive peers and 30 passive 30 passive ones in the iroh-gossip's [HyParView](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf) default implementation) sign a unix_minute derived hash for example: `sig( hash( topic + unix_minute + node_id ) )`. this is **not** save from sybil attacks and i am not a big fan of it right now.
- **Solution-3:** iroh-gossip is inherenetly unsafe and designed to only give out a node id to a trust worthy set of peers. This is an important consideration since any "topic tracker" that exposes node ids into a gossip network that has no build in mechanism to keep out bad actors and protocol abusers. this makes the publishing of node ids and the topics they belong to very dangerous. Considering this, a topic needs a "secret" that can only be derived based on information the joining nodes already have (the individual app implementations can decide on their own). So we get a secret and we use it to generate another keypair, this time for encryption. we can stick to curve 25519 or some other encryption compatible key schema. this is to make sure we never publicly expose the node ids alongside the topic. I build a "gossip with permissions" on top of iroh-gossip before and I created a crate for translating ed25519 keys to X25519 keys compatible with hpke encryption: [https://github.com/rustonbsd/ed25519-dalek-hpke](https://github.com/rustonbsd/ed25519-dalek-hpk) (this should be safe enough for our purposes). tldr: we create one time encryption keys and encrypt the record with it and then use the shared secret to encrypt the one time encryption key and append it to the record. Nodes with the secret can then decrypt the key and subsequently the record. If we rely on this shared secret we are vulnerable to key compromize, but since iroh-gossip leaves security to the app developer, I think we can do the same thing. Implementations can have access to secret rotation and decide what secret seed is used when or so. (This route is my vote)

## 4. System Stability Mechanism
- **Goal:** prevent the discovery mechanism from being overloaded by too many writes (DDoS/spam) or synchronized access patterns (thundering herd)
- **Core Question:** "What gives a node the right to write, and what stops everyone from writing at the same time?"
- **Example solutions:** random time delays (since we can trust everyone), Proof-of-Work, Verifiable Delay Functions (VDFs), or probabilistic slotting schemes that ensure writes are rate-limited and desynchronized
- **Solution-1:** a combination of random time delays (since we can trust everyone) and a simple multi slotting scheme. Lets say N slots and you calculate the solt (we use the different salts in mutable record writes as different slots) `salt = hash ("slot:" + (hash( topic + unix_minute + my_node_id ) % N) )`

---

# My Proposal 
the following is my proposal based on the solutions i voted for above.
this doesn't mean that the solutions are right nor that there aren't better ones i haven't considered.
but I think we could use everything above this line to formalize the requirements some more.

## Publishing procedure (simple)

1. get all records from `get_all(pubkey, salt)` where pubkey is the derived signature public key from the topic and unix minute as follows: `keypair_seed = hash( topic + unix_minute )`
2. decrypt all records withe the shared secret
3. verify the records
4. if 1 <= valid records found, sleep for some time then repeat 1
5. if only invalid record or no records found, write your own record into your slot for the current unix minute.
6. sleep for some time then repeat 1

## Bootstrap procedure (simple)

1. get all records from `get_all(pubkey, salt)` where pubkey is the derived signature public key from the topic and unix minute as follows: `keypair_seed = hash( topic + unix_minute )` and the salt is `salt = hash ( "slot:" + i)` where `i` is a randomly picked slot from the range 0 to N-1
2. if no records found, repeat step 1 with `i = (i + 1) % N`
3. for all found records, decrypt with shared secret and verify the record
4. add all found records to a list of bootstrap nodes, if all collected bootstrap node lists contain more then `MIN_BOOTSTRAP_NODES` nodes, we join the gossip topic in iroh-gossip
5. if failed, continue with 1
6. on succes, switch to publisher mode


## Record structure

```rust
//  297 bytes at S=5
struct Record {
    // Record Content
    topic: [u8; 32],                // sha512( topic_string )[..32]
    unix_minute: u64,               // floor(unixtime / 60)
    slot: u8,                // slot number this record was written into
    node_id: [u8; 32],              // publisher ed25519 public key
    active_peers: [[u8; 32]; S],    // S=5 node ids of the active view of the publisher

    // Record Signature
    signature: [u8; 64],            // ed25519 signature over above fields
                                    // signed by the publishers ed25519 private key
                                    // (the one node_id is the public key for)
  
}

// >= 329 bytes at S=5
struct EncryptedRecord {
    encrypted_record: Vec<u8>,      // encrypted Record
    
    // x25519 one time key used for encrypting the record
    // the key itself is encrypted using a an encryption keypair
    // derived from the shared secret
    // (and maybe topic and unix minute as well, but i think we can
    // leave that to the individual app implementations)
    encrypted_decryption_key: [u8; 32],     
}
```

## Verification

1. verify the signature against the node_id and the concatenated `// Record Content` fields as the data for the sigature verification
2. verify the unix_minute matches the current unix minute the key pair was derived from
3. verify the slot matches the slot number the record was written into
4. optional (verify that active_peers doesn't contains the node_id of the publisher)

## Encryption, Decryption
I used a one time key encryption scheme in the advanced-gossip project, we can use (for now) the same here. 
The above mentioned [https://github.com/rustonbsd/ed25519-dalek-hpke](https://github.com/rustonbsd/ed25519-dalek-hpk) crate was written for exactly this purpose.

The reference below uses one time keys to sign records for all peers that are allowed to read it. 
That part can be ignored, it is about the onetime keys and the interplay between ed25519 and hpke.

here the one time enc code as a reference: https://github.com/rustonbsd/advanced-gossip/blob/main/src/structs.rs#L239-L264