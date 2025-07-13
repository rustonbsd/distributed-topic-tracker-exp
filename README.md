# distributed-topic-tracker-exp
iroh-gossip + mainline + queryable secp256k1 or ed25519 key derivation.

# Examples
secp256k1 native key derivation example: `cargo run --example secp256k1_native_key_derivation`

if we use the secp256k1 curve and derive query keys via native key derivation on this curve, we safe a bunch of complexity and can use existing crates for *all* the crypto stuff wich is generally a good thing i think. but we have to build directly on mainline and the queries will ultimitely convert to bittorrent info_hashes that. (same as pkarr uses).

ed25519 bip32 key derivation example: `cargo run --example bip32_ed25519_key_derivation`

if we use the ed25519 curve with the bip32 extension described in the paper and implemented in the example above, we can calculate the "query" as the "index" via for example hashing the query and taking the first 32 bytes of the hash as the index and then itterating from that index until we find a valid child key. This would be deterministic and allow for publisher and client to derive the identical child pub keys (and secret key for publisher) if the root_public_key and root_chain_code are known (they don't need to change). this is not compatible with pkarr or the ed25519 crate. keys cant just be loaded in and pub keys calculated from secret keys since the ed25519-dalek crate doesn't work with expanded keys directly. Signing and verification implemented for making sure the math works out and it does wow :).

ed25519 native key derivation example: `TODO`