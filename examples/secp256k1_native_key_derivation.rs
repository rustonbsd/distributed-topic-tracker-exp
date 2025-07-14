// Non-Hardned key, therefore we can do simple scalar arithmetic with pub and private keys
// and keep them consistent as long as we derive the "scalar" from the query deterministically.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};


// Key are the derive_child from secret or pub key functions:
fn derive_child_pub(pub_key: &PublicKey, query: &str) -> anyhow::Result<PublicKey> {
    let secp = Secp256k1::new();

    // Compute query Scalar:
    let mut hasher = Sha256::new();
    hasher.update(b"query:");
    hasher.update(query.as_bytes());
    let query_hash: [u8; 32] = hasher.finalize().into();

    // Parse hash as query Scalar and treat it as a SecretKey
    // calculate the public key from the newly created SecretKey/query Scalar.
    let query_scalar = SecretKey::from_byte_array(query_hash)?;
    let query_point = PublicKey::from_secret_key(&secp, &query_scalar);

    // now we "add" the query_point to the parent public key (this fails if the resulting point is at infinity)
    // child_public_key = parent_public_key + query_scalar*G
    let child_public_key = pub_key.combine(&query_point)?;

    Ok(child_public_key)
}

fn derive_child_sec(sec_key: &SecretKey, query: &str) -> anyhow::Result<SecretKey> {
    // Compute query Scalar:
    let mut hasher = Sha256::new();
    hasher.update(b"query:");
    hasher.update(query.as_bytes());
    let query_hash: [u8; 32] = hasher.finalize().into();

    // Parse hash as query Scalar and treat it as a SecretKey
    let query_scalar = SecretKey::from_byte_array(query_hash)?;

    // now we "tweak" the root secret key by query_scalar amount mod curve order:
    // Child key = (parent_key + query_scalar) mod n
    let child_secret_key = sec_key.add_tweak(&query_scalar.into())?;

    Ok(child_secret_key)
}

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // Generate a random secret key
    let root_secret_key = SecretKey::new(&mut secp256k1::rand::rng());
    let root_public_key = PublicKey::from_secret_key(&secp, &root_secret_key);

    println!("Root public key: \n{}", z32::encode(&root_public_key.serialize()));
    println!("Root secret key: \n{}", z32::encode(&root_secret_key.secret_bytes()));
    println!();

    // Derive child key from public key
    let child_pub_key = derive_child_pub(&root_public_key, "example_query")?;
    println!("Child public key (derived from public key): \n{}", z32::encode(&child_pub_key.serialize()));
    println!();

    // Derive child key from secret key
    let child_secp = Secp256k1::new();
    let child_sec_key = derive_child_sec(&root_secret_key, "example_query")?;
    println!("Child public key (derived from secret key): \n{}",z32::encode(&PublicKey::from_secret_key(&child_secp, &child_sec_key).serialize()));
    println!();
    println!("Child secret key (derived from secret key): \n{}", z32::encode(&child_sec_key.secret_bytes()));
    println!();

    assert_eq!(
        child_pub_key.serialize(),
        PublicKey::from_secret_key(&secp, &child_sec_key).serialize()
    );

    Ok(())
}
