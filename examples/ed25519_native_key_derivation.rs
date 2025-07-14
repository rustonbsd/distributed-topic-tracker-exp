use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;

fn derive_child_sec(pub_key: &VerifyingKey, query: &str) -> anyhow::Result<SigningKey> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(pub_key.as_bytes());
    hasher.update(query.as_bytes());
    let query_hash: [u8; 64] = hasher.finalize().into();

    let new_signing_key: [u8; 32] = query_hash[..32].try_into()?;

    Ok(SigningKey::from_bytes(&new_signing_key))
}

fn derive_child_pub(pub_key: &VerifyingKey, query: &str) -> anyhow::Result<VerifyingKey> {
    let super_secret_no_one_knows_its_here = derive_child_sec(pub_key, query)?;
    Ok(VerifyingKey::from(&super_secret_no_one_knows_its_here))
}

fn main() -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);

    // Generate a random secret key
    let root_secret_key = signing_key.clone();
    let root_public_key = VerifyingKey::from(&signing_key);

    println!("Root public key: \n{}", z32::encode(root_public_key.as_bytes()));
    println!("Root secret key: \n{}", z32::encode(root_secret_key.as_bytes()));
    println!();

    // Derive child key from public key
    // NOTE: clients will only be able to derive the public key from the same query and root public key
    //      as the publisher (ed25519 doesn't support key derivation natively like secp256k1 does). 
    //      So the only way to make this work with this curve natively is to accept
    //      the trade off that malicious publishers can use the child secret key 
    //      (that is unavoidably known to non-authors) to override the child public key
    //      on for example Pkarr; but if the root_key is used to sign every query message published then
    //      clients can verify the signature and the worst that can happen is a "DoS" attack. 
    //      But to my understanding (which is to be questioned ^^) pkarr also doesn't protect against this attack.
    //      (I am using pkarr here as an example but the same applies to the underlying bittorrent dht with the extension:
    //       https://www.bittorrent.org/beps/bep_0044.html).
    //     PLEASE CORRECT ME IF I AM WRONG or ask questions, we should investigate any doubts
    //      (especially since I am not a cryptography expert ^^ - neither am I!).
    let child_pub_key = derive_child_pub(&root_public_key, "example_query")?;
    println!("Child public key (derived from public key): \n{}", z32::encode(child_pub_key.as_bytes()));
    println!();

    // Derive child key from secret key
    let child_sec_key = derive_child_sec(&root_public_key, "example_query")?;
    println!("Child public key (derived from secret key): \n{}",z32::encode(VerifyingKey::from(&child_sec_key).as_bytes()));
    println!();
    println!("Child secret key (derived from secret key): \n{}", z32::encode(child_sec_key.as_bytes()));
    println!();

    assert_eq!(
        child_pub_key.to_bytes(),
        VerifyingKey::from(&child_sec_key).to_bytes()
    );

    Ok(())
}
