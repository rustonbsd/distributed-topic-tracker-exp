use std::fmt::Display;

use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT, traits::IsIdentity};
use hmac::{Hmac, Mac};
use primitive_types::U256;
use sha2::{Digest, Sha512};

#[derive(Debug, Clone)]
struct ExtendedPrivateKey {
    pub key_left: [u8; 32],
    pub key_right: [u8; 32],
    pub public: Public,
}

#[derive(Debug, Clone)]
struct Public {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl Display for ExtendedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("key_left", &z32::encode(&self.key_left))
            .field("key_right", &z32::encode(&self.key_right))
            .field("public_key", &z32::encode(&self.public.key))
            .field("chain_code", &z32::encode(&self.public.chain_code))
            .finish()
    }
}

impl Display for Public {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Public")
            .field("public_key", &z32::encode(&self.key))
            .field("chain_code", &z32::encode(&self.chain_code))
            .finish()
    }
}

// "Recall that FK stands for HMAC-SHA512 with key K."
type HmacSha512 = Hmac<Sha512>;

// Taken from: https://docs.rs/curve25519-dalek/4.2.0/curve25519_dalek/constants/constant.BASEPOINT_ORDER.html
const BASEPOINT_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn generate_root_key(master_secret: &[u8; 32]) -> anyhow::Result<ExtendedPrivateKey> {
    let root_secret_mac = HmacSha512::new_from_slice(master_secret)?
        .finalize()
        .into_bytes();

    let mut root_secret_key_left = [0u8; 32];
    let mut root_secret_key_right = [0u8; 32];
    root_secret_key_left.copy_from_slice(&root_secret_mac[..32]);
    root_secret_key_right.copy_from_slice(&root_secret_mac[32..]);

    // "If the third highest bit of the last byte of kL is not zero, discard this key"
    if root_secret_key_left[31] & 0b00100000 != 0 {
        return Err(anyhow::anyhow!(
            "third highest bit requirement not met. invalid root key"
        ));
    }

    root_secret_key_left[0] &= 0b11111000; // "the lowest 3 bits of the first byte of kL of are cleared"
    root_secret_key_left[31] &= 0b01111111; // " the highest bit of the last byte is cleared"
    root_secret_key_left[31] |= 0b01000000; // " the second highest bit of the last byte is set"

    // [kL]B = "interpret kL as a little-endian integer and perform a fixed-base scalar multiplication"
    let key_left_scalar = Scalar::from_bytes_mod_order(root_secret_key_left.clone());
    let root_public_key = (ED25519_BASEPOINT_POINT * key_left_scalar)
        .compress()
        .to_bytes();

    // "Derive c ← H256(0x01|| ̃k), where H256 is SHA-256, and call it the root chain code"
    let mut h256 = sha2::Sha256::new();
    h256.update(&[0x01]);
    h256.update(&master_secret);
    let mut root_chain_code = [0u8; 32];
    root_chain_code.copy_from_slice(&h256.finalize());

    Ok(ExtendedPrivateKey {
        key_left: root_secret_key_left,
        key_right: root_secret_key_right,
        public: Public {
            key: root_public_key,
            chain_code: root_chain_code,
        },
    })
}

fn derive_child_from_secret_key_non_hardened(
    parent_key: &ExtendedPrivateKey,
    i: u32,
) -> anyhow::Result<ExtendedPrivateKey> {
    if i >= i32::MAX as u32 {
        return Err(anyhow::anyhow!("index > 2^31: hardened keys not supported"));
    };

    let mut z_mac = HmacSha512::new_from_slice(&parent_key.public.chain_code)?;
    z_mac.update(&[0x02]);
    z_mac.update(&parent_key.public.key);
    z_mac.update(&i.to_le_bytes());
    let z = z_mac.finalize().into_bytes();

    let mut z_left = [0u8; 32];
    let mut z_right = [0u8; 32];
    z_left.copy_from_slice(&z[..32]);
    z_right.copy_from_slice(&z[32..]);

    let z_left_shifted = {
        let mut n = U256::from_little_endian(&z_left);
        n <<= 3;
        n.to_little_endian()
    };

    // "kL ← 〈 8[ZL] + [ kPL ]〉, (1)"
    let key_left = {
        let mut n = U256::from_little_endian(&z_left_shifted);
        n += U256::from_little_endian(&parent_key.key_left);
        n.to_little_endian()
    };

    // "If kL is divisible by the base order n, discard the child."
    let base_order = U256::from_little_endian(&BASEPOINT_ORDER);
    if U256::from_little_endian(&key_left) % base_order == U256::zero() {
        return Err(anyhow::anyhow!(
            "kL is divisible by the base order n, discard child key"
        ));
    }

    // "kR ← 〈 [ZR] + [ kPR ] mod 2 256 〉, (2)"
    let key_right = {
        let mut n = U256::from_little_endian(&z_right);
        n += U256::from_little_endian(&parent_key.key_right);
        n.to_little_endian()
    };

    // "ci ← FcP(0x03||AP ||i), i < 231"
    let mut chain_code_mac = HmacSha512::new_from_slice(&parent_key.public.chain_code)?;
    chain_code_mac.update(&[0x03]);
    chain_code_mac.update(&parent_key.public.key);
    chain_code_mac.update(&i.to_le_bytes());
    let chain_code: [u8; 32] = chain_code_mac.finalize().into_bytes()[32..].try_into()?;

    // "The child public key Ai is derived as Ai = [ kL]B."
    let public_key = {
        let key_left_scalar = Scalar::from_bytes_mod_order(key_left);
        (ED25519_BASEPOINT_POINT * key_left_scalar)
            .compress()
            .to_bytes()
    };

    Ok(ExtendedPrivateKey {
        key_left,
        key_right,
        public: Public {
            key: public_key,
            chain_code,
        },
    })
}

fn derive_child_from_public_key_non_hardened(public: &Public, i: u32) -> anyhow::Result<Public> {
    if i >= i32::MAX as u32 {
        return Err(anyhow::anyhow!("index > 2^31: hardened keys not supported"));
    };

    // "Z ← FcP(0x02||AP ||i), i < 231"
    let mut z_mac = HmacSha512::new_from_slice(&public.chain_code)?;
    z_mac.update(&[0x02]);
    z_mac.update(&public.key);
    z_mac.update(&i.to_le_bytes());
    let z_pub = z_mac.finalize().into_bytes();
    let z_pub_left_shifted = {
        let mut n = U256::from_little_endian(&z_pub[..32]);
        n <<= 3;
        n.to_little_endian()
    };

    // "Ai ← AP + [8 ZL]B"
    let public_key = {
        let z_pub_left_scalar = Scalar::from_bytes_mod_order(z_pub_left_shifted);
        let parent_public_key_point =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&public.key)?
                .decompress()
                .ok_or(anyhow::anyhow!("invalid parent public key"))?;
        let child_public_key_point =
            parent_public_key_point + (ED25519_BASEPOINT_POINT * z_pub_left_scalar);

        // "If Ai is the identity point (0, 1), discard the child."
        if child_public_key_point.is_identity() {
            return Err(anyhow::anyhow!(
                "child public key is the identity point, discard child key"
            ));
        }
        child_public_key_point.compress().to_bytes()
    };

    // "ci ← FcP(0x03||AP ||i), i < 2^31"
    let mut chain_code_mac = HmacSha512::new_from_slice(&public.chain_code)?;
    chain_code_mac.update(&[0x03]);
    chain_code_mac.update(&public.key);
    chain_code_mac.update(&i.to_le_bytes());
    let chain_code: [u8; 32] = chain_code_mac.finalize().into_bytes()[32..].try_into()?;

    Ok(Public {
        key: public_key,
        chain_code,
    })
}

fn main() -> anyhow::Result<()> {
    let master_secret = [43u8; 32];
    let root_key = generate_root_key(&master_secret)?;
    println!("Root key: {}", root_key);

    let (child_key, index) = {
        let mut i = 0;
        loop {
            if let Ok(child_key) = derive_child_from_secret_key_non_hardened(&root_key, i) {
                break (child_key, i)
            }
            println!("i: {}", i);
            i+=1;
        }
    };
    println!("Child key (index: {}): {}", index, child_key);

    let (child_pub_key, index) = {
        let mut i = 0;
        loop {
            if let Ok(child_pub_key) = derive_child_from_public_key_non_hardened(&root_key.public, i) {
                break (child_pub_key, i)
            }
            i+=1;
        }
    };
    println!("Child public key (index: {}): {}", index, child_pub_key);


    // Need to implement signing or use a crate for this:
    // https://github.com/typed-io/rust-ed25519-bip32/tree/master

    assert_eq!(child_key.public.key, child_pub_key.key);

    Ok(())
}
