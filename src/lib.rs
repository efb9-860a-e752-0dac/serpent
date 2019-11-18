//! # Serpent
//!
//! `serpent-cipher` is an implementation of the
//! [Serpent cipher](https://www.cl.cam.ac.uk/~rja14/serpent.html) most
//! known for being one of the leading candidates for AES.
//!
//! It's based on the unoptimized C reference implementation and uses
//! some of the test vectors given in their submission package to
//! validate the implementation.
//!
//! For easy interoperation with Rust crypto this crate implements
//! the `BlockCipher` trait from the `block-cipher-trait` crate.

mod keys;
mod tables;
mod transforms;

pub use block_cipher_trait;
pub use block_cipher_trait::generic_array;
pub use generic_array::typenum;

use block_cipher_trait::BlockCipher;
use generic_array::GenericArray;
use std::convert::TryInto;
use typenum::{U1, U16, U32};

use transforms::{apply_permutation, apply_s_hat, apply_s_hat_inv, apply_xor_table};

const PHI: u32 = 0x9e37_79b9;
const ROUNDS: usize = 32;

/// The Serpent cipher instance
///
/// Implements both a friendly `u128` encryption interface as well as the
/// common Rust crypto `block_cipher_trait::BlockCipher` trait for easy use
/// in stream cipher algorithms.
pub struct Serpent {
    subkeys: keys::Subkeys,
}

impl Serpent {
    /// Constructs an instance from a little-endian binary key,
    /// only takes keys whose length are a multiple of eight bits.
    pub fn with_binary_key(key: &[u8]) -> Option<Serpent> {
        let expanded_key = keys::expand_key(key, key.len() * 8)?;
        Some(Serpent {
            subkeys: keys::derive_subkeys(expanded_key),
        })
    }

    /// Constructs an instance from a big-endian text representation
    /// of a hexadecimal key, e.g. `"abcdef0123456"`. Key length is
    /// assumed to be a multiple of four bits.
    pub fn with_text_key(key: &str) -> Option<Serpent> {
        let binary_key = keys::parse_text_key(key)?;
        Serpent::with_binary_key(&binary_key)
    }

    /// Easy encryption of a block stored in a 128-bit little-endian integer
    pub fn encrypt_block(&self, block: u128) -> u128 {
        let mut b_hat = apply_permutation(&tables::IP, block);
        for i in 0..ROUNDS {
            b_hat = do_round(i, b_hat, &self.subkeys);
        }
        apply_permutation(&tables::FP, b_hat)
    }

    /// Easy decryption of a block stored in a 128-bit little-endian integer
    pub fn decrypt_block(&self, block: u128) -> u128 {
        let mut b_hat = apply_permutation(&tables::IP, block);
        for i in (0..ROUNDS).rev() {
            b_hat = do_round_inv(i, b_hat, &self.subkeys);
        }
        apply_permutation(&tables::FP, b_hat)
    }
}

/// Implements BlockCipher with 256-bit keys as the favoured fixed key length.
/// Other variable key lengths are not yet implemented.
impl BlockCipher for Serpent {
    type KeySize = U32;
    type BlockSize = U16;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U32>) -> Self {
        Serpent::with_binary_key(&key).unwrap()
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let input = u128::from_le_bytes(block.as_slice().try_into().unwrap());
        let output = self.encrypt_block(input);
        block.copy_from_slice(&u128::to_le_bytes(output));
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let input = u128::from_le_bytes(block.as_slice().try_into().unwrap());
        let output = self.decrypt_block(input);
        block.copy_from_slice(&u128::to_le_bytes(output));
    }
}

fn do_round(i: usize, b_hat_i: u128, k_hat: &keys::Subkeys) -> u128 {
    let xored = b_hat_i ^ k_hat[i];
    let s_hat_i = apply_s_hat(i, xored);
    if i <= ROUNDS - 2 {
        apply_xor_table(&tables::LT, s_hat_i)
    } else {
        s_hat_i ^ k_hat[ROUNDS]
    }
}

fn do_round_inv(i: usize, b_hat_i_plus_1: u128, k_hat: &keys::Subkeys) -> u128 {
    let s_hat_i = if i <= ROUNDS - 2 {
        apply_xor_table(&tables::LT_INV, b_hat_i_plus_1)
    } else {
        b_hat_i_plus_1 ^ k_hat[ROUNDS]
    };
    let xored = apply_s_hat_inv(i, s_hat_i);
    xored ^ k_hat[i]
}
