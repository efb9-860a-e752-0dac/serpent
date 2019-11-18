use crate::tables::*;
use crate::transforms::*;
use crate::PHI;
use crate::ROUNDS;

pub(crate) type Key = [u8; 32];
pub(crate) type Subkey = u128;
pub(crate) type Subkeys = [Subkey; ROUNDS + 1];

pub(crate) fn parse_text_key(key: &str) -> Option<Vec<u8>> {
    if !key.is_ascii() {
        return None;
    }
    let bytes = key.as_bytes();
    if bytes.iter().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }
    let len = bytes.len();
    let len_bits = len * 4;
    if len_bits > 256 {
        return None;
    }
    let mut key = bytes
        .iter()
        .rev()
        .enumerate()
        .fold([0u8; 32], |mut k, (place, digit)| {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => unreachable!(),
            } as u8;
            let offset = (place & 1) * 4;
            k[place / 2] |= nibble << offset;
            k
        });

    if len_bits < 256 {
        let offset = (len & 1) * 4;
        key[len / 2] |= 1 << offset;
    }
    Some(key[..].into())
}

pub(crate) fn expand_key(source: &[u8], len_bits: usize) -> Option<Key> {
    let source_bits = source.len() * 8;

    // Bail out if the key material is too long or if the stated bit length
    // mismatches the byte length.
    if source_bits > 256 || len_bits > 256 || source_bits < len_bits {
        return None;
    }

    let mut key = [0u8; 32];
    key[..source.len()].copy_from_slice(&source);
    if len_bits < 256 {
        let byte_index = len_bits / 8;
        let bit_index = len_bits % 8;
        key[byte_index] |= 1 << bit_index;
    }

    Some(key)
}

pub(crate) fn derive_subkeys(key: Key) -> [Subkey; ROUNDS + 1] {
    use byteorder::{ByteOrder, LE};
    use std::convert::TryInto;
    let mut w = [0u32; 140];
    LE::read_u32_into(&key, &mut w[..8]);

    for i in 0..132 {
        let slot = i + 8;
        w[slot] = (w[slot - 8] ^ w[slot - 5] ^ w[slot - 3] ^ w[slot - 1] ^ PHI ^ i as u32)
            .rotate_left(11);
    }

    let w = &w[8..];
    let mut k = [0u32; 132];
    for i in 0..=ROUNDS {
        let s_idx = (ROUNDS + 3 - i) % ROUNDS;
        for j in 0..32 {
            let src = (&w[4 * i..4 * i + 4]).try_into().unwrap();
            let input = gather_nibble(src, j);
            let output = apply_s(s_idx, input);

            let dst = (&mut k[4 * i..4 * i + 4]).try_into().unwrap();
            scatter_nibble(output, dst, j);
        }
    }
    // distribute 32-bit values k[] into 128-bit subkeys
    let mut subkeys = [0u128; ROUNDS + 1];
    for i in 0..33 {
        subkeys[i] = u128::from(k[4 * i])
            | u128::from(k[4 * i + 1]) << 32
            | u128::from(k[4 * i + 2]) << 64
            | u128::from(k[4 * i + 3]) << 96;
    }

    // apply IP to the key
    for subkey in &mut subkeys[..] {
        *subkey = apply_permutation(&IP, *subkey);
    }

    subkeys
}

fn gather_nibble(words: &[u32; 4], bit_idx: usize) -> u8 {
    let mut output = 0u8;
    for (i, word) in words.iter().enumerate() {
        let bit = ((word >> bit_idx) & 1) as u8;
        output |= bit << i;
    }
    output
}

fn scatter_nibble(nibble: u8, words: &mut [u32; 4], out_bit_idx: usize) {
    assert_eq!(words.len(), 4);
    for (i, word) in words.iter_mut().enumerate() {
        let bit = u32::from((nibble >> i) & 1);
        *word |= bit << out_bit_idx;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_keys() {
        // 128 bits, observe 0b0001 nibble halfway through output and rest 0b0000
        let binary_key = super::parse_text_key("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            binary_key,
            [
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            ]
        );

        // 252 bits, observe 0b0001 nibble in most significant nibble
        let binary_key = super::parse_text_key(
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            binary_key,
            [
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x11, //
            ]
        );

        // 256 bits, observe full key represented
        let binary_key = super::parse_text_key(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            binary_key,
            [
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, //
            ]
        );
    }
}
