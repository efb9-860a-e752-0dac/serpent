mod tables;

type Key = [u8; 32];
type Subkey = u128;
type Subkeys = [Subkey; ROUNDS + 1];

const PHI: u32 = 0x9e3779b9;
const ROUNDS: usize = 32;

fn apply_s(s_idx: usize, nibble: u8) -> u8 {
    tables::SBOX[s_idx % 8][nibble as usize]
}

fn apply_s_inv(s_idx: usize, nibble: u8) -> u8 {
    tables::SBOX_INV[s_idx % 8][nibble as usize]
}

fn apply_s_hat(s_idx: usize, source: u128) -> u128 {
    let mut res = 0u128;
    for i in 0..32 {
        let src_nibble = (source >> (i * 4)) as u8 & 0xf;
        let res_nibble = apply_s(s_idx, src_nibble) as u128;
        res |= res_nibble << (i * 4);
    }
    res
}

fn apply_s_hat_inv(s_idx: usize, source: u128) -> u128 {
    let mut res = 0u128;
    for i in 0..32 {
        let src_nibble = (source >> (i * 4)) as u8 & 0xf;
        let res_nibble = apply_s_inv(s_idx, src_nibble) as u128;
        res |= res_nibble << (i * 4);
    }
    res
}

fn apply_permutation(table: &[u8], input: u128) -> u128 {
    let mut output = 0u128;
    for p in 0..128 {
        let in_shift = table[p];
        let bit = (input >> in_shift) & 1;
        output |= bit << p;
    }
    output
}

fn apply_xor_table(table: &tables::XorTable, input: u128) -> u128 {
    let mut output = 0u128;
    for i in 0..128 {
        let mut bit = 0u8;
        for bit_idx in table[i] {
            bit ^= (input >> bit_idx) as u8 & 1;
        }
        output |= (bit as u128) << i;
    }
    output
}

pub struct Serpent {
    subkeys: Subkeys,
}

impl Serpent {
    pub fn with_text_key(key: &str) -> Option<Serpent> {
        let binary_key = parse_text_key(key)?;
        Some(Serpent {
            subkeys: derive_subkeys(binary_key),
        })
    }

    pub fn encrypt_block(&self, block: u128) -> u128 {
        let mut b_hat = apply_permutation(&tables::IP, block);
        for i in 0..ROUNDS {
            b_hat = do_round(i, b_hat, &self.subkeys);
        }
        apply_permutation(&tables::FP, b_hat)
    }

    pub fn decrypt_block(&self, block: u128) -> u128 {
        let mut b_hat = apply_permutation(&tables::IP, block);
        for i in (0..ROUNDS).rev() {
            b_hat = do_round_inv(i, b_hat, &self.subkeys);
        }
        apply_permutation(&tables::FP, b_hat)
    }
}

fn do_round(i: usize, b_hat_i: u128, k_hat: &Subkeys) -> u128 {
    let xored = b_hat_i ^ k_hat[i];
    let s_hat_i = apply_s_hat(i, xored);
    if i <= ROUNDS - 2 {
        apply_xor_table(&tables::LT, s_hat_i)
    } else {
        s_hat_i ^ k_hat[ROUNDS]
    }
}

fn do_round_inv(i: usize, b_hat_i_plus_1: u128, k_hat: &Subkeys) -> u128 {
    let s_hat_i = if i <= ROUNDS - 2 {
        apply_xor_table(&tables::LT_INV, b_hat_i_plus_1)
    } else {
        b_hat_i_plus_1 ^ k_hat[ROUNDS]
    };
    let xored = apply_s_hat_inv(i, s_hat_i);
    xored ^ k_hat[i]
}

fn parse_text_key(key: &str) -> Option<Key> {
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
    Some(key)
}

fn gather_nibble(words: &[u32], bit_idx: usize) -> u8 {
    assert_eq!(words.len(), 4);
    let mut output = 0u8;
    for i in 0..4 {
        let bit = ((words[i] >> bit_idx) & 1) as u8;
        output |= bit << i;
    }
    output
}

fn scatter_nibble(nibble: u8, words: &mut [u32], out_bit_idx: usize) {
    assert_eq!(words.len(), 4);
    for i in 0..4 {
        let bit = ((nibble >> i) & 1) as u32;
        words[i] |= bit << out_bit_idx;
    }
}

fn derive_subkeys(key: Key) -> [Subkey; ROUNDS + 1] {
    use byteorder::{ByteOrder, LE};
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
            let words = &w[4 * i..4 * i + 4];
            let input = gather_nibble(words, j);
            let output = apply_s(s_idx, input);
            scatter_nibble(output, &mut k[4 * i..4 * i + 4], j);
        }
    }
    // distribute 32-bit values k[] into 128-bit subkeys
    let mut subkeys = [0u128; ROUNDS + 1];
    for i in 0..33 {
        subkeys[i] = k[4 * i] as u128
            | (k[4 * i + 1] as u128) << 32
            | (k[4 * i + 2] as u128) << 64
            | (k[4 * i + 3] as u128) << 96;
    }

    // apply IP to the key
    for i in 0..subkeys.len() {
        subkeys[i] = apply_permutation(&tables::IP, subkeys[i]);
    }

    subkeys
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

    #[test]
    fn derive_subkeys() {
        let binary_key = super::parse_text_key(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        super::derive_subkeys(binary_key);
    }
}
