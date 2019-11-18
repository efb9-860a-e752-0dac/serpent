use crate::tables;

pub(crate) fn apply_s(s_idx: usize, nibble: u8) -> u8 {
    tables::SBOX[s_idx % 8][nibble as usize]
}

pub(crate) fn apply_s_inv(s_idx: usize, nibble: u8) -> u8 {
    tables::SBOX_INV[s_idx % 8][nibble as usize]
}

pub(crate) fn apply_s_hat(s_idx: usize, source: u128) -> u128 {
    let mut res = 0u128;
    for i in 0..32 {
        let src_nibble = (source >> (i * 4)) as u8 & 0xf;
        let res_nibble = u128::from(apply_s(s_idx, src_nibble));
        res |= res_nibble << (i * 4);
    }
    res
}

pub(crate) fn apply_s_hat_inv(s_idx: usize, source: u128) -> u128 {
    let mut res = 0u128;
    for i in 0..32 {
        let src_nibble = (source >> (i * 4)) as u8 & 0xf;
        let res_nibble = u128::from(apply_s_inv(s_idx, src_nibble));
        res |= res_nibble << (i * 4);
    }
    res
}

pub(crate) fn apply_permutation(table: &tables::Permutation, input: u128) -> u128 {
    let mut output = 0u128;
    for (p, in_shift) in table.iter().enumerate() {
        let bit = (input >> in_shift) & 1;
        output |= bit << p;
    }
    output
}

pub(crate) fn apply_xor_table(table: &tables::XorTable, input: u128) -> u128 {
    let mut output = 0u128;
    for (i, indices) in table.iter().enumerate() {
        let mut bit = 0u8;
        for bit_idx in *indices {
            bit ^= (input >> bit_idx) as u8 & 1;
        }
        output |= u128::from(bit) << i;
    }
    output
}
