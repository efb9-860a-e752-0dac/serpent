// #[macro_use]
// use serpent::generic_array;
// use block_cipher_trait::BlockCipher;

fn nibble_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => unreachable!(),
    }
}

fn bytes_from_hex_str(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 == 1 || bytes.iter().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }

    Some(
        bytes
            .chunks_exact(2)
            .rev()
            .map(|chunk| nibble_value(chunk[0]) << 4 | nibble_value(chunk[1]))
            .collect(),
    )
}

fn block_from_bytes(bytes: &[u8]) -> u128 {
    use std::convert::TryInto;
    u128::from_le_bytes(bytes.try_into().unwrap())
}

#[test]
fn variable_key() {
    let vk_txt = include_str!("ecb_vk.txt");
    let mut pt = None;
    let mut key = None;
    for line in vk_txt.lines() {
        let mut parts = line.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("PT"), Some(v)) => pt = bytes_from_hex_str(v),
            (Some("KEY"), Some(v)) => key = Some(v),
            (Some("CT"), Some(v)) => {
                let ct = bytes_from_hex_str(v).unwrap();
                let cipher = serpent::Serpent::with_text_key(key.unwrap()).unwrap();
                let plain = block_from_bytes(pt.as_ref().unwrap());
                let truth = block_from_bytes(&ct);
                let encrypted = cipher.encrypt_block(plain);
                let decrypted = cipher.decrypt_block(encrypted);
                assert_eq!(encrypted, truth);
                assert_eq!(decrypted, plain);
            }
            _ => {}
        }
    }
}

#[test]
fn variable_text() {
    let vt_txt = include_str!("ecb_vt.txt");
    let mut pt = None;
    let mut key = None;
    for line in vt_txt.lines() {
        let mut parts = line.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("PT"), Some(v)) => pt = bytes_from_hex_str(v),
            (Some("KEY"), Some(v)) => key = Some(v),
            (Some("CT"), Some(v)) => {
                let ct = bytes_from_hex_str(v).unwrap();
                let cipher = serpent::Serpent::with_text_key(key.unwrap()).unwrap();
                let plain = block_from_bytes(pt.as_ref().unwrap());
                let truth = block_from_bytes(&ct);
                let encrypted = cipher.encrypt_block(plain);
                let decrypted = cipher.decrypt_block(encrypted);
                assert_eq!(encrypted, truth);
                assert_eq!(decrypted, plain);
            }
            _ => {}
        }
    }
}

#[test]
fn tables() {
    let vt_txt = include_str!("ecb_tbl.txt");
    let mut pt = None;
    let mut key = None;
    for line in vt_txt.lines() {
        let mut parts = line.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("PT"), Some(v)) => pt = bytes_from_hex_str(v),
            (Some("KEY"), Some(v)) => key = Some(v),
            (Some("CT"), Some(v)) => {
                let ct = bytes_from_hex_str(v).unwrap();
                let cipher = serpent::Serpent::with_text_key(key.unwrap()).unwrap();
                let plain = block_from_bytes(pt.as_ref().unwrap());
                let truth = block_from_bytes(&ct);
                let encrypted = cipher.encrypt_block(plain);
                let decrypted = cipher.decrypt_block(encrypted);
                assert_eq!(encrypted, truth);
                assert_eq!(decrypted, plain);
            }
            _ => {}
        }
    }
}
