use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::ByteOrder;
use byteorder::{BigEndian, ReadBytesExt};
use hmac_sha256::{HMAC, Hash};
use secp256k1::Message;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use sha3::{Digest, Keccak256};
use std::error;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::mac;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;
const TIMEOUT_ATTEMPRS: usize = 40;

pub fn ecdh_x(pubkey: &[u8], privkey: &[u8]) -> Vec<u8> {
    let sk = k256::ecdsa::SigningKey::from_slice(privkey).unwrap();
    let pk = k256::PublicKey::from_sec1_bytes(pubkey).unwrap();
    let shared_secret =
        k256::elliptic_curve::ecdh::diffie_hellman(sk.as_nonzero_scalar(), pk.as_affine());

    shared_secret.raw_secret_bytes().to_vec()
}

pub fn concat_kdf(key_material: Vec<u8>, key_length: usize) -> Vec<u8> {
    const SHA256_BLOCK_SIZE: usize = 64;
    let reps = ((key_length + 7) * 8) / (SHA256_BLOCK_SIZE * 8);
    let mut counter = 0;

    let mut buffers: Vec<Vec<u8>> = vec![];

    while counter <= reps {
        counter += 1;
        let mut tmp = [0u8; 4];
        BigEndian::write_u32(&mut tmp, counter as u32);
        let mut hash = Hash::new();
        hash.update(tmp);
        hash.update(&key_material);
        buffers.push(hash.finalize().into());
    }

    let mut result: Vec<u8> = vec![];
    buffers.iter().for_each(|x| result.extend(x));

    return result[0..key_length].to_vec();
}

pub fn encrypt_message(remote_public: &[u8], mut data: Vec<u8>, shared_mac_data: &[u8]) -> Vec<u8> {
    // let privkey = k256::SecretKey::random(&mut OsRng);
    let privkey = k256::SecretKey::from_slice(&[1_u8; 32]).unwrap();
    let x = ecdh_x(remote_public, &privkey.to_bytes().to_vec());
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // encrypt
    let iv = [0u8; 16];
    // OsRng.fill_bytes(&mut iv);

    let mut cipher = Aes128Ctr64BE::new(e_key.try_into().unwrap(), &iv.into());
    cipher.apply_keystream(&mut data);

    let mut data_iv: Vec<u8> = vec![];
    data_iv.extend(iv);
    data_iv.extend(data);

    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let tag = HMAC::mac(input, m_key);

    let public_key = privkey.public_key();
    let vkey = k256::ecdsa::VerifyingKey::from(public_key);
    let uncompressed_pubkey_bytes = vkey.to_sec1_point(false).to_bytes();

    let mut result: Vec<u8> = vec![];

    result.extend(uncompressed_pubkey_bytes.to_vec());
    result.extend(data_iv);
    result.extend(tag);

    return result;
}

pub fn decrypt_message(payload: &[u8], shared_mac_data: &[u8], private_key: &[u8]) -> Vec<u8> {
    assert_eq!(payload[0], 0x04);

    let public_key = payload[0..65].to_vec();
    let data_iv = payload[65..(payload.len() - 32)].to_vec();
    let tag = payload[(payload.len() - 32)..].to_vec();

    // derive keys
    let x = ecdh_x(&public_key, private_key);
    let key = concat_kdf(x, 32);
    let e_key = &key[0..16]; // encryption key
    let m_key = Hash::hash(&key[16..32]); // mac key

    // check the tag
    // create tag
    let mut input: Vec<u8> = vec![];
    input.extend(&data_iv);
    input.extend(shared_mac_data);
    let _tag = HMAC::mac(input, m_key).to_vec();

    assert_eq!(_tag, tag);

    // decrypt data
    let iv = &data_iv[0..16];
    let mut encrypted_data = data_iv[16..].to_vec();
    let mut decipher = Aes128Ctr64BE::new(e_key.try_into().unwrap(), iv.try_into().unwrap());
    // decipher encrypted_data and return result in encrypted_data variable
    decipher.apply_keystream(&mut encrypted_data);

    return encrypted_data;
}

pub fn create_auth_eip8(
    remote_id: &[u8],
    private_key: &[u8],
    nonce: &[u8],
    ephemeral_privkey: &[u8],
    pad: &[u8],
) -> Vec<u8> {
    let mut auth_message: Vec<u8> = vec![];
    // Add 04 to the remote ID to get the remote public key
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    // ECDH stuff
    let shared_secret = ecdh_x(&remote_public_key, &private_key);

    // XOR pubkey and nonce
    let msg_hash: Vec<u8> = shared_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    // sign message
    let ephemeral_signing_key = secp256k1::SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let (recid, sig) = secp256k1::SECP256K1
        .sign_ecdsa_recoverable(
            &secp256k1::Message::from_digest_slice(&msg_hash).unwrap(),
            &ephemeral_signing_key,
        )
        .serialize_compact();

    // convert to RSV
    let mut rsv_sig = sig.to_vec();

    // adding signing id
    rsv_sig.push(recid.to_i32() as u8); // TODO: maybe the conversion here is not great

    // Initialize array with empty vectors
    let sk = k256::ecdsa::SigningKey::from_slice(&private_key).unwrap();
    let vkey = sk.verifying_key();
    let uncompressed_pubkey_bytes = vkey.to_sec1_point(false).to_bytes();

    let data = vec![
        rsv_sig,
        uncompressed_pubkey_bytes[1..].to_vec(),
        nonce.to_vec(),
        vec![0x04],
    ];

    // Encoded RLP data
    let encoded_data = rlp::encode_list::<Vec<u8>, _>(&data);

    // Concat padding to the encoded data
    auth_message.extend(encoded_data.to_vec());
    auth_message.extend(pad);

    let overhead_length = 113;
    let shared_mac_data = ((auth_message.len() + overhead_length) as u16).to_be_bytes();

    // Encrypt message
    let enrcyped_auth_message = encrypt_message(&remote_public_key, auth_message, &shared_mac_data);

    let init_msg = [shared_mac_data.to_vec(), enrcyped_auth_message].concat();

    return init_msg;
}

pub async fn read_auth_eip8(
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn error::Error>> {
    let timeout = Duration::from_millis(100 * TIMEOUT_ATTEMPRS as u64);

    let mut buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await??;

    let size_expected = BigEndian::read_u16(&buf) as usize;
    let shared_mac_data = &buf[0..2];

    let mut payload = vec![0u8; size_expected];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload)).await??;

    Ok((payload, shared_mac_data.to_vec()))
}

pub fn verify_auth_eip8(
    payload: &[u8],
    shared_mac_data: &[u8],
    private_key: &[u8],
    ephemeral_privkey: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let decrypted = decrypt_message(payload, shared_mac_data, private_key);

    // decode RPL data
    let rlp = rlp::Rlp::new(&decrypted);
    let mut rlp = rlp.into_iter();

    let sig: Vec<u8> = rlp.next().unwrap().as_val().unwrap();
    let remote_id: Vec<u8> = rlp.next().unwrap().as_val().unwrap();
    let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();

    let recid = RecoveryId::from_i32(sig[64] as i32).unwrap();
    let sig = RecoverableSignature::from_compact(&sig[..64], recid).unwrap();

    // Public key is is the id with 04 (uncompressed key) byte in front
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    let shared_secret = ecdh_x(&remote_public_key, &private_key);

    // XOR remote_public_key and nonce
    let msg_hash: Vec<u8> = shared_secret
        .iter()
        .zip(remote_nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    let msg = Message::from_digest_slice(&msg_hash).unwrap();
    let remote_ephemeral_public_key = sig.recover(&msg).unwrap().serialize_uncompressed().to_vec();

    let ephemeral_shared_secret = ecdh_x(&remote_ephemeral_public_key, ephemeral_privkey);

    return (remote_id, remote_nonce, ephemeral_shared_secret);
}

pub fn create_auth_non_eip8(
    remote_id: &[u8],
    private_key: &[u8],
    nonce: &[u8],
    ephemeral_privkey: &[u8],
    ephemeral_pubkey: &[u8],
) -> Vec<u8> {
    // Add 04 to the remote ID to get the remote public key
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    // ECDH stuff
    let shared_secret = ecdh_x(&remote_public_key, &private_key);

    // XOR pubkey and nonce
    let msg_hash: Vec<u8> = shared_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();

    // sign message
    let ephemeral_signing_key = secp256k1::SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let (recid, sig) = secp256k1::SECP256K1
        .sign_ecdsa_recoverable(
            &secp256k1::Message::from_digest_slice(&msg_hash).unwrap(),
            &ephemeral_signing_key,
        )
        .serialize_compact();

    // Initialize array with empty vectors
    let sk = k256::ecdsa::SigningKey::from_slice(&private_key).unwrap();
    let vkey = sk.verifying_key();
    let uncompressed_pubkey_bytes = vkey.to_sec1_point(false).to_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&[vec![4], ephemeral_pubkey.to_vec()].concat());
    let ephemeral_pubkey_hash = hasher.finalize();

    let data = vec![
        sig.to_vec(),
        vec![recid.to_i32() as u8],
        ephemeral_pubkey_hash.to_vec(),
        uncompressed_pubkey_bytes[1..].to_vec(),
        nonce.to_vec(),
        vec![0x00],
    ]
    .concat();

    // Encrypt message
    return encrypt_message(&remote_public_key, data, &vec![]);
}

pub fn setup_frame(
    remote_nonce: Vec<u8>,
    nonce: Vec<u8>,
    ephemeral_shared_secret: Vec<u8>,
    remote_data: Vec<u8>,
    init_msg: Vec<u8>,
    h_nonce: Vec<u8>,
) -> (Aes256Ctr64BE, mac::MAC, Aes256Ctr64BE, mac::MAC) {
    let iv = [0u8; 16];

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(h_nonce);
    let shared_secret = hasher.finalize();

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(shared_secret);
    let aes_secret = hasher.finalize();

    let ingress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());
    let egress_aes = Aes256Ctr64BE::new(&aes_secret.into(), &iv.into());

    let mut hasher = Keccak256::new();
    hasher.update(&ephemeral_shared_secret);
    hasher.update(aes_secret);
    let mac_secret = hasher.finalize();

    // The MAC thingy is actually keccak256

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut ingress_mac = mac::MAC::new(mac_secret.to_vec());
    ingress_mac.update(&[xor_result, remote_data].concat());

    let xor_result: Vec<u8> = mac_secret
        .iter()
        .zip(remote_nonce.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let mut egress_mac = mac::MAC::new(mac_secret.to_vec());
    egress_mac.update(&[xor_result, init_msg].concat());

    return (ingress_aes, ingress_mac, egress_aes, egress_mac);
}

// NOTE: could be [u8; 32]
pub fn parse_header(
    data: &[u8],
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> usize {
    let mut header = data[0..16].to_vec();
    let mac = &data[16..32];

    ingress_mac.update_header(&mut header);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut header);
    let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3).unwrap()).unwrap();
    return body_size;
}

pub fn parse_body(
    data: &Vec<u8>,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
    body_size: usize,
) -> Vec<u8> {
    let mut body = data[0..data.len() - 16].to_vec();
    let mac = &data[data.len() - 16..];

    /* Something about mac that we are missing */
    ingress_mac.update_body(&mut body);
    let _mac = ingress_mac.digest();
    assert_eq!(_mac, mac);

    ingress_aes.apply_keystream(&mut body);

    return body[0..body_size].to_vec();
}

pub fn get_body_len(size: usize) -> usize {
    (if size % 16 == 0 {
        size
    } else {
        (size / 16 + 1) * 16
    }) + 16
}

pub fn create_header(
    length: usize,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let mut buf = [0; 8];
    BigEndian::write_uint(&mut buf, length as u64, 3);
    let mut header = [0_u8; 16];
    header[0..3].copy_from_slice(&buf[0..3]);
    header[3] = 0xC2;
    header[4] = 0x80;
    header[5] = 0x80;

    egress_aes.apply_keystream(&mut header);
    egress_mac.update_header(&mut header.to_vec());

    let tag = egress_mac.digest();

    return [header.to_vec(), tag].concat().to_vec();
}

pub fn create_body(
    body: Vec<u8>,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Vec<u8> {
    let body_len = get_body_len(body.len()) - 16;

    let mut body_message = vec![0; body_len];
    body_message[..body.len()].clone_from_slice(&body);

    egress_aes.apply_keystream(&mut body_message);
    egress_mac.update_body(&mut body_message.to_vec());
    let tag = egress_mac.digest();

    return [body_message.to_vec(), tag].concat().to_vec();
}

pub async fn send_message(
    msg: Vec<u8>,
    stream: &mut TcpStream,
    egress_mac: &mut mac::MAC,
    egress_aes: &mut Aes256Ctr64BE,
) -> Result<(), Box<dyn error::Error>> {
    let header = create_header(msg.len(), egress_mac, egress_aes);
    let body = create_body(msg, egress_mac, egress_aes);

    stream.write_all(&[header, body].concat()).await?;

    Ok(())
}

pub async fn read_message(
    stream: &mut TcpStream,
    ingress_mac: &mut mac::MAC,
    ingress_aes: &mut Aes256Ctr64BE,
) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut buf = [0u8; 32];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read header timeout"))??;

    assert_eq!(buf.len(), 32);

    let next_size = parse_header(buf.as_ref(), ingress_mac, ingress_aes);
    let body_size = get_body_len(next_size);

    let mut body = vec![0u8; body_size];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut body))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read body timeout"))??;

    assert_eq!(body.len(), body_size);

    Ok(parse_body(&body, ingress_mac, ingress_aes, next_size))
}

pub async fn read_ack_message(
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn error::Error>> {
    let timeout = Duration::from_millis(100 * TIMEOUT_ATTEMPRS as u64);

    let mut buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await??;

    let size_expected = BigEndian::read_u16(&buf) as usize;
    let shared_mac_data = buf[0..2].to_vec();

    let mut payload = vec![0u8; size_expected];
    tokio::time::timeout(timeout, stream.read_exact(&mut payload)).await??;

    assert_eq!(payload.len(), size_expected);

    Ok((payload, shared_mac_data))
}

pub fn create_ack(
    remote_id: &[u8],
    nonce: &[u8],
    ephemeral_privkey: &[u8],
    _pad: &[u8],
) -> Vec<u8> {
    let mut ack_message: Vec<u8> = vec![];
    // Add 04 to the remote ID to get the remote public key
    let remote_public_key: Vec<u8> = [vec![4], remote_id.to_vec()].concat();

    let ephemeral_signing_key = secp256k1::SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let secp = secp256k1::Secp256k1::new();
    let ephemeral_public_key: Vec<u8> = ephemeral_signing_key
        .public_key(&secp)
        .serialize_uncompressed()
        .to_vec();

    let data = vec![
        ephemeral_public_key[1..].to_vec(),
        nonce.to_vec(),
        vec![0x04],
    ];
    // Encoded RLP data
    let encoded_data = rlp::encode_list::<Vec<u8>, _>(&data);

    // Concat padding to the encoded data
    ack_message.extend(encoded_data.to_vec());
    // ack_message.extend(pad);
    let overhead_length = 113;
    let shared_mac_data = ((ack_message.len() + overhead_length) as u16).to_be_bytes();

    // Encrypt message
    let enrcyped_ack_message = encrypt_message(&remote_public_key, ack_message, &shared_mac_data);

    let init_msg = [shared_mac_data.to_vec(), enrcyped_ack_message].concat();

    return init_msg;
}

pub fn handle_ack_message(
    payload: &[u8],
    shared_mac_data: &[u8],
    private_key: &[u8],
    ephemeral_privkey: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let decrypted = decrypt_message(payload, shared_mac_data, private_key);

    // decode RPL data
    let rlp = rlp::Rlp::new(&decrypted);
    let mut rlp = rlp.into_iter();

    // id to pubkey
    let remote_public_key: Vec<u8> = [vec![0x04], rlp.next().unwrap().as_val().unwrap()].concat();
    let remote_nonce: Vec<u8> = rlp.next().unwrap().as_val().unwrap();

    let ephemeral_shared_secret = ecdh_x(&remote_public_key, ephemeral_privkey);

    return (remote_public_key, remote_nonce, ephemeral_shared_secret);
}
