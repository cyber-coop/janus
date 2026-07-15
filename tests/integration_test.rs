use devp2p::{ecies::ECIES, util::pk2id};
use janus::utils;
use secp256k1_20::{PublicKey, SECP256K1, SecretKey};
use sha3::{Digest, Keccak256};

#[test]
fn communicate() {
    let server_secret_key = SecretKey::from_slice(&[1_u8; 32]).unwrap();
    let server_public_key = PublicKey::from_secret_key(SECP256K1, &server_secret_key);
    let server_nonce = primitive_types::H256::from_slice(
        &hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
    );
    let server_ephemeral_key = SecretKey::from_slice(&[2_u8; 32]).unwrap();
    let server_id = pk2id(&server_public_key).0.to_vec();

    let private_key =
        hex::decode("472D4B6150645267556B58703273357638792F423F4528482B4D625165546856").unwrap();
    // Should be generated randomly
    let nonce =
        hex::decode("09267e7d55aada87e46468b2838cc616f084394d6d600714b58ad7a3a2c0c870").unwrap();
    // Epheremal private key (should be random)
    let ephemeral_privkey =
        hex::decode("691bb7a2fd6647eae78a235b9d305d09f796fe8e8ce7a18aa1aa1deff9649a02").unwrap();
    // Pad (should be generated randomly)
    let pad = [0_u8; 100].to_vec();

    let client_secret_key = SecretKey::from_slice(&private_key).unwrap();
    let client_public_key = PublicKey::from_secret_key(SECP256K1, &client_secret_key);
    let client_ephemeral_key = SecretKey::from_slice(&ephemeral_privkey).unwrap();
    let client_id = pk2id(&client_public_key).0.to_vec();

    // let mut server_ecies = ECIES::new_static_server(server_secret_key, server_nonce, server_ephemeral_key).unwrap();
    let mut client_ecies = ECIES::new_static_client(
        client_secret_key,
        primitive_types::H512::from_slice(&server_id),
        server_nonce,
        client_ephemeral_key,
    )
    .unwrap();

    let mut init_msg =
        utils::create_auth_eip8(&server_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // Handshake
    // server_ecies.read_auth(&mut init_msg).unwrap();
    // let expected_ack = server_ecies.create_ack();

    let ack = utils::create_ack(&client_id, &nonce, &[2_u8; 32].to_vec(), &pad);

    // assert_eq!(hex::encode(&expected_ack), hex::encode(&ack));

    let auth = client_ecies.create_auth();
    client_ecies.read_ack(&mut ack.clone()).unwrap();

    // assert_eq!(hex::encode(&init_msg), hex::encode(&auth));

    let shared_mac_data = auth[0..2].to_vec();
    let payload = auth[2..].to_vec();

    let (remote_id, remote_nonce, ephemeral_shared_secret) = utils::verify_auth_eip8(
        &payload,
        &shared_mac_data,
        &[1_u8; 32].to_vec(),
        &[2_u8; 32].to_vec(),
    );

    let remote_data = [shared_mac_data, payload].concat();

    let nonce_material = [nonce.clone(), remote_nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize().to_vec();
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        ack,
        h_nonce,
    );

    let server_to_client_data = [0_u8, 1_u8, 2_u8, 3_u8, 4_u8];

    let mut header = utils::create_header(
        server_to_client_data.len(),
        &mut egress_mac,
        &mut egress_aes,
    );
    client_ecies.read_header(&mut header).unwrap();
}
