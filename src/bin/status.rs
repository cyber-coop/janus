use log::{error, info};
use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use sha3::{Digest, Keccak256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{net::TcpStream, time::Duration};
use tokio::task::JoinSet;
use tokio_postgres::NoTls;

use void::config;
use void::message;
use void::utils;

#[tokio::main]
async fn main() {
    // init logger
    env_logger::init();

    info!("Start getting status from nodes");
    let cfg = config::read_config();

    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );

    let (postgres_client, connection) = tokio_postgres::connect(&database_params, NoTls)
        .await
        .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });

    let records = postgres_client
        .query("SELECT * FROM nodes ORDER BY RANDOM();", &[])
        .await
        .unwrap();

    let postgres = Arc::new(postgres_client);
    let mut set = JoinSet::new();
    for record in records {
        let postgres = postgres.clone();
        set.spawn(async move {
            let update_statement = postgres.prepare("UPDATE nodes SET network_id = $1, fork_id = $2, genesis = $3, capabilities = $4, client = $5, last_ping_timestamp = NOW() WHERE id = $6;").await.unwrap();

            let ip: String = record.get(0);
            let port: i32 = record.get(1);
            let remote_id: Vec<u8> = record.get(3);

            // Connect to node
            let ip_addr: IpAddr = ip.parse().unwrap();
            let addr = SocketAddr::from((ip_addr, port as u16));
            let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10));

            let target = format!("{}@{}", hex::encode(&remote_id), addr);

            if stream.is_err() {
                error!(target: &target,
                    "Couldn't reach node",
                );
                return;
            }

            let mut stream = stream.unwrap();
            // Set read timeout
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let private_key = SecretKey::new(&mut rand::thread_rng())
                .secret_bytes()
                .to_vec();
            let mut nonce = vec![0; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            let ephemeral_privkey = SecretKey::new(&mut rand::thread_rng())
                .secret_bytes()
                .to_vec();
            let pad = vec![0; 100]; // should be generated randomly but we don't really care

            /******************
             *
             *  Create Auth message (EIP8 supported)
             *
             ******************/
            info!(target: &target,
                "Creating EIP8 Auth message",
            );
            let init_msg =
                utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

            // send the message
            info!(target: &target,
                "Sending EIP8 Auth message",
            );

            if let Err(err) = utils::send_eip8_auth_message(&init_msg, &mut stream) {
                error!(target: &target,
                    "Couldn't send eip8 ({})",
                    err
                );
                return;
            };

            info!(target: &target,
                "waiting for answer...",
            );

            // Read Ack
            let (payload, shared_mac_data) = match utils::read_ack_message(&mut stream) {
                Ok((payload, shared_mac_data)) => (payload, shared_mac_data),
                Err(err) => {
                    error!(target: &target,
                        "Couldn't send eip8 ({})",
                        err
                    );

                    return;
                }
            };

            // Handle Ack
            info!(target: &target,
                "ACK message received",
            );
            let decrypted = utils::decrypt_message(&payload, &shared_mac_data, &private_key);

            // decode RPL data
            let rlp = rlp::Rlp::new(&decrypted);

            // id to pubkey
            let remote_public_key: Vec<u8> =
                [vec![0x04], rlp.at(0).unwrap().as_val().unwrap()].concat();
            let remote_nonce: Vec<u8> = rlp.at(1).unwrap().as_val().unwrap();

            let ephemeral_shared_secret = utils::ecdh_x(&remote_public_key, &ephemeral_privkey);

            /******************
             *
             *  Setup Frame
             *
             ******************/

            let nonce_material = [remote_nonce.clone(), nonce.clone()].concat();
            let mut hasher = Keccak256::new();
            hasher.update(&nonce_material);
            let h_nonce = hasher.finalize().to_vec();
            let remote_data = [shared_mac_data, payload].concat();
            let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) =
                utils::setup_frame(
                    remote_nonce,
                    nonce,
                    ephemeral_shared_secret,
                    remote_data,
                    init_msg,
                    h_nonce,
                );

            info!(target: &target,
                "Frame setup done !",
            );

            info!(target: &target,
                "Received Ack, waiting for Header",
            );

            /******************
             *
             *  Handle HELLO
             *
             ******************/

            let uncrypted_body = match utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes) {
                Ok(ub) => ub,
                Err(err) => {
                    error!(target: &target,"{}", err);
                    return;
                }
            };

            if uncrypted_body[0] == 0x01 {
                // we have a disconnect message unfortunately
                error!(target: &target,
                    "Disconnect {}",
                    hex::encode(uncrypted_body[1..].to_vec())
                );
                return;
            }

            // Should be HELLO
            assert_eq!(0x80, uncrypted_body[0]);
            let hello_message = message::parse_hello_message(uncrypted_body[1..].to_vec());

            let capabilities = serde_json::to_string(&hello_message.capabilities).unwrap();

            // We need to find the highest eth version it supports
            let mut version = 0;
            for capability in &hello_message.capabilities {
                if capability.0.to_string() == "eth" {
                    if capability.1 > version {
                        version = capability.1;
                    }
                }
            }

            /******************
             *
             *  Create Hello
             *
             ******************/

            info!(target: &target,
                "Sending HELLO message",
            );
            // Create Hello
            let secp = secp256k1::Secp256k1::new();
            let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
            let hello = message::HelloMessage {
                protocol_version: message::BASE_PROTOCOL_VERSION,
                client: String::from("deadbrain corp."),
                capabilities: vec![
                    ("eth".into(), 64),
                    ("eth".into(), 65),
                    ("eth".into(), 66),
                    ("eth".into(), 67),
                    ("eth".into(), 68),
                ],
                port: 0,
                id: secp256k1::PublicKey::from_secret_key(&secp, &private_key)
                    .serialize_uncompressed()[1..]
                    .to_vec(),
            };

            let payload = message::create_hello_message(hello);
            utils::send_message(payload, &mut stream, &mut egress_mac, &mut egress_aes);

            /******************
             *
             *  Handle STATUS message
             *
             ******************/

            info!(target: &target,
                "Handling STATUS message",
            );
            let uncrypted_body = match utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes) {
                Ok(ub) => ub,
                Err(err) => {
                    error!(target: &target,"{}", err);
                    return;
                }
            };

            if uncrypted_body[0] == 0x01 {
                // we have a disconnect message unfortunately
                error!(
                    target: &target,
                    "Disconnect {}",
                    hex::encode(uncrypted_body[1..].to_vec())
                );
                return;
            }
            let their_status = message::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

            info!(target: &target,
                "network_id = {:?}",
                &their_status.network_id
            );

            /******************
             *
             *  Send STATUS message
             *
             ******************/

            // Do we even need to send ou status ? We could just disconnect from here

            info!(target: &target,
                "Sending STATUS message",
            );

            let genesis_hash = [
                212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69,
                161, 24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
            ];

            let status = message::Status {
                version,
                network_id: 1, // TODO: allow to do random networks
                td: vec![0],
                blockhash: genesis_hash.to_vec(),
                genesis: genesis_hash.to_vec(),
                fork_id: (vec![159, 61, 34, 84], 0),
            };

            // Send STATUS message
            let status = message::create_status_message(status);
            utils::send_message(status, &mut stream, &mut egress_mac, &mut egress_aes);

            let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
            let _result = postgres
                .execute(
                    &update_statement,
                    &[
                        &(their_status.network_id as i64),
                        &their_status.fork_id.0,
                        &their_status.genesis,
                        &serde_json::to_value(&cap).unwrap(),
                        &hello_message.client,
                        &remote_id,
                    ],
                )
                .await
                .unwrap();
        });
    }

    set.join_all().await;
    info!("Contacted all the nodes");
}
