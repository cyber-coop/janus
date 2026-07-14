use secp256k1::rand::RngCore;
use secp256k1::{rand, SecretKey};
use sha3::{Digest, Keccak256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::Row;
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{error, info, Instrument};

use janus::config;
use janus::message;
use janus::utils;

#[tokio::main]
async fn main() {
    // init logger
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Start getting status from nodes");
    let cfg = config::read_config();

    // Connect to postgres
    let connect_options = PgConnectOptions::new()
        .host(&cfg.database.host)
        .username(&cfg.database.user)
        .password(&cfg.database.password)
        .database(&cfg.database.dbname);

    let pool = PgPoolOptions::new()
        .connect_with(connect_options)
        .await
        .unwrap();

    let records = sqlx::query("SELECT * FROM nodes ORDER BY RANDOM();")
        .fetch_all(&pool)
        .await
        .unwrap();

    let mut set = JoinSet::new();
    for record in records {
        let pool = pool.clone();
        set.spawn(async move {
            let ip: String = record.get(0);
            let port: i32 = record.get(1);
            let remote_id: Vec<u8> = record.get(3);

            // Connect to node
            let ip_addr: IpAddr = ip.parse().unwrap();
            let addr = SocketAddr::from((ip_addr, port as u16));
            let span = tracing::info_span!(
                "node",
                remote_id = %hex::encode(&remote_id),
                ip = %ip,
                tcp_port = port,
            );

            async move {
                let mut stream = match TcpStream::connect(&addr).await {
                    Ok(s) => s,
                    Err(_) => {
                        error!("Couldn't reach node");
                        return;
                    }
                };

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
                info!("Creating EIP8 Auth message");
                let init_msg =
                    utils::create_auth_eip8(&remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

                // send the message
                info!("Sending EIP8 Auth message");

                if let Err(err) = stream.write_all(&init_msg).await {
                    error!("Couldn't send eip8 ({})", err);
                    return;
                };

                info!("waiting for answer...");

                // Read Ack
                let (payload, shared_mac_data) = match utils::read_ack_message(&mut stream).await {
                    Ok((payload, shared_mac_data)) => (payload, shared_mac_data),
                    Err(err) => {
                        error!("Couldn't send eip8 ({})", err);

                        return;
                    }
                };

                // Handle Ack
                info!("ACK message received");
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

                info!("Frame setup done !");

                info!("Received Ack, waiting for Header");

                /******************
                 *
                 *  Handle HELLO
                 *
                 ******************/

                let uncrypted_body = match utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes).await {
                    Ok(ub) => ub,
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                if uncrypted_body[0] == 0x01 {
                    // we have a disconnect message unfortunately
                    let reason = message::parse_disconnect_message(uncrypted_body[1..].to_vec())
                        .map(message::disconnect_reason_str)
                        .unwrap_or("Unknown disconnect reason");
                    error!("Disconnect: {}", reason);
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

                info!("Sending HELLO message");
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
                        ("eth".into(), 69),
                        // TODO: add 70 and 71
                    ],
                    port: 0,
                    id: secp256k1::PublicKey::from_secret_key(&secp, &private_key)
                        .serialize_uncompressed()[1..]
                        .to_vec(),
                };

                let payload = message::create_hello_message(hello);
                let _ = utils::send_message(payload, &mut stream, &mut egress_mac, &mut egress_aes).await;

                /******************
                 *
                 *  Handle STATUS message
                 *
                 ******************/

                info!("Handling STATUS message");
                let uncrypted_body = match utils::read_message(&mut stream, &mut ingress_mac, &mut ingress_aes).await {
                    Ok(ub) => ub,
                    Err(err) => {
                        error!("{}", err);
                        return;
                    }
                };

                if uncrypted_body[0] == 0x01 {
                    // we have a disconnect message unfortunately
                    let reason = message::parse_disconnect_message(uncrypted_body[1..].to_vec())
                        .map(message::disconnect_reason_str)
                        .unwrap_or("Unknown disconnect reason");
                    error!("Disconnect: {}", reason);
                    return;
                }

                let genesis_hash = [
                    212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69,
                    161, 24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
                ];

                let (their_network_id, their_fork_id, their_genesis) = if version >= 69 {
                    let their_status = message::parse_eth69_status_message(uncrypted_body[1..].to_vec()).unwrap();
                    info!("network_id = {:?}", &their_status.network_id);

                    let reply = message::Status69 {
                        version,
                        network_id: 1,
                        genesis: genesis_hash.to_vec(),
                        fork_id: (vec![159, 61, 34, 84], 0),
                        earliest: 0,
                        latest: 0,
                        latest_hash: genesis_hash.to_vec(),
                    };
                    let _ = utils::send_message(
                        message::create_eth69_status_message(reply),
                        &mut stream,
                        &mut egress_mac,
                        &mut egress_aes,
                    ).await;

                    (their_status.network_id, their_status.fork_id.0, their_status.genesis)
                } else {
                    let their_status = message::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();
                    info!("network_id = {:?}", &their_status.network_id);

                    let reply = message::Status {
                        version,
                        network_id: 1,
                        td: vec![0],
                        blockhash: genesis_hash.to_vec(),
                        genesis: genesis_hash.to_vec(),
                        fork_id: (vec![159, 61, 34, 84], 0),
                    };
                    let _ = utils::send_message(
                        message::create_status_message(reply),
                        &mut stream,
                        &mut egress_mac,
                        &mut egress_aes,
                    ).await;

                    (their_status.network_id, their_status.fork_id.0, their_status.genesis)
                };

                let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
                sqlx::query("UPDATE nodes SET network_id = $1, fork_id = $2, genesis = $3, capabilities = $4, client = $5, last_ping_timestamp = NOW() WHERE id = $6;")
                    .bind(their_network_id as i64)
                    .bind(&their_fork_id)
                    .bind(&their_genesis)
                    .bind(serde_json::to_value(&cap).unwrap())
                    .bind(&hello_message.client)
                    .bind(&remote_id)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            .instrument(span)
            .await
        });
    }

    set.join_all().await;
    info!("Contacted all the nodes");
}
