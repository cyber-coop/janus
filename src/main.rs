use discv4::{Node, NodeId, NodeRecord};
use rand::Rng;
use secp256k1::SecretKey;
use sha3::Digest;
use sha3::Keccak256;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::error::Error;
use std::net::Ipv6Addr;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use janus::config;
use janus::message;
use janus::utils;

static SERVER_PORT: u16 = 30303;
const BOOTSTRAP_NODES: &[&str] = &[
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303", // bootnode-aws-ap-southeast-1-001
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303", // bootnode-aws-us-east-1-001
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303", // bootnode-hetzner-hel
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303", // bootnode-hetzner-fsn
];

// Ethereum mainnet network info, shared by both the incoming and outgoing STATUS replies.
const GENESIS_HASH: [u8; 32] = [
    212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161, 24, 208,
    144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163,
];
const FORK_HASH: [u8; 4] = [252, 100, 236, 4]; // 0xfc64ec04
const FORK_NEXT: u64 = 1150000;
const NETWORK_ID: u64 = 1;

#[tokio::main]
async fn main() {
    // init logger
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Janus!");

    let cfg = config::read_config();

    let connect_options = PgConnectOptions::new()
        .host(&cfg.database.host)
        .username(&cfg.database.user)
        .password(&cfg.database.password)
        .database(&cfg.database.dbname);

    let pool = PgPoolOptions::new()
        .connect_with(connect_options)
        .await
        .expect("database to be reachable");
    info!("Connection to the database created");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("database migrations to succeed");
    info!("Database migrations applied");

    let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let node = Node::new(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT).into(),
        secret_key,
        BOOTSTRAP_NODES.iter().map(|v| v.parse().unwrap()).collect(),
        None,
        true,
        SERVER_PORT,
    )
    .await
    .unwrap();
    info!("Discv4 server started");

    // Create the channel for status task to query those peers
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<NodeRecord>();

    let discovery_task = {
        // shadow naming (maybe this is a mistake)
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                let target = NodeId::random();
                info!("Looking up random target: {}", target);
                let result = node.lookup(target).await;

                for entry in result {
                    info!("Found node: {:?}", entry);
                    // Upsert the node and bump last_discovered_at, but only if it hasn't
                    // been discovered in the last 24h. This both fixes the ON CONFLICT-less
                    // insert (which used to silently fail on every rediscovery) and throttles
                    // how often an already-known node gets a fresh status-check triggered.
                    let discovered = sqlx::query(
                        "INSERT INTO nodes (ip, tcp_port, udp_port, id, last_discovered_at) \
                         VALUES ($1,$2,$3,$4,NOW()) \
                         ON CONFLICT (id) DO UPDATE \
                            SET last_discovered_at = NOW() \
                            WHERE nodes.last_discovered_at IS NULL \
                               OR nodes.last_discovered_at < NOW() - INTERVAL '24 hours' \
                         RETURNING id;",
                    )
                    .bind(entry.address.to_string())
                    .bind(entry.tcp_port as i32)
                    .bind(entry.udp_port as i32)
                    .bind(entry.id.as_bytes())
                    .fetch_optional(&pool)
                    .await;

                    if let Ok(Some(_)) = discovered {
                        let _ = tx.send(entry);
                    }
                }

                info!("Current nodes: {}", node.num_nodes());
            }
        })
    };

    let status_task = {
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                while let Some(entry) = rx.recv().await {
                    let addr = SocketAddr::from((entry.address, entry.tcp_port));

                    let pool = pool.clone();
                    tokio::spawn(async move {
                        // TODO: distinguish connection-failure kinds (refused vs timed out, etc.)
                        // and persist them to the database instead of just logging, so we can
                        // track per-node reachability history rather than only the latest attempt.
                        let mut stream = match tokio::time::timeout(
                            Duration::from_secs(5),
                            TcpStream::connect(&addr),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(_)) => {
                                trace!("Couldn't reach node");
                                return;
                            }
                            Err(_) => {
                                trace!("Connection attempt timed out");
                                return;
                            }
                        };
                        if let Err(err) =
                            handle_outgoing_connection(&mut stream, &pool, entry.id.as_bytes())
                                .await
                        {
                            info!("Failed to get the STATUS message from node : {}", err);
                        };
                    });
                }
            }
        })
    };

    let server_task = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let tcp_bind_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, SERVER_PORT));
            let listener = TcpListener::bind(tcp_bind_addr)
                .await
                .expect("server to start");
            info!("Server started on [::]:{SERVER_PORT}");

            loop {
                let (mut socket, addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(err) => {
                        error!("Failed to accept connection: {}", err);
                        continue;
                    }
                };
                info!("New connection: {:?}", addr);

                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_incoming_connection(&mut socket, &pool, &secret_key.secret_bytes())
                            .await
                    {
                        info!("Failed to handle connection request : {}", err.to_string());
                    };
                });

                info!("Connection closed ({:?})", addr);
            }
        })
    };

    let _ = tokio::join!(discovery_task, server_task, status_task);
}

#[tracing::instrument(
    skip(stream, pool, private_key),
    fields(remote_id = tracing::field::Empty, ip = tracing::field::Empty, tcp_port = tracing::field::Empty)
)]
async fn handle_incoming_connection(
    stream: &mut TcpStream,
    pool: &PgPool,
    private_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    let peer_addr = stream.peer_addr().expect("to have a peer address");
    let span = tracing::Span::current();
    span.record("ip", peer_addr.ip().to_string());
    span.record("tcp_port", peer_addr.port());

    let mut nonce = vec![0; 32];
    rand::rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let pad = vec![0; 100]; // should be generated randomly but we don't really care

    // Handle auth eip8 message
    let (payload, shared_mac_data) = utils::read_auth_eip8(stream).await?;
    let (remote_id, remote_nonce, ephemeral_shared_secret) =
        utils::verify_auth_eip8(&payload, &shared_mac_data, private_key, &ephemeral_privkey);
    span.record("remote_id", hex::encode(&remote_id));

    // Send Ack message
    let init_msg = utils::create_ack(&remote_id, &nonce, &ephemeral_privkey, &pad);
    stream.write_all(&init_msg).await?;

    // Setup Frame
    // IMPORTANT!!! When receiving connection we reverse nonce order (see https://github.com/paradigmxyz/reth/blob/main/crates/net/ecies/src/algorithm.rs#L584C31-L584C39)
    let nonce_material = [nonce.clone(), remote_nonce.clone()].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&nonce_material);
    let h_nonce = hasher.finalize().to_vec();
    let remote_data = [shared_mac_data, payload].concat();
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
        remote_nonce,
        nonce,
        ephemeral_shared_secret,
        remote_data,
        init_msg,
        h_nonce,
    );

    info!("Sending HELLO message");
    // Create Hello
    let secp = secp256k1::Secp256k1::new();
    let private_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let hello_message = message::HelloMessage {
        protocol_version: message::BASE_PROTOCOL_VERSION,
        client: String::from("deadbrain corp."),
        capabilities: vec![
            ("eth".into(), 64),
            ("eth".into(), 65),
            ("eth".into(), 66),
            ("eth".into(), 67),
            ("eth".into(), 68),
            ("eth".into(), 69),
        ],
        port: 0,
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
            [1..]
            .to_vec(),
    };

    let payload = message::create_hello_message(hello_message);
    let _ = utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes).await;

    // Handle HELLO
    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).await
    {
        Ok(ub) => ub,
        Err(err) => {
            return Err(format!("{:?}", err).into());
        }
    };

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        let reason = message::parse_disconnect_message(&uncrypted_body[1..])
            .map(message::disconnect_reason_str)
            .unwrap_or("Unknown disconnect reason");
        trace!("Disconnect: {}", reason);
        return Err("Received disconnect message".into());
    }

    // Should be HELLO
    if uncrypted_body[0] != 0x80 {
        trace!("message received is not HELLO");
        return Err("First message should be Hello".into());
    }

    let hello = message::parse_hello_message(&uncrypted_body[1..]);
    info!("{:?}", &hello);

    let capabilities = serde_json::to_string(&hello.capabilities).unwrap();

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello.capabilities {
        if capability.0.to_string() == "eth" {
            if capability.1 > version && capability.1 < 70 {
                version = capability.1;
            }
        }
    }

    info!("Handling STATUS message");
    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).await
    {
        Ok(body) => body,
        Err(err) => {
            trace!("Fail to read STATUS message");
            return Err(err);
        }
    };
    if uncrypted_body[0] == 0x01 {
        let reason = message::parse_disconnect_message(&uncrypted_body[1..])
            .map(message::disconnect_reason_str)
            .unwrap_or("Unknown disconnect reason");
        trace!("Disconnect: {}", reason);

        return Err("Disconnected peer".into());
    }

    let (network_id, fork_id, genesis) = if version >= 69 {
        let status = match message::parse_eth69_status_message(&uncrypted_body[1..]) {
            Ok(status) => status,
            Err(err) => {
                warn!("Fail to parse STATUS eth/69 : {}", err);
                return Err(err);
            }
        };

        info!("Found eth69 status {:?}", &status);

        let reply = message::Status69 {
            version,
            network_id: NETWORK_ID,
            genesis: GENESIS_HASH.to_vec(),
            fork_id: (FORK_HASH.to_vec(), FORK_NEXT),
            earliest: 0,
            latest: 0,
            latest_hash: GENESIS_HASH.to_vec(),
        };
        let payload = message::create_eth69_status_message(reply);
        let _ = utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes).await;

        (status.network_id, status.fork_id.0, status.genesis)
    } else {
        let status = match message::parse_status_message(&uncrypted_body[1..]) {
            Ok(status) => status,
            Err(err) => {
                warn!("Fail to parse STATUS eth/68 and lower : {}", err);
                return Err(err);
            }
        };
        info!("Found status {:?}", &status);

        let reply = message::Status {
            version,
            network_id: NETWORK_ID,
            td: vec![0],
            blockhash: GENESIS_HASH.to_vec(),
            genesis: GENESIS_HASH.to_vec(),
            fork_id: (FORK_HASH.to_vec(), FORK_NEXT),
        };
        let payload = message::create_status_message(reply);
        let _ = utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes).await;

        (status.network_id, status.fork_id.0, status.genesis)
    };

    info!("Sending STATUS message done");

    let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
    sqlx::query("INSERT INTO nodes (ip, tcp_port, id, network_id, fork_id, genesis, client, capabilities) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET network_id=$4, fork_id = $5, genesis=$6, client=$7, capabilities=$8;")
        .bind(peer_addr.ip().to_string())
        .bind(peer_addr.port() as i32)
        .bind(&remote_id)
        .bind(network_id as i64)
        .bind(&fork_id)
        .bind(&genesis)
        .bind(&hello.client)
        .bind(serde_json::to_value(&cap).unwrap())
        .execute(pool)
        .await
        .unwrap();

    Ok(())
}

async fn handle_outgoing_connection(
    stream: &mut TcpStream,
    pool: &PgPool,
    remote_id: &[u8],
) -> Result<(), Box<dyn Error>> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let mut nonce = vec![0; 32];
    rand::rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng())
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
        utils::create_auth_eip8(remote_id, &private_key, &nonce, &ephemeral_privkey, &pad);

    // send the message
    info!("Sending EIP8 Auth message");

    if let Err(err) = stream.write_all(&init_msg).await {
        return Err(format!("Fail to send AUTH message : {}", err).into());
    };

    info!("waiting for answer...");

    // Read Ack
    let (payload, shared_mac_data) = match utils::read_ack_message(stream).await {
        Ok((payload, shared_mac_data)) => (payload, shared_mac_data),
        Err(err) => {
            return Err(format!("Fail to read ACK message : {}", err).into());
        }
    };

    // Handle Ack
    info!("ACK message received");
    let decrypted = utils::decrypt_message(&payload, &shared_mac_data, &private_key);

    // decode RPL data
    let rlp = rlp::Rlp::new(&decrypted);

    // id to pubkey
    let remote_public_key: Vec<u8> = [vec![0x04], rlp.at(0).unwrap().as_val().unwrap()].concat();
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
    let (mut ingress_aes, mut ingress_mac, mut egress_aes, mut egress_mac) = utils::setup_frame(
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

    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).await
    {
        Ok(ub) => ub,
        Err(err) => {
            return Err(format!("Failed to read Hello message : {}", err).into());
        }
    };

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        let reason = message::parse_disconnect_message(&uncrypted_body[1..])
            .map(message::disconnect_reason_str)
            .unwrap_or("Unknown disconnect reason");
        trace!("Disconnect: {}", reason);
        return Err("Received disconnect message".into());
    }

    // Should be HELLO
    if uncrypted_body[0] != 0x80 {
        trace!("message received is not HELLO");
        return Err("First message should be Hello".into());
    }
    let hello_message = message::parse_hello_message(&uncrypted_body[1..]);

    let capabilities = serde_json::to_string(&hello_message.capabilities).unwrap();

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello_message.capabilities {
        if capability.0.to_string() == "eth" {
            if capability.1 > version && capability.1 < 70 {
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
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
            [1..]
            .to_vec(),
    };

    let payload = message::create_hello_message(hello);
    let _ = utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes).await;

    /******************
     *
     *  Send STATUS message
     *
     *  We send ours right away instead of waiting to receive
     *  theirs first: some implementations wait for our STATUS
     *  before sending their own, and will disconnect with a
     *  timeout error if we wait too.
     *
     ******************/

    info!("Sending STATUS message");
    if version >= 69 {
        let reply = message::Status69 {
            version,
            network_id: NETWORK_ID,
            genesis: GENESIS_HASH.to_vec(),
            fork_id: (FORK_HASH.to_vec(), FORK_NEXT),
            earliest: 0,
            latest: 0,
            latest_hash: GENESIS_HASH.to_vec(),
        };
        let _ = utils::send_message(
            message::create_eth69_status_message(reply),
            stream,
            &mut egress_mac,
            &mut egress_aes,
        )
        .await;
    } else {
        let reply = message::Status {
            version,
            network_id: NETWORK_ID,
            td: vec![0],
            blockhash: GENESIS_HASH.to_vec(),
            genesis: GENESIS_HASH.to_vec(),
            fork_id: (FORK_HASH.to_vec(), FORK_NEXT),
        };
        let _ = utils::send_message(
            message::create_status_message(reply),
            stream,
            &mut egress_mac,
            &mut egress_aes,
        )
        .await;
    }

    /******************
     *
     *  Handle STATUS message
     *
     ******************/

    info!("Handling STATUS message");
    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).await
    {
        Ok(ub) => ub,
        Err(err) => {
            return Err(format!("Failed to read STATUS message : {}", err).into());
        }
    };

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        let reason = message::parse_disconnect_message(&uncrypted_body[1..])
            .map(message::disconnect_reason_str)
            .unwrap_or("Unknown disconnect reason");
        return Err(format!("DISCONNECT reason : {}", reason).into());
    }

    let (their_network_id, their_fork_id, their_genesis) = if version >= 69 {
        let their_status = message::parse_eth69_status_message(&uncrypted_body[1..])?;
        info!("network_id = {:?}", &their_status.network_id);

        (
            their_status.network_id,
            their_status.fork_id.0,
            their_status.genesis,
        )
    } else {
        let their_status = message::parse_status_message(&uncrypted_body[1..])?;
        info!("network_id = {:?}", &their_status.network_id);

        (
            their_status.network_id,
            their_status.fork_id.0,
            their_status.genesis,
        )
    };

    let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
    sqlx::query("UPDATE nodes SET network_id = $1, fork_id = $2, genesis = $3, capabilities = $4, client = $5, last_ping_timestamp = NOW() WHERE id = $6;")
        .bind(their_network_id as i64)
        .bind(&their_fork_id)
        .bind(&their_genesis)
        .bind(serde_json::to_value(&cap).unwrap())
        .bind(&hello_message.client)
        .bind(&remote_id)
        .execute(pool)
        .await
        .unwrap();

    Ok(())
}
