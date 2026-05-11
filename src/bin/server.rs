use discv4::Node;
use log::{error, info, warn};
use rand::RngCore;
use secp256k1::SecretKey;
use sha3::{Digest, Keccak256};
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

static SERVER_PORT: u16 = 50505;

use void::config;
use void::message;
use void::networks;
use void::utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // init logger
    env_logger::init();

    info!("Starting server");

    let cfg = config::read_config();
    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );
    let (postgres_client, connection) =
        tokio_postgres::connect(&database_params, tokio_postgres::NoTls)
            .await
            .unwrap();
    info!("Connection to the database created");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });

    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let secp = secp256k1::Secp256k1::new();

    let id = secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
        [1..]
        .to_vec();

    let _node = Node::new(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT).into(),
        private_key,
        networks::BOOTSTRAP_NODES
            .iter()
            .map(|v| v.parse().unwrap())
            .collect(),
        None,
        true,
        SERVER_PORT,
    )
    .await
    .unwrap();

    info!("Remote id {}", hex::encode(id));

    let private_key = private_key.secret_bytes();

    let tcp_bind_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, SERVER_PORT));
    let listener = TcpListener::bind(tcp_bind_addr).unwrap();
    info!("Server started on [::]:{SERVER_PORT}");

    let postgres = Arc::new(postgres_client);
    loop {
        let (mut socket, addr) = listener.accept().unwrap();
        // Set read timeout
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        info!("New connection: {:?}", addr);

        let postgres = postgres.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                &mut socket,
                &postgres,
                &private_key.to_vec(),
                networks::Network::ETHEREUM_MAINNET,
            )
            .await
            {
                error!("Failed to handle connection request : {}", err.to_string());
            };
        });

        info!("Connection closed ({:?})", addr);
    }
}

async fn handle_connection(
    stream: &mut TcpStream,
    postgres_client: &tokio_postgres::Client,
    private_key: &Vec<u8>,
    network: networks::Network,
) -> Result<(), Box<dyn Error>> {
    let insert_statement = postgres_client.prepare("INSERT INTO nodes (ip, tcp_port, id, network_id, fork_id, genesis, client, capabilities) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET network_id=$4, fork_id = $5, genesis=$6, client=$7, capabilities=$8;").await.unwrap();

    let mut nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ephemeral_privkey = SecretKey::new(&mut secp256k1::rand::thread_rng())
        .secret_bytes()
        .to_vec();
    let pad = vec![0; 100]; // should be generated randomly but we don't really care

    // Handle auth eip8 message
    let (payload, shared_mac_data) = utils::read_auth_eip8(stream).unwrap();
    let (remote_id, remote_nonce, ephemeral_shared_secret) =
        utils::verify_auth_eip8(&payload, &shared_mac_data, private_key, &ephemeral_privkey);

    // Send Ack message
    let init_msg = utils::create_ack(&remote_id, &nonce, &ephemeral_privkey, &pad);
    utils::send_ack_message(&init_msg, stream)?;

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
        ],
        port: 0,
        id: secp256k1::PublicKey::from_secret_key(&secp, &private_key).serialize_uncompressed()
            [1..]
            .to_vec(),
    };

    let payload = message::create_hello_message(hello_message);
    utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes);

    // Handle HELLO
    let uncrypted_body = match utils::read_message(stream, &mut ingress_mac, &mut ingress_aes) {
        Ok(ub) => ub,
        Err(err) => {
            return Err(format!("{:?}", err).into());
        }
    };

    if uncrypted_body[0] == 0x01 {
        // we have a disconnect message unfortunately
        error!("Disconnect {}", hex::encode(uncrypted_body[1..].to_vec()));
        return Err("Received disconnect message".into());
    }

    // Should be HELLO
    assert_eq!(0x80, uncrypted_body[0]);
    let hello = message::parse_hello_message(uncrypted_body[1..].to_vec());
    info!("{:?}", &hello);

    let capabilities = serde_json::to_string(&hello.capabilities).unwrap();

    // We need to find the highest eth version it supports
    let mut version = 0;
    for capability in &hello.capabilities {
        if capability.0.to_string() == "eth" {
            if capability.1 > version {
                version = capability.1;
            }
        }
    }

    info!("Handling STATUS message");
    let uncrypted_body = utils::read_message(stream, &mut ingress_mac, &mut ingress_aes).unwrap();
    if uncrypted_body[0] == 0x01 {
        warn!("Disconnect message : {}", hex::encode(&uncrypted_body));

        return Err("Disconnected peer".into());
    }
    let status = message::parse_status_message(uncrypted_body[1..].to_vec()).unwrap();

    info!("Found status {:?}", &status);

    info!("Sending STATUS message");
    let status_message = message::Status {
        version,
        network_id: network.network_id, // TODO: allow to do random networks
        td: network.head_td.to_be_bytes().to_vec(),
        blockhash: network.genesis_hash.to_vec(),
        genesis: network.genesis_hash.to_vec(),
        fork_id: (
            network.fork_id[0].to_be_bytes().to_vec(),
            network.fork_id[1].into(),
        ),
    };

    let payload = message::create_status_message(status_message);
    utils::send_message(payload, stream, &mut egress_mac, &mut egress_aes);

    let address = stream.peer_addr().expect("to have a peer address");
    let cap: Vec<(String, u32)> = serde_json::from_str(&capabilities).unwrap();
    let _ = postgres_client
        .execute(
            &insert_statement,
            &[
                &address.ip().to_string(),
                &(address.port() as i32),
                &remote_id,
                &(status.network_id as i64),
                &hello.client,
                &serde_json::to_value(&cap).unwrap(),
            ],
        )
        .await
        .unwrap();

    Ok(())
}
