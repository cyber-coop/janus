use discv4::Node;
use log::{error, info};
use secp256k1::SecretKey;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio_postgres::NoTls;

use janus::config;

const BOOTSTRAP_NODES: &[&str] = &[
	"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303", // bootnode-aws-ap-southeast-1-001
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",   // bootnode-aws-us-east-1-001
	"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303", // bootnode-hetzner-hel
	"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303", // bootnode-hetzner-fsn
];

#[tokio::main]
async fn main() {
    // init logger
    env_logger::init();

    let cfg = config::read_config();

    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );

    let (postgres_client, connection) = tokio_postgres::connect(&database_params, NoTls)
        .await
        .unwrap();
    info!("Connection to the database created");

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });

    let port = 30303;
    let node = Node::new(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into(),
        SecretKey::new(&mut secp256k1::rand::thread_rng()),
        BOOTSTRAP_NODES.iter().map(|v| v.parse().unwrap()).collect(),
        None,
        true,
        port,
    )
    .await
    .unwrap();

    let statement = postgres_client
        .prepare("INSERT INTO nodes VALUES ($1,$2,$3,$4);")
        .await
        .unwrap();
    loop {
        let target = rand::random();
        info!("Looking up random target: {}", target);
        let result = node.lookup(target).await;

        for entry in result {
            info!("Found node: {:?}", entry);
            // we don't check result because we don't care
            let _ = postgres_client
                .execute(
                    &statement,
                    &[
                        &entry.address.to_string(),
                        &(entry.tcp_port as i32),
                        &(entry.udp_port as i32),
                        &entry.id.as_bytes(),
                    ],
                )
                .await;
        }

        info!("Current nodes: {}", node.num_nodes());
    }
}
