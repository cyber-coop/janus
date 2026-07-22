use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use toml;

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub user: String,
    pub password: String,
    pub dbname: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct NodeConfig {
    // Optional explicit override: hex-encoded secp256k1 secret key for the
    // node's identity on the discovery network. If not set here, it falls
    // back to a separate, auto-managed key file (see main.rs) rather than
    // ever being written into this file.
    pub secret_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    #[serde(default)]
    pub node: NodeConfig,
}

pub fn read_config() -> Config {
    let mut file = File::open("config.toml").expect("config.toml file required");
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let config: Config = toml::from_str(&contents).unwrap();

    return config;
}
