const BASE_PROTOCOL_OFFSET: u8 = 16;
pub const BASE_PROTOCOL_VERSION: u32 = 5;

pub fn create_ping_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x02];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn create_pong_message() -> Vec<u8> {
    let payload = rlp::encode_list(&[0_u8; 0]);
    let code: Vec<u8> = vec![0x03];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

#[derive(Debug)]
pub struct Status {
    pub version: u32,
    pub network_id: u64,
    pub td: Vec<u8>,
    pub blockhash: Vec<u8>,
    pub genesis: Vec<u8>,
    pub fork_id: (Vec<u8>, u64), // [Fork Hash, Next Fork]
}

// Create status message following the ETH protocol
pub fn create_status_message(status: Status) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    s.append(&status.version);
    s.append(&status.network_id);
    s.append(&status.td);
    s.append(&status.blockhash);
    s.append(&status.genesis);
    s.begin_list(2);
    s.append(&status.fork_id.0);
    s.append(&status.fork_id.1);

    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_status_message(payload: Vec<u8>) -> Option<Status> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    if r.is_empty() {
        return None;
    }

    let version: u32 = r.at(0).unwrap().as_val().unwrap();
    let network_id: u64 = r.at(1).unwrap().as_val().unwrap();
    let td: Vec<u8> = r.at(2).unwrap().as_val().unwrap();
    let blockhash: Vec<u8> = r.at(3).unwrap().as_val().unwrap();
    let genesis: Vec<u8> = r.at(4).unwrap().as_val().unwrap();

    // get forkid info
    let forkidrlp = r.at(5).unwrap();
    assert!(forkidrlp.is_list());
    let fork_hash: Vec<u8> = forkidrlp.at(0).unwrap().as_val().unwrap();
    let fork_next: u64 = forkidrlp.at(1).unwrap().as_val().unwrap();

    let status = Status {
        version,
        network_id,
        td,
        blockhash,
        genesis,
        fork_id: (fork_hash, fork_next),
    };

    return Some(status);
}

#[derive(Debug)]
pub struct Status69 {
    pub version: u32,
    pub network_id: u64,
    pub genesis: Vec<u8>,
    pub fork_id: (Vec<u8>, u64),
    pub earliest: u32,
    pub latest: u32,
    pub latest_hash: Vec<u8>,
}

pub fn create_eth69_status_message(status: Status69) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.begin_unbounded_list();
    s.append(&status.version);
    s.append(&status.network_id);
    s.append(&status.genesis);
    s.begin_list(2);
    s.append(&status.fork_id.0);
    s.append(&status.fork_id.1);
    s.append(&status.earliest);
    s.append(&status.latest);
    s.append(&status.latest_hash);
    s.finalize_unbounded_list();

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x00 + BASE_PROTOCOL_OFFSET];

    let mut enc = snap::raw::Encoder::new();
    let payload_compressed = enc.compress_vec(&payload).unwrap();

    return [code.to_vec(), payload_compressed].concat();
}

pub fn parse_eth69_status_message(payload: Vec<u8>) -> Option<Status69> {
    let mut dec = snap::raw::Decoder::new();
    let message = dec.decompress_vec(&payload).unwrap();

    let r = rlp::Rlp::new(&message);
    assert!(r.is_list());

    if r.is_empty() {
        return None;
    }

    let version: u32 = r.at(0).unwrap().as_val().unwrap();
    let network_id: u64 = r.at(1).unwrap().as_val().unwrap();
    let genesis: Vec<u8> = r.at(2).unwrap().as_val().unwrap();
    let forkidrlp = r.at(3).unwrap();
    assert!(forkidrlp.is_list());
    let fork_hash: Vec<u8> = forkidrlp.at(0).unwrap().as_val().unwrap();
    let fork_next: u64 = forkidrlp.at(1).unwrap().as_val().unwrap();
    let earliest: u32 = r.at(4).unwrap().as_val().unwrap();
    let latest: u32 = r.at(5).unwrap().as_val().unwrap();
    let latest_hash: Vec<u8> = r.at(6).unwrap().as_val().unwrap();

    Some(Status69 {
        version,
        network_id,
        genesis,
        fork_id: (fork_hash, fork_next),
        earliest,
        latest,
        latest_hash,
    })
}

#[derive(Clone, Debug)]
pub struct HelloMessage {
    pub protocol_version: u32,
    pub client: String,
    pub capabilities: Vec<(String, u32)>,
    pub port: u16,
    pub id: Vec<u8>,
}

pub fn create_hello_message(hello: HelloMessage) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();

    s.begin_list(5);
    s.append(&hello.protocol_version);
    s.append(&hello.client);

    s.begin_list(hello.capabilities.len());
    for capability in hello.capabilities {
        s.begin_list(2);
        s.append(&capability.0);
        s.append(&capability.1);
    }

    s.append(&hello.port);
    s.append(&hello.id);

    let payload = s.as_raw();
    let code: Vec<u8> = vec![0x80];
    // Add HELLO code in front
    let message = [code.to_vec(), payload.to_vec()].concat();

    return message;
}

pub fn parse_hello_message(payload: Vec<u8>) -> HelloMessage {
    let r = rlp::Rlp::new(&payload);
    assert!(r.is_list());

    let protocol_version: u32 = r.at(0).unwrap().as_val().unwrap();
    let client: String = r.at(1).unwrap().as_val().unwrap();
    let capabilities_list = r.at(2).unwrap();

    let mut capabilities: Vec<(String, u32)> = vec![];
    for i in 0..capabilities_list.item_count().unwrap() {
        let capability = capabilities_list.at(i).unwrap();
        assert!(capability.is_list());

        let name: String = capability.at(0).unwrap().as_val().unwrap();
        let version: u32 = capability.at(1).unwrap().as_val().unwrap();

        capabilities.push((name, version));
    }

    let port = r.at(3).unwrap().as_val().unwrap();
    let id = r.at(4).unwrap().as_val().unwrap();

    HelloMessage {
        protocol_version,
        client,
        capabilities,
        port,
        id,
    }
}
