CREATE TABLE IF NOT EXISTS nodes (
    ip TEXT NOT NULL,
    tcp_port INT,
    udp_port INT,
    id BYTEA NOT NULL PRIMARY KEY,
    network_id BIGINT,
    fork_id BYTEA,
    genesis BYTEA,
    client TEXT,
    capabilities JSON,
    last_ping_timestamp TIMESTAMP DEFAULT NULL
);
