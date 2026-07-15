# Janus

<p align="center">
  <img src="https://mythologica.fr/rome/pic/janus.jpg" alt="Janus, the two-faced Roman god of doorways and transitions" width="250">
</p>

Collect all the node found on Ethereum DISCV4 protocol (but not all them are Ethereum). The nodes IP are stored in a postgres database.

## Quick Start

```
$ git clone https://github.com/cyber-coop/eth-node-finder.git
$ cp config.example.toml config.toml
$ docker compose up
```

## Dev

Start postgres via docker compose.
```
$ docker compose up -d postgres
```

Create your `config.toml` from `config.example.toml`.

Start `janus` to see it running. It's a single binary/process that does discovery (DISCV4), accepts incoming connections, and dials out to check node status, all sharing one node identity.
```
$ RUST_LOG=info cargo run
```

## Database migrations

Schema changes live under `migrations/` (managed with `sqlx`). To apply pending migrations against a running database:
```
$ cargo install sqlx-cli --no-default-features --features postgres
$ sqlx migrate run --database-url postgres://postgres:wow@localhost:5432/blockchains
```

## Postgres

```
$ docker exec -ti postgres bash
```

Once inside the container
```
$ psql -U postgres -d blockchains
> SELECT * FROM nodes;
> SELECT * FROM nodes WHERE network_id IS NOT NULL;
```
