# ── Builder ───────────────────────────────────────────────────────────────────
FROM rust:slim AS builder

WORKDIR /usr/src/janus

COPY . .
RUN cargo install --path .

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:trixie-slim

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Programs that map nodes network (Ethereum and Ethereum like)."

COPY --from=builder /usr/local/cargo/bin/janus /usr/local/bin/janus

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# TCP/UDP port server
EXPOSE 30303/tcp
EXPOSE 30303/udp

# Default log is info
ENV RUST_LOG="janus=info"

ENTRYPOINT ["janus"]
