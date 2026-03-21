FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && apt-get clean

WORKDIR /build
COPY . /build/innerwarden-mesh

# Build the test binary
WORKDIR /build/innerwarden-mesh
RUN cargo build --release --example mesh_node 2>&1

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && apt-get clean
COPY --from=builder /build/innerwarden-mesh/target/release/examples/mesh_node /usr/local/bin/mesh_node

ENTRYPOINT ["/usr/local/bin/mesh_node"]
