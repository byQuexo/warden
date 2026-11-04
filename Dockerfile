# Multi-stage build: gateway, CLI and mock MCP server in one small image.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p warden-gateway -p warden-cli -p warden-testkit

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/warden && chown 65532:65532 /var/lib/warden
COPY --from=build /src/target/release/warden-gateway /src/target/release/warden /src/target/release/mock-mcp /usr/local/bin/
USER 65532:65532
EXPOSE 8088 8089
ENTRYPOINT ["warden-gateway"]
CMD ["--config", "/etc/warden/gateway.yaml"]
