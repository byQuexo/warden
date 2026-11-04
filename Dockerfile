# Multi-stage build: gateway, CLI and mock MCP server in one small image.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p agent-scope-gateway -p agent-scope-cli -p agent-scope-testkit

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/agent-scope && chown 65532:65532 /var/lib/agent-scope
COPY --from=build /src/target/release/agent-scope-gateway /src/target/release/agent-scope /src/target/release/mock-mcp /usr/local/bin/
USER 65532:65532
EXPOSE 8088 8089
ENTRYPOINT ["agent-scope-gateway"]
CMD ["--config", "/etc/agent-scope/gateway.yaml"]
