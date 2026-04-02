FROM rust:1.86-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vendor ./vendor

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home trailing \
    && mkdir -p /data \
    && chown -R trailing:trailing /data

WORKDIR /app

COPY --from=builder /app/target/release/trailing /usr/local/bin/trailing

ENV TRAILING_PORT=3001
ENV TRAILING_DB_PATH=/data/trailing.db

VOLUME ["/data"]
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD sh -c 'if [ -n "$TRAILING_API_KEY" ]; then curl -fsS -H "x-api-key: $TRAILING_API_KEY" "http://127.0.0.1:${TRAILING_PORT}/v1/health" >/dev/null; else curl -fsS "http://127.0.0.1:${TRAILING_PORT}/v1/health" >/dev/null; fi'

USER trailing

CMD ["trailing", "serve"]
