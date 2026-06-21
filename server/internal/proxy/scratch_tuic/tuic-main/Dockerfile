# Modify by Shadowsocks-rust Dockerfile
FROM --platform=$BUILDPLATFORM rust:alpine AS builder
ARG TARGETARCH
RUN set -x \
    && apk add --no-cache build-base
WORKDIR /root/tuic
ADD . .
RUN case "$TARGETARCH" in \
    "386") \
    RUST_TARGET="i686-unknown-linux-musl" \
    MUSL="i686-linux-musl" \
    ;; \
    "amd64") \
    RUST_TARGET="x86_64-unknown-linux-musl" \
    MUSL="x86_64-linux-musl" \
    ;; \
    "arm64") \
    RUST_TARGET="aarch64-unknown-linux-musl" \
    MUSL="aarch64-linux-musl" \
    ;; \
    *) \
    echo "Doesn't support $TARGETARCH architecture" \
    exit 1 \
    ;; \
    esac \
    && wget -qO- "https://musl.cc/$MUSL-cross.tgz" | tar -xzC /root/ \
    && PATH="/root/$MUSL-cross/bin:$PATH" \
    && CC=/root/$MUSL-cross/bin/$MUSL-gcc \
    && echo "CC=$CC" \
    && rustup override set nightly \
    && rustup target add "$RUST_TARGET" \
    && RUSTFLAGS="-C linker=$CC" CC=$CC cargo build --target "$RUST_TARGET" --release \
    && mv target/$RUST_TARGET/release/tuic-server target/release/

FROM alpine:3.16 AS tuic-server

COPY --from=builder /root/tuic/target/release/tuic-server /usr/local/bin/tuic-server

ENTRYPOINT ["tuic-server"]
