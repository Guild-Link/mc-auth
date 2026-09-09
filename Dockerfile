FROM rust:alpine AS build

ENV RUSTUP_TOOLCHAIN=nightly-2026-09-08
RUN apk add --no-cache cmake make \
    && rustup toolchain install nightly-2026-09-08 --profile minimal

WORKDIR /app
COPY src ./src
COPY Cargo.toml Cargo.lock ./

RUN cargo build --locked --release

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /app/target/release/mc-auth /mc-auth

USER 65532:65532
ENTRYPOINT ["/mc-auth"]
