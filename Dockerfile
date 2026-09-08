FROM rustlang/rust:nightly-alpine AS build

RUN apk add --no-cache cmake make
WORKDIR /app
COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --locked --release

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /app/target/release/minecraft-auth /minecraft-auth

USER 65532:65532
ENTRYPOINT ["/minecraft-auth"]
