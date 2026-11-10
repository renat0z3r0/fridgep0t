# ---- build stage -----------------------------------------------------------
# Both base images are pinned by the digest of their multi-arch manifest list,
# so a build fetches exactly what was reviewed; the tag stays for readability
# only. Digests recorded 2026-11-09. To refresh one:
#   podman pull <image:tag>
#   podman image inspect --format '{{index .RepoDigests 0}}' <image:tag>
FROM docker.io/library/rust:1.83-slim-bookworm@sha256:540c902e99c384163b688bbd8b5b8520e94e7731b27f7bd0eaa56ae1960627ab AS build
WORKDIR /src
# Cache the dependency build first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked || true
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- runtime stage ---------------------------------------------------------
# Distroless static: no shell, no package manager, nonroot by default. Nothing
# for an attacker to pivot to even in the impossible case they escape the decoy.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/fridgep0t /fridgep0t
USER nonroot
# LOG_PATH and TLS_DIR point at a writable volume; the rootfs stays read-only.
# TLS_DIR keeps the generated certificate, so a restart serves the same one.
ENV LOG_PATH=/logs/events.jsonl TLS_DIR=/logs/tls HTTP_PORT=8080 HTTPS_PORT=8443
EXPOSE 8080 8443
ENTRYPOINT ["/fridgep0t"]
