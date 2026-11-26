# sandboxd container image (cycle 5, FR-CI1).
#
# Built by .github/workflows/release.yml from the release's own Linux binaries (the same archives
# that passed the escape suite), for linux/amd64 and linux/arm64:
#
#   bin/amd64/sandboxd, bin/arm64/sandboxd   (from the release archives)
#   docker buildx build --platform linux/amd64,linux/arm64 -f packaging/container/Dockerfile .
#
# Run:
#   docker run -p 8080:8080 -v sandboxd-cache:/var/cache/sandboxd \
#     -e SANDBOXD_TOKEN_SHA256=<from `sandboxd token new`> ghcr.io/<owner>/sandboxd
# or mount your own config at /etc/sandboxd/sandboxd.toml (and policies at /etc/sandboxd/policies).
FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

ARG TARGETARCH
LABEL org.opencontainers.image.title="sandboxd" \
      org.opencontainers.image.description="Run untrusted, agent-generated Python and JavaScript in a WebAssembly sandbox" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/SoumyabrataNandi/Agent_SandBox"

# ca-certificates: only for policies that grant HTTPS egress through the broker.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/sandboxd --shell /usr/sbin/nologin sandboxd \
 && mkdir -p /etc/sandboxd/policies /var/cache/sandboxd /var/lib/sandboxd/work \
 && chown -R sandboxd:sandboxd /var/cache/sandboxd /var/lib/sandboxd

COPY --chmod=0755 bin/${TARGETARCH}/sandboxd /usr/local/bin/sandboxd
COPY packaging/container/sandboxd.toml /etc/sandboxd/sandboxd.toml
COPY --chmod=0755 packaging/container/entrypoint.sh /usr/local/bin/sandboxd-entrypoint
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/sandboxd/

USER 10001:10001
ENV SANDBOXD_CONFIG=/etc/sandboxd/sandboxd.toml
VOLUME ["/var/cache/sandboxd"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sandboxd-entrypoint"]
CMD ["serve"]
