# syntax=docker/dockerfile:1

# This Containerfile expects a pre-built lgtm-lbac-proxy binary
# Build the binary first: CGO_ENABLED=0 go build -ldflags="-w -s" -trimpath -o lgtm-lbac-proxy .

# Helper stage to create user and get certificates
FROM alpine:3.24.3 AS prep

# Create nonroot user
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

# Update CA certificates
RUN apk add --no-cache ca-certificates tzdata

# Final runtime stage
FROM scratch

# Copy CA certificates for HTTPS requests
COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/ca/ca-certificates.crt

# Copy timezone data
COPY --from=prep /usr/share/zoneinfo /usr/share/zoneinfo

# Copy user and group files
COPY --from=prep /etc/passwd /etc/passwd
COPY --from=prep /etc/group /etc/group

# Copy the pre-built binary
COPY lgtm-lbac-proxy /usr/local/bin/lgtm-lbac-proxy

# Run as non-root user
USER 65532:65532

# Add metadata labels
LABEL org.opencontainers.image.title="LGTM LBAC Proxy" \
      org.opencontainers.image.description="Label-Based Access Control proxy for LGTM stack (Loki, Grafana, Tempo, Mimir)" \
      org.opencontainers.image.vendor="at-blacknight-projects" \
      org.opencontainers.image.source="https://github.com/at-blacknight-projects/lgtm-lbac-proxy" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Health check using the binary itself
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/lgtm-lbac-proxy", "--version"]

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/lgtm-lbac-proxy"]
