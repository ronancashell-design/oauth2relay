# Build:  make docker            (or docker build --build-arg VERSION=2.0.0 .)
# Run:    docker run -p 8080:8080 -v /etc/oauth2relay:/etc/oauth2relay:ro oauth2relay:2.0.0
#
# The configuration is read from /etc/oauth2relay/config.json. Set "host" to
# "0.0.0.0" in it, otherwise the relay only listens inside the container.

# The build stage runs on the build machine's platform and cross-compiles, so
# multi-platform images (docker buildx --platform linux/amd64,linux/arm64)
# need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.VERSION=${VERSION}" -o /out/oauth2relay ./cmd/oauth2relay

# static-debian13 has CA certificates and time zone data, and no shell or
# package manager. The user is numeric so that Kubernetes runAsNonRoot can
# check it.
FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="OAUTH2Relay" \
      org.opencontainers.image.description="OAuth 2.0 authentication relay" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="Fijomi Systems SL" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://oauth2relay.com/"
COPY --from=build /out/oauth2relay /usr/local/bin/oauth2relay
COPY LICENSE NOTICE /usr/share/doc/oauth2relay/
USER 65532:65532
# 8080 is the relay port and 9090 the suggested admin_port.
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/oauth2relay"]
CMD ["--config", "/etc/oauth2relay/config.json"]
