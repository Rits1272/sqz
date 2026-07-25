# Build sqzd as a static binary so it can run on a scratch-like base.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Copy manifests first so dependency download is cached independently of source.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
# The frontend is compiled into the binary via go:embed, so it must be present
# at build time — not mounted at runtime.
COPY web/ web/

# CGO_ENABLED=0 keeps go-nostr on its pure-Go secp256k1 path, which avoids
# needing libsecp256k1 in the runtime image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sqzd ./cmd/sqzd

FROM alpine:3.20

# Redis and relay connections are TLS in production; without CA certs every
# outbound handshake fails.
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 sqz

COPY --from=build /out/sqzd /usr/local/bin/sqzd

USER sqz
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sqzd"]
