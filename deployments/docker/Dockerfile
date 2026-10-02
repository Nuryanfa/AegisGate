FROM golang:1.25-bookworm AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN set -eu; \
    for value in "$VERSION" "$COMMIT" "$BUILD_TIME"; do \
      if [ "${#value}" -gt 64 ]; then echo "build metadata exceeds 64 characters" >&2; exit 1; fi; \
      case "$value" in ''|*[!A-Za-z0-9._:+-]*) echo "build metadata contains unsupported characters" >&2; exit 1;; esac; \
    done; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildTime=$BUILD_TIME" -o /out/gateway ./cmd/gateway \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/example-upstream ./cmd/example-upstream

FROM gcr.io/distroless/static-debian12:nonroot AS gateway

WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /out/gateway /app/gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/gateway"]

FROM gcr.io/distroless/static-debian12:nonroot AS example-upstream

WORKDIR /app
COPY --from=builder --chown=nonroot:nonroot /out/example-upstream /app/example-upstream
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/app/example-upstream"]
