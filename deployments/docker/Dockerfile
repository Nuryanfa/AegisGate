FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway \
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
