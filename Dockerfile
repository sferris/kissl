# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod ./
COPY *.go ./
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/kissl \
    .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S kissl \
    && adduser -S -G kissl kissl \
    && mkdir -p /data \
    && chown kissl:kissl /data

COPY --from=build /out/kissl /usr/local/bin/kissl

ENV KISSL_ADDR=:8080 \
    KISSL_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8080

USER kissl
ENTRYPOINT ["/usr/local/bin/kissl"]
