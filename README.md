# kissl - Keep it Simple SSL

A small certificate authority manager for lab environments, written in Go using only the standard library. I don't need anything complicated and I was tired of doing this by hand, so this was born.

kissl provides a modern web interface and REST API for:

- Creating root and issuing certificate authorities
- Registering servers
- Signing server CSRs
- Renewing and removing certificates
- Downloading PEM certificates or base64-encoded PKCS#7/P7B bundles
- Managing per-server API credentials
- Downloading an OpenSSL CSR configuration template

Certificate files are stored in individual directories, while metadata and authentication records are stored as JSON.

## Requirements

- Go 1.22 or newer
- GNU Make, if using the included `Makefile`
- Docker, optionally

## Quick start

Set an administrator token and start the application:

```sh
KISSL_ADMIN_TOKEN='replace-with-a-long-random-token' go run .
```

Open <http://localhost:8080> and sign in with the administrator token.

If `KISSL_ADMIN_TOKEN` is not set, kissl generates a temporary administrator token and prints it to the application log. A new token is generated after every restart, so explicitly configuring one is recommended.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `KISSL_ADDR` | `:8080` | HTTP listen address |
| `KISSL_DATA_DIR` | `./data` | Persistent certificate and JSON data directory |
| `KISSL_ADMIN_TOKEN` | Generated at startup | Administrator login and bearer token |
| `KISSL_COOKIE_SECURE` | `false` | Set to `true` to mark administrator session cookies as Secure |

The service speaks plain HTTP. For access outside a trusted lab network, place it behind an HTTPS reverse proxy and set `KISSL_COOKIE_SECURE=true`.

## Web interface

The web interface supports:

- Root and issuing CA creation and removal
- One-step server registration and CSR signing
- Separate server registration and certificate issuance
- PEM and P7B certificate downloads
- Server certificate removal
- API credential enable, disable, and revoke actions
- An in-app REST API reference
- Light and dark themes

New server credentials are disabled by default. An administrator must enable them before the server can use authenticated API endpoints.

## Filesystem layout

```text
data/
  auth.json
  ca/
    <ca-id>/
      metadata.json
      root-cert.pem
      root-key.pem
      issuing-cert.pem
      issuing-key.pem
  servers/
    <server-id>/
      metadata.json
      csr.pem
      cert.pem
```

Private keys and JSON authentication data are written with restrictive permissions. Writes use temporary files and atomic rename operations.

Protect `/data`, its backups, and the host running kissl. CA private keys are intentionally stored unencrypted because kissl is designed for controlled lab environments.

## REST API

API errors are returned as JSON:

```json
{"error":"description"}
```

### Download the OpenSSL CSR template

No authentication is required:

```sh
curl -o openssl.cnf \
  http://localhost:8080/api/v1/openssl.cnf
```

The template contains:

- Default subject values for WTFerris Net
- Editable common name and SAN examples
- Private-key and CSR generation commands
- Commented API registration, issuance, and download examples using the request's current base URL

After editing the common name and SAN entries, generate a key and CSR:

```sh
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out server.key

openssl req \
  -new \
  -key server.key \
  -out server.csr \
  -config openssl.cnf
```

Keep `server.key` on the server. kissl only needs the CSR.

### Register a server

Registration does not require authentication:

```sh
curl -X POST \
  http://localhost:8080/api/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"server.example.lab"}'
```

Example response:

```json
{
  "server_id": "SERVER_ID",
  "token": "ONE_TIME_BEARER_TOKEN",
  "enabled": false
}
```

The plaintext token is returned only once. kissl stores its SHA-256 hash in `auth.json`.

Server names are unique using case-insensitive comparison with surrounding whitespace ignored. Duplicate registration attempts return `409 Conflict`.

### Authentication

Authenticated server endpoints require the token returned during registration:

```text
Authorization: Bearer ONE_TIME_BEARER_TOKEN
```

A newly registered token returns `403 Forbidden` until an administrator enables it. Invalid and revoked tokens return `401 Unauthorized`.

### Get server status

```sh
curl \
  http://localhost:8080/api/v1/server \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN'
```

### Issue the first certificate

Send the PEM CSR as the raw request body. The CA ID is part of the URL and `valid` is the requested validity in days:

```sh
curl -X POST \
  'http://localhost:8080/api/v1/ca/CA_ID/server/certificate?valid=90' \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN' \
  -H 'Content-Type: application/pkcs10' \
  --data-binary @server.csr
```

If `valid` is omitted, it defaults to 90 days. Certificate validity must be between 1 and 825 days and cannot exceed the issuing CA expiration date.

The CSR signature is validated. DNS, IP, email, and URI SANs from the CSR are preserved in the issued certificate.

### Renew a certificate

Renewal uses the CSR stored during the initial issuance:

```sh
curl -X POST \
  http://localhost:8080/api/v1/server/renew \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"validity_days":90}'
```

### Download a PEM certificate

```sh
curl \
  http://localhost:8080/api/v1/server/certificate \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN' \
  -o server.pem
```

### Download a P7B certificate chain

```sh
curl \
  'http://localhost:8080/api/v1/server/certificate?format=p7b' \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN' \
  -o server-chain.p7b
```

The P7B response is a base64-encoded PEM PKCS#7 bundle containing:

1. The server certificate
2. The issuing CA certificate
3. The root CA certificate

The CA overview provides a **Download Chain** link that returns a PEM bundle containing the issuing certificate followed by the root certificate. Administrator certificate download URLs also accept `?format=p7b`.

### Remove a certificate

```sh
curl -X DELETE \
  http://localhost:8080/api/v1/server/certificate \
  -H 'Authorization: Bearer ONE_TIME_BEARER_TOKEN'
```

This removes the issued certificate and stored CSR, but keeps the server registration and API credential.

## Build and test

The default Make target compiles kissl and runs the unit tests:

```sh
make
```

Available targets:

| Target | Description |
|---|---|
| `make` or `make all` | Build the executable and run unit tests |
| `make build` | Build `bin/kissl` |
| `make test` | Run unit tests |
| `make test-race` | Run tests with Go's race detector |
| `make run` | Run the application |
| `make clean` | Remove build artifacts |

The equivalent direct Go commands are:

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

## Docker

Build the multi-stage image:

```sh
docker build -t kissl .
```

Run it with a named volume mounted at `/data`:

```sh
docker run --rm \
  -p 8080:8080 \
  -e KISSL_ADMIN_TOKEN='replace-with-a-long-random-token' \
  -v kissl-data:/data \
  kissl
```

The final Alpine container runs as the unprivileged `kissl` user. All certificates, keys, metadata, and authentication records are stored beneath `/data`.

## Security notes

kissl is intended for lab use, but includes moderate protections:

- ECDSA P-256 root and issuing CA keys
- Random 128-bit certificate serial numbers
- CSR signature validation
- CA and leaf validity limits
- Hashed per-server bearer tokens
- Disabled-by-default server registrations
- Constant-time token comparisons
- HttpOnly, SameSite=Strict administrator session cookies
- Same-origin checks for browser mutations
- Restrictive private-key and authentication-file permissions
- Internally generated and validated filesystem identifiers
- Atomic file writes
- Standard browser security headers

For stronger security, run kissl behind HTTPS, restrict network access, protect the data volume and backups, and use a long random administrator token.
