# ImmichCrypt

Encrypted S3 proxy for Immich with multi-slot key recovery.

Sits between [Immich](https://immich.app) and any S3-compatible storage (MinIO, Cloudflare R2, Backblaze B2), encrypting all photos with **AES-256-GCM** before they leave your server. A LUKS-style key slot system gives you 5 ways to unlock the master key — no single point of failure.

## Features

- **AES-256-GCM encryption** — random 12-byte nonce per file
- **5 recovery paths** — password, SSH key, YubiKey (planned), env var, Shamir 2-of-3
- **Auto-unlock** — tries SSH key → password → env var automatically
- **SigV4 re-signing** — transparent pass-through to any S3 API
- **Quantum-resistant** — symmetric encryption, no asymmetric crypto
- **No vendor lock-in** — works with MinIO, R2, B2, or any S3-compatible backend

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -ldflags="-s -w" -o ImmichCrypt ./cmd/proxy/

# Generate a master key (save in Bitwarden)
openssl rand -base64 32

# Run
SSE_C_KEY="<your-base64-key>" \
R2_ENDPOINT="http://minio:9000" \
R2_ACCESS_KEY_ID="<key>" \
R2_SECRET_ACCESS_KEY="<secret>" \
R2_BUCKET="immich-photos" \
./ImmichCrypt
```

## Recovery Methods

| Method | Setup | Recovery |
|---|---|---|
| Password | `MASTER_PASSWORD=...` | Type password at startup |
| SSH Key | Auto-detected from `~/.ssh/` | No action needed |
| YubiKey | Hardware token (planned) | Tap USB key |
| SSE_C_KEY | Env var | Direct key access |
| Email (Shamir) | 2-of-3 shares | Contact 2 recovery contacts |

## Architecture

```
Immich ──► ImmichCrypt :2300
              │
              ├─ Try SSH key    → unlock master key
              ├─ Try password   → unlock master key
              ├─ Try YubiKey    → unlock master key (planned)
              ├─ Try SSE_C_KEY  → direct AES key
              │
              └─ AES-256-GCM encrypt/decrypt photo data
              └─ SigV4 re-sign → forward to S3
```

## License

MIT
