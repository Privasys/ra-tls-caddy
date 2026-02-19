# RA-TLS Issuer for Caddy

A Caddy `tls.issuance` module (`ra_tls`) that produces **RA-TLS certificates** for Confidential Computing.

## Supported Backends

| Backend   | Hardware         | Status    |
|-----------|------------------|-----------|
| `tdx`     | Intel TDX        | Supported |
| `sev-snp` | AMD SEV-SNP     | Planned   |

The hardware-specific logic is abstracted behind the `Attester` interface ([attester.go](attester.go)). Each backend lives in its own file (e.g. [attester_tdx.go](attester_tdx.go)) and registers itself via `init()`.

## How It Works

The module supports two attestation paths:

### Deterministic (Issue path)

1. **Key Generation** — An ECDSA P-256 key pair is generated inside the TEE.
2. **Attestation** — We chose that `ReportData = SHA-512( SHA-256(DER public key) || creation_time )`, where `creation_time` is `NotBefore` truncated to 1-minute precision (`"2006-01-02T15:04Z"`). The quote is obtained from the configured backend.
3. **Certificate** — An X.509 certificate is signed by a user-provided **intermediary CA** (private PKI), embedding the attestation evidence in a backend-specific extension OID. The PEM output includes the full chain (leaf + CA cert).

Certificates are cached by certmagic and auto-renewed. A verifier reproduces the ReportData from the certificate alone.

### Challenge-Response (GetCertificate path)

When a TLS client sends a **RATS-TLS nonce** in its ClientHello (per `draft-ietf-rats-tls-attestation`):

1. **Ephemeral Key** — A fresh ECDSA P-256 key pair is generated.
2. **Attestation** — `ReportData = SHA-512( SHA-256(DER public key) || nonce )`, binding the quote to the client's challenge.
3. **Certificate** — A very short-lived (5 min) certificate is signed by the same CA, with the quote embedded.

This certificate is **not cached** — each challenge produces a unique response.

> **Note:** Go 1.25's `tls.ClientHelloInfo.Extensions` exposes the extension **type IDs** present in the ClientHello, so the module can detect that a RATS-TLS extension was sent. However, the raw extension **payloads** are not available, so the nonce cannot be extracted yet. When the extension is detected without a readable nonce, the module logs a warning and falls back to the deterministic certificate. To fully enable this path, intercept raw ClientHello bytes at the network layer or wait for Go to expose raw extension data.

## Requirements

- Linux host running inside a **Confidential VM**
- Backend-specific support:
  - `tdx` — Kernel configfs-tsm (`/sys/kernel/config/tsm/report`)
- An **intermediary CA** certificate and private key (private PKI)
- Go 1.25+ and [xcaddy](https://github.com/caddyserver/xcaddy)

## Building

```bash
# Install xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with the RA-TLS module
xcaddy build --with github.com/Privasys/caddy-ra-tls-module=.
```

## Caddyfile Usage

```caddyfile
example.com {
    tls {
        issuer ra_tls {
            backend tdx
            ca_cert /path/to/intermediate-ca.crt
            ca_key  /path/to/intermediate-ca.key
        }
    }
    respond "Hello from a Confidential VM!"
}
```

## JSON Config Usage

```json
{
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          {
            "subjects": ["example.com"],
            "issuers": [
              {
                "module": "ra_tls",
                "backend": "tdx",
                "ca_cert_path": "/path/to/intermediate-ca.crt",
                "ca_key_path": "/path/to/intermediate-ca.key"
              }
            ]
          }
        ]
      }
    }
  }
}
```

## Key Sensitivity

The ECDSA private key is generated inside the TEE and protected by hardware memory encryption at runtime. However, certmagic will PEM-encode and persist it via its storage backend. To prevent writing it to unencrypted disk:

- Use an encrypted filesystem or volume for Caddy's data directory.
- Or configure a secrets-manager storage module.

## Verification

A relying party verifying an RA-TLS certificate should:

### Deterministic path

1. Validate the certificate chain back to the trusted root CA.
2. Extract the attestation evidence from the backend-specific extension OID (e.g. `1.2.840.113741.1.5.5.1.6` for TDX).
3. Verify the evidence against the hardware vendor's attestation infrastructure.
4. Read the certificate's `NotBefore` field, format it as `"2006-01-02T15:04Z"` (UTC, minute precision).
5. Compute `SHA-512( SHA-256(DER public key) || formatted_time_string )` and confirm it matches the quote's `ReportData`.
6. Check the quote's measurement registers against expected values.

### Challenge-response path

1. Validate the certificate chain back to the trusted root CA.
2. Extract the attestation evidence from the backend-specific extension OID.
3. Verify the evidence against the hardware vendor's attestation infrastructure.
4. Compute `SHA-512( SHA-256(DER public key) || original_nonce )` using the nonce sent in the ClientHello.
5. Confirm the result matches the quote's `ReportData` — this proves freshness.
6. Check the quote's measurement registers against expected values.

## Adding a New Backend

1. Create `attester_<name>.go` implementing the `Attester` interface.
2. Register it in an `init()` function: `RegisterAttester("<name>", func() Attester { return new(MyAttester) })`
3. The new backend is immediately available via `backend <name>` in the Caddyfile.

## Third-Party Licenses & Acknowledgments

This project makes use of the following open source libraries:

- [Caddy v2](https://github.com/caddyserver/caddy) ([Apache 2.0 License](https://github.com/caddyserver/caddy/blob/master/LICENSE))
- [CertMagic](https://github.com/caddyserver/certmagic) ([Apache 2.0 License](https://github.com/caddyserver/certmagic/blob/master/LICENSE))
- [go-tdx-guest](https://github.com/google/go-tdx-guest) ([Apache 2.0 License](https://github.com/google/go-tdx-guest/blob/main/LICENSE))
- [Uber Zap](https://github.com/uber-go/zap) ([MIT License](https://github.com/uber-go/zap/blob/master/LICENSE.txt))

Please refer to each project for their respective license terms.

## License

This project is licensed under the [GNU Affero General Public License v3 (AGPL-3.0)](https://www.gnu.org/licenses/agpl-3.0.html).

![AGPLv3 License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)