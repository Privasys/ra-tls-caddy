# RA-TLS Issuer for Caddy

![AGPLv3 License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)

A Caddy `tls.issuance` module (`ra_tls`) that produces **RA-TLS certificates** for Confidential Computing.

## Extended certificate

This module will serve an x509 certificate extended with an attribute for the TEE quote. For exemple, for an Intel TDX Confidential VM:

<img width="581" height="624" alt="image" src="https://github.com/user-attachments/assets/28d83c19-b6f0-4f40-9f7d-895d31fe20ce" />

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

When a TLS client sends a **RA-TLS challenge** in its ClientHello (extension `0xffbb`):

1. **Ephemeral Key** — A fresh ECDSA P-256 key pair is generated.
2. **Attestation** — `ReportData = SHA-512( SHA-256(DER public key) || nonce )`, binding the quote to the client's challenge.
3. **Certificate** — A very short-lived (5 min) certificate is signed by the same CA, with the quote embedded.

This certificate is **not cached** — each challenge produces a unique response.

> **Note:** This branch requires the [Privasys/go fork](https://github.com/Privasys/go/tree/ratls) ([initial commit](https://github.com/Privasys/go/commit/1de8bde833631316999b14a67f1551c14e69206f)) which adds `ClientHelloInfo.RATLSChallenge` to `crypto/tls`, enabling challenge-response attestation. An upstream PR is open at [golang/go#77714](https://github.com/golang/go/pull/77714). The code references `hello.RATLSChallenge` directly and **will not compile with standard Go**.

## Requirements

- Linux host running inside a **Confidential VM**
- Backend-specific support:
  - `tdx` — Kernel configfs-tsm (`/sys/kernel/config/tsm/report`)
- An **intermediary CA** certificate and private key (private PKI)
- [Privasys/go fork](https://github.com/Privasys/go/tree/ratls) (`ratls` branch — [initial commit](https://github.com/Privasys/go/commit/1de8bde833631316999b14a67f1551c14e69206f)) and [xcaddy](https://github.com/caddyserver/xcaddy)

## Building

First, build the Go fork:

```bash
git clone -b ratls https://github.com/Privasys/go.git ~/go-ratls
cd ~/go-ratls/src && ./make.bash
export GOROOT=~/go-ratls
export PATH=$GOROOT/bin:$PATH
```

Then build Caddy with the RA-TLS module:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

git clone https://github.com/Privasys/ra-tls-caddy.git
cd ra-tls-caddy
xcaddy build --with github.com/Privasys/ra-tls-caddy=.
```

> **Note:** The `=.` suffix tells xcaddy to use the local directory as the module source. The import path before `=` must match the `module` directive in `go.mod`. If you are working from a fork, update `go.mod` accordingly.

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

## Inspecting the Certificate

Once Caddy is running, inspect the RA-TLS certificate with standard tools:

```bash
# Retrieve and display the full certificate
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -text
```

Look for the TDX quote in the X.509 extensions:

```
X509v3 extensions:
    ...
    1.2.840.113741.1.5.5.1.6:
        <hex dump of the TDX quote — ~8000 bytes of attestation evidence>
```

To save the certificate for programmatic verification:

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -outform PEM > ratls-cert.pem

openssl asn1parse -in ratls-cert.pem
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

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for details.

## License

This project is licensed under the [GNU Affero General Public License v3 (AGPL-3.0)](https://www.gnu.org/licenses/agpl-3.0.html).

You are free to use, modify, and distribute this software under the terms of the AGPL-3.0. Any modified versions or services built on this software that are accessible over a network **must** make the complete source code available under the same license.

### Commercial Licensing

For commercial, closed-source, or proprietary use that is not compatible with the AGPL-3.0, a separate **commercial license** is available.

Please contact **legal@privasys.org** for licensing enquiries.
