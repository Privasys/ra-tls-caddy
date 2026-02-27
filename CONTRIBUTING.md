# Contributing to RA-TLS Caddy

Thank you for your interest in contributing! This project implements an RA-TLS certificate issuance module for [Caddy](https://caddyserver.com/) targeting Confidential Computing environments.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Build the [Privasys/go fork](https://github.com/Privasys/go/tree/ratls) (`ratls` branch — [initial commit](https://github.com/Privasys/go/commit/1de8bde833631316999b14a67f1551c14e69206f)):
   ```bash
   git clone -b ratls https://github.com/Privasys/go.git ~/go-ratls
   cd ~/go-ratls/src && ./make.bash
   export GOROOT=~/go-ratls
   export PATH=$GOROOT/bin:$PATH
   ```
3. Build with [xcaddy](https://github.com/caddyserver/xcaddy):
   ```bash
   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
   cd ra-tls-caddy
   xcaddy build --with github.com/Privasys/ra-tls-caddy=.
   ```

## Project Structure

| Path | Description |
|------|-------------|
| `ra-tls.go` | Core module — certificate issuance, caching, and challenge-response logic |
| `attester.go` | `Attester` interface and backend registry |
| `attester_tdx.go` | Intel TDX backend |
| `attester_sgx.go` | Intel SGX backend |

## Making Changes

- Follow the existing code style — use `gofmt` and keep imports organised.
- Keep commits focused: one logical change per commit.
- Write meaningful commit messages (e.g. `attester: add AMD SEV-SNP backend`).
- If adding a new attestation backend, implement the `Attester` interface in `attester_<name>.go` and register it via `init()`.

## Submitting a Pull Request

1. Create a feature branch from `main`:
   ```bash
   git checkout -b my-feature
   ```
2. Make your changes and commit.
3. Push to your fork and open a Pull Request against `main`.
4. Describe what you changed and why.

## Reporting Issues

If you find a bug or have a suggestion, please [open an issue](https://github.com/Privasys/ra-tls-caddy/issues). Include:

- A clear description of the problem or suggestion.
- Steps to reproduce (for bugs).
- The TEE backend and hardware platform you are using.

## License

By contributing, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).
