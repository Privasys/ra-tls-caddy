// Package ratls implements a Caddy TLS issuance module ("ra_tls") that
// produces RA-TLS certificates for Confidential VMs.
//
// It generates ECDSA P-256 key pairs and issues X.509 certificates signed by a
// private-PKI intermediary CA. Each certificate embeds hardware attestation
// evidence (a quote/report) in a custom X.509 extension whose OID is
// determined by the selected backend.
//
// # Backends
//
// Hardware-specific logic is abstracted behind the Attester interface (see
// attester.go). The backend is selected via the "backend" configuration
// field. Currently supported:
//
//   - "tdx" -- Intel TDX via Linux configfs-tsm (attester_tdx.go)
//   - "sgx" -- Intel SGX via Gramine DCAP (attester_sgx.go)
//
// Planned:
//
//   - "sev-snp" -- AMD SEV-SNP
//
// # Report Data
//
// The quote's 64-byte ReportData field is:
//
// SHA-512( SHA-256(DER public key) || creation_time )
//
// where creation_time is the certificate's NotBefore value truncated to
// 1-minute precision, formatted as the UTC string "2006-01-02T15:04Z".
// This allows a verifier to reproduce the ReportData from the certificate
// alone: read the public key and NotBefore, apply the same formula, and
// compare against the quote.
//
// # Trust Model
//
// Certificates are signed by a user-provided intermediary CA (private PKI).
// The attestation evidence embedded in the certificate provides hardware-
// rooted proof that the public key was generated inside a genuine Confidential
// VM. A relying party should:
//
//  1. Validate the certificate chain back to the trusted root CA.
//  2. Extract and verify the attestation evidence against the hardware
//     vendor's attestation infrastructure.
//  3. Recompute SHA-512(SHA-256(pub key) || NotBefore as "2006-01-02T15:04Z")
//     and confirm it matches the quote's ReportData.
//
// # Attestation Paths
//
// The module supports two attestation modes:
//
//   - Deterministic (Issue path): ReportData = SHA-512(SHA-256(pubkey) || time).
//     Certificates are cached and auto-renewed by certmagic. A verifier
//     reproduces the ReportData from the certificate's public key and NotBefore.
//
//   - Challenge-Response (GetCertificate path): When the client's TLS
//     ClientHello contains a RATS-TLS nonce extension (per
//     draft-ietf-rats-tls-attestation), a fresh ephemeral certificate is
//     generated with ReportData = SHA-512(SHA-256(pubkey) || nonce). This
//     certificate is not cached. Requires a TLS implementation that exposes
//     raw ClientHello extensions (see extractRATSNonce).
//
// # Private Key Sensitivity
//
// The ECDSA private key is generated inside the TEE and protected by hardware
// memory encryption. It should be treated as highly sensitive:
//
//   - It is held in an in-memory sync.Map only between GenerateKey and Issue,
//     then immediately deleted from the map after use.
//   - certmagic will still PEM-encode and persist the key via its Storage backend.
//     To avoid writing it to unencrypted disk, configure Caddy with an encrypted
//     or in-memory storage backend.
//
// # Caddyfile Example
//
//	example.com {
//	   tls {
//	       issuer ra_tls {
//	           backend tdx
//	           ca_cert /path/to/intermediate-ca.crt
//	           ca_key  /path/to/intermediate-ca.key
//	       }
//	   }
//	   respond "Hello from a Confidential VM!"
//	}
//
// # Build
//
//	xcaddy build --with github.com/Privasys/caddy-ra-tls-module=.
package ratls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RATLSIssuer{})
}

// reportTimeFormat is the deterministic format used when encoding the
// certificate creation time into the ReportData hash. It yields minute-
// precision UTC strings like "2026-02-18T14:30Z", which a verifier can
// reproduce from the certificate's NotBefore field.
const reportTimeFormat = "2006-01-02T15:04Z"

// RATLSIssuer is a Caddy TLS issuance module that produces RA-TLS
// certificates for Confidential VMs.
//
// It implements:
//   - certmagic.KeyGenerator -- generates ECDSA P-256 key pairs.
//   - certmagic.Issuer       -- issues CA-signed certificates with embedded attestation evidence.
//   - certmagic.Manager      -- serves challenge-response certs for RATS-TLS clients.
//   - caddy.Provisioner      -- verifies hardware availability and loads the CA.
//   - caddyfile.Unmarshaler  -- parses the "ra_tls" Caddyfile directive.
type RATLSIssuer struct {
	// Backend selects the confidential computing hardware backend.
	// Supported values: "tdx". Planned: "sev-snp", "sgx".
	Backend string `json:"backend"`

	// CACertPath is the path to the PEM-encoded intermediary CA certificate
	// used to sign issued RA-TLS certificates.
	CACertPath string `json:"ca_cert_path"`

	// CAKeyPath is the path to the PEM-encoded private key of the
	// intermediary CA.
	CAKeyPath string `json:"ca_key_path"`

	// attester is the hardware-specific attestation provider, created from
	// the Backend configuration during Provision.
	attester Attester

	// caCert is the parsed intermediary CA certificate.
	caCert *x509.Certificate

	// caKey is the parsed intermediary CA private key.
	caKey crypto.Signer

	logger *zap.Logger

	// keys temporarily holds private keys between GenerateKey and Issue,
	// indexed by the SHA-512 fingerprint of their DER-encoded PKIX public
	// key. Keys are removed (LoadAndDelete) as soon as Issue consumes them.
	keys sync.Map
}

// ---------------------------------------------------------------------------
// caddy.Module
// ---------------------------------------------------------------------------

// CaddyModule returns the Caddy module information.
func (RATLSIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.ra_tls",
		New: func() caddy.Module { return new(RATLSIssuer) },
	}
}

// ---------------------------------------------------------------------------
// caddy.Provisioner
// ---------------------------------------------------------------------------

// Provision validates configuration, loads the intermediary CA, and
// initialises the hardware-specific attestation backend.
func (iss *RATLSIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger()

	// -- Validate configuration --------------------------------
	if iss.Backend == "" {
		return fmt.Errorf("ra_tls: backend is required")
	}
	if iss.CACertPath == "" {
		return fmt.Errorf("ra_tls: ca_cert_path is required")
	}
	if iss.CAKeyPath == "" {
		return fmt.Errorf("ra_tls: ca_key_path is required")
	}

	// -- Load intermediary CA certificate ----------------------
	caCertPEM, err := os.ReadFile(iss.CACertPath)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to read CA certificate from %q: %w", iss.CACertPath, err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("ra_tls: no PEM block found in CA certificate file %q", iss.CACertPath)
	}
	iss.caCert, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to parse CA certificate: %w", err)
	}
	if !iss.caCert.IsCA {
		return fmt.Errorf("ra_tls: certificate in %q is not a CA certificate (BasicConstraints.IsCA=false)", iss.CACertPath)
	}

	// -- Load intermediary CA private key ----------------------
	caKeyPEM, err := os.ReadFile(iss.CAKeyPath)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to read CA key from %q: %w", iss.CAKeyPath, err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("ra_tls: no PEM block found in CA key file %q", iss.CAKeyPath)
	}
	caKeyRaw, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		// Fall back to SEC 1 (EC) or PKCS#1 (RSA) formats.
		caKeyRaw, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("ra_tls: failed to parse CA private key (tried PKCS#8 and SEC1): %w", err)
		}
	}
	var ok bool
	iss.caKey, ok = caKeyRaw.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ra_tls: CA private key type %T does not implement crypto.Signer", caKeyRaw)
	}

	iss.logger.Info("intermediary CA loaded",
		zap.String("ca_cert", iss.CACertPath),
		zap.String("ca_subject", iss.caCert.Subject.String()))

	// -- Initialise the attestation backend --------------------
	attester, err := newAttester(iss.Backend)
	if err != nil {
		return fmt.Errorf("ra_tls: %w", err)
	}
	if err := attester.Provision(iss.logger); err != nil {
		return fmt.Errorf("ra_tls[%s]: %w", iss.Backend, err)
	}
	iss.attester = attester

	iss.logger.Info("RA-TLS issuer provisioned successfully",
		zap.String("backend", iss.Backend))
	return nil
}

// ---------------------------------------------------------------------------
// certmagic.KeyGenerator
// ---------------------------------------------------------------------------

// GenerateKey generates an ECDSA P-256 key pair and stores it temporarily so
// that the subsequent call to Issue can retrieve it for signing by the
// intermediary CA.
//
// The returned crypto.PrivateKey is an *ecdsa.PrivateKey (which also
// implements crypto.Signer). Because the key is generated inside a TEE, it
// should be treated as sensitive -- configure an encrypted or in-memory
// storage backend in Caddy to avoid persisting it in plaintext.
func (iss *RATLSIssuer) GenerateKey() (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: ECDSA P-256 key generation failed: %w", err)
	}

	fp, err := pubKeyFingerprint(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: public key fingerprinting failed: %w", err)
	}
	iss.keys.Store(fp, key)

	iss.logger.Debug("generated ECDSA P-256 key pair (TEE-sensitive)")
	return key, nil
}

// ---------------------------------------------------------------------------
// certmagic.Issuer
// ---------------------------------------------------------------------------

// Issue creates a CA-signed X.509 certificate with embedded attestation
// evidence from the configured hardware backend.
//
// Steps performed:
//  1. Validate the CSR signature.
//  2. Determine the creation time (NotBefore), truncated to 1-minute precision.
//  3. Compute ReportData = SHA-512( SHA-256(DER public key) || creation_time ).
//  4. Request attestation evidence from the backend with the ReportData.
//  5. Build a certificate template carrying the evidence in a backend-
//     specific extension and sign it with the intermediary CA key.
func (iss *RATLSIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	// -- 1. Validate CSR --------------------------------------
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ra_tls: CSR signature verification failed: %w", err)
	}

	// -- 2. Creation time, truncated to the minute -------------
	creationTime := time.Now().UTC().Truncate(time.Minute)
	creationTimeStr := creationTime.Format(reportTimeFormat)

	// -- 3. ReportData = SHA-512( SHA-256(pubkey) || creation_time )
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: failed to marshal CSR public key: %w", err)
	}
	reportData := computeReportData(pubKeyDER, []byte(creationTimeStr))

	// -- 4. Generate attestation evidence ---------------------
	rawQuote, err := iss.attester.Quote(reportData)
	if err != nil {
		return nil, fmt.Errorf("ra_tls[%s]: %w", iss.attester.Name(), err)
	}
	iss.logger.Info("attestation evidence generated",
		zap.String("backend", iss.attester.Name()),
		zap.Int("quote_bytes", len(rawQuote)),
		zap.String("creation_time", creationTimeStr),
		zap.String("report_data_algo", "SHA-512(SHA-256(pubkey) || time)"))

	// -- 5. Retrieve the private key from our ephemeral store -
	ecPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ra_tls: expected ECDSA public key in CSR, got %T", csr.PublicKey)
	}
	fp, err := pubKeyFingerprint(ecPub)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: failed to fingerprint CSR public key: %w", err)
	}
	keyVal, loaded := iss.keys.LoadAndDelete(fp)
	if !loaded {
		return nil, fmt.Errorf("ra_tls: no private key found for CSR public key; " +
			"ensure this issuer's GenerateKey is used as the key source")
	}
	_ = keyVal.(*ecdsa.PrivateKey) // type-assert to ensure correctness

	// -- 6. Build the X.509 certificate -----------------------
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ra_tls: serial number generation failed: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		EmailAddresses: csr.EmailAddresses,

		NotBefore: creationTime,
		NotAfter:  creationTime.Add(24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,

		ExtraExtensions: []pkix.Extension{
			iss.attester.CertExtension(rawQuote),
		},
	}

	// -- 7. Sign with the intermediary CA and encode the PEM chain
	certDER, err := iss.signCertificate(template, csr.PublicKey)
	if err != nil {
		return nil, err
	}
	chainPEM := iss.encodeChainPEM(certDER)

	iss.logger.Info("RA-TLS certificate issued (CA-signed)",
		zap.String("backend", iss.attester.Name()),
		zap.Strings("dns_names", csr.DNSNames),
		zap.String("ca_subject", iss.caCert.Subject.String()),
		zap.String("not_before", creationTimeStr),
		zap.Time("not_after", template.NotAfter))

	return &certmagic.IssuedCertificate{
		Certificate: chainPEM,
		Metadata: map[string]any{
			"issuer":        "ra_tls",
			"backend":       iss.attester.Name(),
			"quote_size":    len(rawQuote),
			"creation_time": creationTimeStr,
		},
	}, nil
}

// IssuerKey returns a string that uniquely identifies this issuer
// configuration, used by certmagic to namespace stored certificates.
func (iss *RATLSIssuer) IssuerKey() string {
	if iss.Backend != "" {
		return "ra_tls_" + iss.Backend
	}
	return "ra_tls"
}

// ---------------------------------------------------------------------------
// certmagic.Manager -- challenge-response attestation
// ---------------------------------------------------------------------------

// GetCertificate implements certmagic.Manager. It inspects the TLS
// ClientHello for a RATS-TLS attestation nonce. If present, it generates
// a fresh ephemeral certificate with attestation evidence bound to the
// client's nonce -- providing interactive, challenge-response attestation.
//
// If no RATS-TLS nonce is found in the ClientHello, it returns (nil, nil)
// to let certmagic serve a pre-issued certificate from the Issue() path.
func (iss *RATLSIssuer) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	nonce, found := extractRATSNonce(hello)
	if !found {
		return nil, nil
	}

	if nonce == nil {
		iss.logger.Warn("RATS-TLS extension detected in ClientHello but nonce payload "+
			"is unavailable (Go crypto/tls only exposes extension IDs); "+
			"falling back to deterministic certificate",
			zap.String("server_name", hello.ServerName))
		return nil, nil
	}

	iss.logger.Info("RATS-TLS nonce detected in ClientHello, generating challenge-response certificate",
		zap.String("server_name", hello.ServerName),
		zap.Int("nonce_bytes", len(nonce)))

	// -- Generate ephemeral ECDSA P-256 key pair --------------
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: ephemeral key generation failed: %w", err)
	}

	// -- ReportData = SHA-512( SHA-256(pubkey) || nonce ) ------
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: failed to marshal ephemeral public key: %w", err)
	}
	reportData := computeReportData(pubKeyDER, nonce)

	// -- Generate attestation evidence ------------------------
	rawQuote, err := iss.attester.Quote(reportData)
	if err != nil {
		return nil, fmt.Errorf("ra_tls[%s]: %w", iss.attester.Name(), err)
	}

	// -- Build certificate template ---------------------------
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ra_tls: serial number generation failed: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hello.ServerName,
		},
		DNSNames:  []string{hello.ServerName},
		NotBefore: now,
		NotAfter:  now.Add(5 * time.Minute),

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,

		ExtraExtensions: []pkix.Extension{
			iss.attester.CertExtension(rawQuote),
		},
	}

	// -- Sign with the intermediary CA ------------------------
	certDER, err := iss.signCertificate(template, &privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	chainPEM := iss.encodeChainPEM(certDER)

	// -- Build tls.Certificate --------------------------------
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: failed to marshal ephemeral private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: failed to build TLS certificate: %w", err)
	}

	iss.logger.Info("RATS-TLS challenge-response certificate generated",
		zap.String("backend", iss.attester.Name()),
		zap.String("server_name", hello.ServerName),
		zap.Int("quote_bytes", len(rawQuote)))

	return &tlsCert, nil
}

// ---------------------------------------------------------------------------
// caddyfile.Unmarshaler
// ---------------------------------------------------------------------------

// UnmarshalCaddyfile parses the "ra_tls" issuer directive:
//
//	tls {
//	   issuer ra_tls {
//	       backend  tdx
//	       ca_cert  /path/to/intermediate-ca.crt
//	       ca_key   /path/to/intermediate-ca.key
//	   }
//	}
func (iss *RATLSIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name "ra_tls"
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "backend":
			if !d.NextArg() {
				return d.ArgErr()
			}
			iss.Backend = d.Val()
		case "ca_cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			iss.CACertPath = d.Val()
		case "ca_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			iss.CAKeyPath = d.Val()
		default:
			return d.Errf("unrecognised sub-directive: %s", d.Val())
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// computeReportData produces the 64-byte ReportData used in attestation
// quotes. It computes SHA-512( SHA-256(pubKeyDER) || binding ), where
// binding is either a time string (deterministic path) or a client nonce
// (challenge-response path).
func computeReportData(pubKeyDER []byte, binding []byte) [64]byte {
	pubKeyHash := sha256.Sum256(pubKeyDER)
	var input []byte
	input = append(input, pubKeyHash[:]...)
	input = append(input, binding...)
	return sha512.Sum512(input)
}

// signCertificate signs the given certificate template with the intermediary
// CA and returns the DER-encoded leaf certificate.
func (iss *RATLSIssuer) signCertificate(template *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, iss.caCert, pub, iss.caKey)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: CA-signed certificate creation failed: %w", err)
	}
	return certDER, nil
}

// encodeChainPEM encodes the leaf certificate (DER) and the intermediary CA
// certificate into a PEM bundle (leaf first, then CA).
func (iss *RATLSIssuer) encodeChainPEM(leafDER []byte) []byte {
	var chain []byte
	chain = append(chain, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafDER,
	})...)
	chain = append(chain, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: iss.caCert.Raw,
	})...)
	return chain
}

// ratsEvidenceRequestExtType is the TLS extension type for the RATS-TLS
// evidence_request extension defined in draft-ietf-rats-tls-attestation.
// Replace with the IANA-assigned value once allocated.
const ratsEvidenceRequestExtType uint16 = 0xFF01 // TODO: replace with IANA assignment

// extractRATSNonce inspects the ClientHello for a RATS-TLS attestation
// nonce extension (per draft-ietf-rats-tls-attestation).
//
// Go 1.25's tls.ClientHelloInfo.Extensions field lists the extension type
// IDs present in the ClientHello, so we can detect whether the RATS-TLS
// extension was sent. However, it does NOT expose the raw extension
// payloads -- only the IDs. Therefore we can tell *that* the client
// requested attestation, but cannot read the nonce value.
//
// To fully enable challenge-response attestation, either:
//   - Intercept the raw ClientHello bytes at the network layer (e.g. via
//     a custom net.Listener that tees the first flight), or
//   - Wait for Go to add raw extension data to tls.ClientHelloInfo, or
//   - Use a TLS library that exposes raw extensions.
func extractRATSNonce(hello *tls.ClientHelloInfo) (nonce []byte, found bool) {
	for _, ext := range hello.Extensions {
		if ext == ratsEvidenceRequestExtType {
			// The extension ID is present, but we cannot read its payload
			// from tls.ClientHelloInfo. Return found=true with a nil nonce
			// to signal the caller that challenge-response was requested
			// but data extraction is not yet implemented.
			//
			// TODO: Once raw extension data is available, parse the nonce
			// from the evidence_request extension payload here.
			return nil, true
		}
	}
	return nil, false
}

// pubKeyFingerprint returns a deterministic fingerprint string derived from
// the SHA-512 hash of the DER-encoded PKIX representation of pub. It is used
// to correlate keys between GenerateKey and Issue.
func pubKeyFingerprint(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha512.Sum512(der)
	return string(h[:]), nil
}

// ---------------------------------------------------------------------------
// Interface guards -- these are compile-time assertions.
// ---------------------------------------------------------------------------

var (
	_ caddy.Module           = (*RATLSIssuer)(nil)
	_ caddy.Provisioner      = (*RATLSIssuer)(nil)
	_ certmagic.Issuer       = (*RATLSIssuer)(nil)
	_ certmagic.KeyGenerator = (*RATLSIssuer)(nil)
	_ certmagic.Manager      = (*RATLSIssuer)(nil)
	_ caddyfile.Unmarshaler  = (*RATLSIssuer)(nil)
)
