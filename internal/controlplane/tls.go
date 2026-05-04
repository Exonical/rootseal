package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

// TLSConfig holds the paths needed to configure mTLS for the gRPC server.
type TLSConfig struct {
	CertFile   string // Server certificate
	KeyFile    string // Server private key
	CAFile     string // CA certificate for verifying client certs
	ClientAuth bool   // Require and verify client certificates
}

// NewServerTransportCredentials loads mTLS credentials for the gRPC server.
// When clientAuth is true the server requires a valid client certificate
// signed by the CA in CAFile (mutual TLS).
func NewServerTransportCredentials(cfg TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(filepath.Clean(cfg.CAFile)) // #nosec G304 -- path from operator-controlled config
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.ClientCAs = caPool
	}

	if cfg.ClientAuth {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(tlsCfg), nil
}

// NewClientTransportCredentials loads mTLS credentials for a gRPC client.
func NewClientTransportCredentials(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	caPEM, err := os.ReadFile(filepath.Clean(caFile)) // #nosec G304 -- path from operator-controlled CLI flag
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsCfg), nil
}
