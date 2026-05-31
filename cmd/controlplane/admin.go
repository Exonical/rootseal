package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"rootseal/internal/controlplane"
)

// dbURLFromEnv returns the configured database URL or a clear error.
func dbURLFromEnv() string {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required for admin commands")
	}
	return dsn
}

// runMintEnrollmentToken generates a single-use, high-entropy enrollment token,
// stores only its SHA-256 hash, and prints the plaintext exactly once to stdout
// for out-of-band delivery to the host being provisioned. The plaintext is
// never logged or persisted.
func runMintEnrollmentToken(args []string) {
	fs := flag.NewFlagSet("mint-enrollment-token", flag.ExitOnError)
	boundCN := fs.String("cn", "", "Optional mTLS CN the token is bound to (recommended)")
	ttl := fs.Duration("ttl", time.Hour, "Token validity window (e.g. 15m, 1h)")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse args: %v", err)
	}

	db, err := controlplane.NewDB(dbURLFromEnv())
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// 256 bits of entropy, URL-safe and without padding.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.CreateEnrollmentToken(ctx, controlplane.HashEnrollmentToken(token), *boundCN, *ttl); err != nil {
		log.Fatalf("failed to store enrollment token: %v", err)
	}

	// Print to stdout only — this is the single delivery point for the plaintext.
	fmt.Println(token)
	fmt.Fprintf(os.Stderr, "enrollment token created (cn=%q, ttl=%s); deliver out-of-band, it is single-use\n", *boundCN, ttl.String())
}

// runRevokeHost marks a host (by hostname+serial) as revoked or active. A
// revoked host is refused at key release even with a valid certificate.
func runRevokeHost(args []string) {
	fs := flag.NewFlagSet("revoke-host", flag.ExitOnError)
	hostname := fs.String("hostname", "", "Hostname of the agent to revoke")
	serial := fs.String("serial", "", "Hardware serial of the agent to revoke")
	unrevoke := fs.Bool("unrevoke", false, "Re-activate a previously revoked host")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse args: %v", err)
	}
	if *hostname == "" || *serial == "" {
		log.Fatal("both -hostname and -serial are required")
	}

	db, err := controlplane.NewDB(dbURLFromEnv())
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.SetAgentRevoked(ctx, *hostname, *serial, !*unrevoke); err != nil {
		log.Fatalf("failed to update host revocation: %v", err)
	}

	state := "revoked"
	if *unrevoke {
		state = "active"
	}
	fmt.Printf("host %s (serial %s) is now %s\n", *hostname, *serial, state)
}
