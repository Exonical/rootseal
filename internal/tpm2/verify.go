// Package tpm2 provides TPM 2.0 attestation using github.com/google/go-tpm
package tpm2

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"

	"rootseal/pkg/api"
)

// Verifier handles TPM attestation verification on the server side
type Verifier struct{}

// NewVerifier creates a new TPM verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyQuote verifies a TPM quote against the stored AK public key
func (v *Verifier) VerifyQuote(akPublicBytes []byte, nonce []byte, quote *api.TPMQuote) error {
	// Parse the AK public key from TPM format
	akPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](akPublicBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal AK public: %w", err)
	}

	// Get the public key contents
	pubContents, err := akPub.Contents()
	if err != nil {
		return fmt.Errorf("failed to get AK public contents: %w", err)
	}

	// Extract RSA public key
	rsaParams, err := pubContents.Parameters.RSADetail()
	if err != nil {
		return fmt.Errorf("failed to get RSA parameters: %w", err)
	}

	rsaUnique, err := pubContents.Unique.RSA()
	if err != nil {
		return fmt.Errorf("failed to get RSA unique: %w", err)
	}

	// Construct the RSA public key
	exponent := int(rsaParams.Exponent)
	if exponent == 0 {
		exponent = 65537 // Default RSA exponent
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaUnique.Buffer),
		E: exponent,
	}

	// Parse the quoted data
	quoted, err := tpm2.Unmarshal[tpm2.TPM2BAttest](quote.Quote)
	if err != nil {
		return fmt.Errorf("failed to unmarshal quoted data: %w", err)
	}

	attestContents, err := quoted.Contents()
	if err != nil {
		return fmt.Errorf("failed to get attest contents: %w", err)
	}

	// Verify the nonce matches
	if !bytes.Equal(attestContents.ExtraData.Buffer, nonce) {
		return fmt.Errorf("nonce mismatch in quote")
	}

	// Verify it's a quote attestation
	if attestContents.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("attestation is not a quote")
	}

	// Get quote info
	quoteInfo, err := attestContents.Attested.Quote()
	if err != nil {
		return fmt.Errorf("failed to get quote info: %w", err)
	}

	// Compute expected PCR digest from provided PCR values
	pcrMap := make(map[int][]byte)
	for _, pcr := range quote.Pcrs {
		pcrMap[int(pcr.Index)] = pcr.Digest
	}

	// Get PCR indices from the quote's PCR selection
	var pcrIndices []int
	for _, sel := range quoteInfo.PCRSelect.PCRSelections {
		for i, b := range sel.PCRSelect {
			for j := 0; j < 8; j++ {
				if b&(1<<j) != 0 {
					pcrIndices = append(pcrIndices, i*8+j)
				}
			}
		}
	}

	// Compute PCR digest
	expectedDigest := ComputePCRDigest(pcrMap, pcrIndices)

	// Verify PCR digest matches
	if !bytes.Equal(quoteInfo.PCRDigest.Buffer, expectedDigest) {
		return fmt.Errorf("PCR digest mismatch")
	}

	// Verify the signature
	// The TPM signs the TPMS_ATTEST structure (the buffer inside TPM2B_ATTEST)
	// Use Bytes() method to get the attestation data that was signed
	quotedHash := sha256.Sum256(quoted.Bytes())

	// Verify RSA signature
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, quotedHash[:], quote.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyEKCertificate verifies the EK certificate chain (optional)
func (v *Verifier) VerifyEKCertificate(ekCert []byte, trustedRoots *x509.CertPool) error {
	if len(ekCert) == 0 {
		return nil // No certificate to verify
	}

	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return fmt.Errorf("failed to parse EK certificate: %w", err)
	}

	if trustedRoots == nil {
		// No trusted roots configured, skip chain verification
		return nil
	}

	opts := x509.VerifyOptions{
		Roots: trustedRoots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("EK certificate verification failed: %w", err)
	}

	return nil
}
