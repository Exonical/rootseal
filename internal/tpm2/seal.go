// Package tpm2 provides TPM 2.0 sealing operations
package tpm2

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SealedBlob holds TPM-sealed data
type SealedBlob struct {
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
}

// Seal encrypts data using the TPM, binding it to current PCR values
func (a *Attestor) Seal(data []byte, pcrs []int) ([]byte, error) {
	if a.srkHandle == 0 {
		// Create SRK if not already created
		srkResp, err := CreatePrimary(a.tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to create SRK: %w", err)
		}
		a.srkHandle = srkResp.ObjectHandle
	}

	// Get SRK public for session
	srkPub, err := tpm2.ReadPublic{ObjectHandle: a.srkHandle}.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read SRK public: %w", err)
	}

	srkPubContents, err := srkPub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK public contents: %w", err)
	}

	// Create PCR policy if PCRs specified
	var policyDigest []byte
	if len(pcrs) > 0 {
		policyDigest, err = ComputePolicyDigest(a.tpm, pcrs)
		if err != nil {
			return nil, fmt.Errorf("failed to compute policy digest: %w", err)
		}
	}

	// Create sealed object template
	sealTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: len(pcrs) == 0, // Only allow auth if no PCR policy
		},
	}

	if len(policyDigest) > 0 {
		sealTemplate.AuthPolicy = tpm2.TPM2BDigest{Buffer: policyDigest}
	}

	// Create the sealed object
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: a.srkHandle,
			Name:   srkPub.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Salted(a.srkHandle, *srkPubContents),
			),
		},
		InPublic: tpm2.New2B(sealTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
	}

	createResp, err := createCmd.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create sealed object: %w", err)
	}

	// Marshal the sealed blob
	return MarshalSealedBlob(createResp.OutPrivate, createResp.OutPublic), nil
}

// Unseal decrypts TPM-sealed data
func (a *Attestor) Unseal(sealedData []byte, pcrs []int) ([]byte, error) {
	if a.srkHandle == 0 {
		// Create SRK if not already created
		srkResp, err := CreatePrimary(a.tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to create SRK: %w", err)
		}
		a.srkHandle = srkResp.ObjectHandle
	}

	// Unmarshal the sealed blob
	sealed, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed blob: %w", err)
	}

	// Get SRK public for session
	srkPub, err := tpm2.ReadPublic{ObjectHandle: a.srkHandle}.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read SRK public: %w", err)
	}

	srkPubContents, err := srkPub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK public contents: %w", err)
	}

	// Load the sealed object
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: a.srkHandle,
			Name:   srkPub.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Salted(a.srkHandle, *srkPubContents),
			),
		},
		InPrivate: sealed.Private,
		InPublic:  sealed.Public,
	}

	loadResp, err := loadCmd.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %w", err)
	}
	defer func() { _ = FlushContext(a.tpm, loadResp.ObjectHandle) }()

	// Create policy session if PCRs specified
	var auth tpm2.Session
	if len(pcrs) > 0 {
		sess, cleanup, err := tpm2.PolicySession(a.tpm, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to create policy session: %w", err)
		}
		defer func() { _ = cleanup() }()

		// Satisfy PCR policy
		pcrSelector, err := createPCRSelector(pcrs)
		if err != nil {
			return nil, fmt.Errorf("failed to create PCR selector: %w", err)
		}

		pcrPolicy := tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: pcrSelector,
					},
				},
			},
		}

		if _, err := pcrPolicy.Execute(a.tpm); err != nil {
			return nil, fmt.Errorf("failed to satisfy PCR policy: %w", err)
		}

		auth = sess
	} else {
		auth = tpm2.PasswordAuth(nil)
	}

	// Unseal the data
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   auth,
		},
	}

	unsealResp, err := unsealCmd.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data: %w", err)
	}

	return unsealResp.OutData.Buffer, nil
}

// MarshalSealedBlob serializes sealed data for storage
func MarshalSealedBlob(priv tpm2.TPM2BPrivate, pub tpm2.TPM2BPublic) []byte {
	privBytes := tpm2.Marshal(priv)
	pubBytes := tpm2.Marshal(pub)

	// Simple format: 4 bytes length + private + public
	result := make([]byte, 4+len(privBytes)+len(pubBytes))
	result[0] = byte(len(privBytes) >> 24)
	result[1] = byte(len(privBytes) >> 16)
	result[2] = byte(len(privBytes) >> 8)
	result[3] = byte(len(privBytes))
	copy(result[4:], privBytes)
	copy(result[4+len(privBytes):], pubBytes)

	return result
}

// UnmarshalSealedBlob deserializes sealed data
func UnmarshalSealedBlob(blob []byte) (*SealedBlob, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob too short")
	}

	privLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if len(blob) < 4+privLen {
		return nil, fmt.Errorf("blob too short for private key")
	}

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob[4 : 4+privLen])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private: %w", err)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob[4+privLen:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public: %w", err)
	}

	return &SealedBlob{
		Private: *priv,
		Public:  *pub,
	}, nil
}

// ComputePolicyDigest computes the policy digest for PCR-bound sealing
func ComputePolicyDigest(tpm transport.TPMCloser, pcrs []int) ([]byte, error) {
	// Start a trial policy session
	sess, cleanup, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("failed to create trial session: %w", err)
	}
	defer func() { _ = cleanup() }()

	// Add PCR policy
	pcrSelector, err := createPCRSelector(pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR selector: %w", err)
	}

	pcrPolicy := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrSelector,
				},
			},
		},
	}

	if _, err := pcrPolicy.Execute(tpm); err != nil {
		return nil, fmt.Errorf("failed to execute PCR policy: %w", err)
	}

	// Get the policy digest
	getDigest := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}
	digestResp, err := getDigest.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy digest: %w", err)
	}

	return digestResp.PolicyDigest.Buffer, nil
}
