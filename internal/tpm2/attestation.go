// Package tpm2 provides TPM 2.0 attestation using github.com/google/go-tpm
package tpm2

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"rootseal/pkg/api"
)

// Attestor handles TPM attestation operations on the client side
type Attestor struct {
	tpm       transport.TPMCloser
	akHandle  tpm2.TPMHandle
	akPublic  tpm2.TPM2BPublic
	akPrivate tpm2.TPM2BPrivate
	akName    tpm2.TPM2BName
	srkHandle tpm2.TPMHandle
}

// NewAttestor opens the TPM
func NewAttestor() (*Attestor, error) {
	t, err := OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}

	return &Attestor{tpm: t}, nil
}

// Close releases TPM resources
func (a *Attestor) Close() error {
	if a.akHandle != 0 {
		FlushContext(a.tpm, a.akHandle)
	}
	if a.srkHandle != 0 {
		FlushContext(a.tpm, a.srkHandle)
	}
	return a.tpm.Close()
}

// CreateAK creates a new Attestation Key under the SRK
func (a *Attestor) CreateAK() error {
	// Create SRK (Storage Root Key) as parent
	srkResp, err := CreatePrimary(a.tpm)
	if err != nil {
		return fmt.Errorf("failed to create SRK: %w", err)
	}
	a.srkHandle = srkResp.ObjectHandle

	// Get SRK public for session encryption
	srkPub, err := srkResp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to get SRK public: %w", err)
	}

	// Create AK under SRK - use RSA signing key template
	akTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			KeyBits: 2048,
		}),
	}

	createAK := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: a.srkHandle,
			Name:   srkResp.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Salted(a.srkHandle, *srkPub),
			),
		},
		InPublic: tpm2.New2B(akTemplate),
	}

	akCreateResp, err := createAK.Execute(a.tpm)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	// Load the AK
	loadAK := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: a.srkHandle,
			Name:   srkResp.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Salted(a.srkHandle, *srkPub),
			),
		},
		InPrivate: akCreateResp.OutPrivate,
		InPublic:  akCreateResp.OutPublic,
	}

	loadResp, err := loadAK.Execute(a.tpm)
	if err != nil {
		return fmt.Errorf("failed to load AK: %w", err)
	}

	a.akHandle = loadResp.ObjectHandle
	a.akPublic = akCreateResp.OutPublic
	a.akPrivate = akCreateResp.OutPrivate
	a.akName = loadResp.Name

	return nil
}

// LoadAK loads an existing Attestation Key from marshaled blob
func (a *Attestor) LoadAK(blob []byte) error {
	// Unmarshal the saved AK data
	akData, err := UnmarshalAKBlob(blob)
	if err != nil {
		return fmt.Errorf("failed to unmarshal AK blob: %w", err)
	}

	// Create SRK
	srkResp, err := CreatePrimary(a.tpm)
	if err != nil {
		return fmt.Errorf("failed to create SRK: %w", err)
	}
	a.srkHandle = srkResp.ObjectHandle

	srkPub, err := srkResp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to get SRK public: %w", err)
	}

	// Load the AK
	loadAK := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: a.srkHandle,
			Name:   srkResp.Name,
			Auth: tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.Salted(a.srkHandle, *srkPub),
			),
		},
		InPrivate: akData.Private,
		InPublic:  akData.Public,
	}

	loadResp, err := loadAK.Execute(a.tpm)
	if err != nil {
		return fmt.Errorf("failed to load AK: %w", err)
	}

	a.akHandle = loadResp.ObjectHandle
	a.akPublic = akData.Public
	a.akPrivate = akData.Private
	a.akName = loadResp.Name

	return nil
}

// MarshalAK returns the AK in a format that can be stored and reloaded
func (a *Attestor) MarshalAK() ([]byte, error) {
	if a.akHandle == 0 {
		return nil, fmt.Errorf("no AK loaded")
	}

	return MarshalAKBlob(a.akPrivate, a.akPublic), nil
}

// GetEnrollment returns TPM enrollment data for registration during postimaging
func (a *Attestor) GetEnrollment() (*api.TPMEnrollment, error) {
	if a.akHandle == 0 {
		return nil, fmt.Errorf("no AK loaded, call CreateAK first")
	}

	// Get AK public key bytes
	akPubBytes := tpm2.Marshal(a.akPublic)

	// Get AK name bytes
	akNameBytes := tpm2.Marshal(a.akName)

	return &api.TPMEnrollment{
		EkPublic: nil, // EK not needed for our attestation flow
		EkCert:   nil,
		AkPublic: akPubBytes,
		AkName:   akNameBytes,
	}, nil
}

// GenerateQuote creates a TPM quote over PCRs with the given nonce
func (a *Attestor) GenerateQuote(nonce []byte, pcrs []int) (*api.TPMQuote, error) {
	if a.akHandle == 0 {
		return nil, fmt.Errorf("no AK loaded")
	}

	// Create PCR selector
	pcrSelector, err := createPCRSelector(pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR selector: %w", err)
	}

	// Generate quote
	quote := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: a.akHandle,
			Name:   a.akName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		PCRSelect: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrSelector,
				},
			},
		},
	}

	quoteResp, err := quote.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quote: %w", err)
	}

	// Read PCR values
	pcrValues, err := ReadPCRs(a.tpm, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	// Convert PCR values to API format
	apiPCRs := make([]*api.PCRValue, 0, len(pcrValues))
	for idx, digest := range pcrValues {
		apiPCRs = append(apiPCRs, &api.PCRValue{
			Index:  int32(idx),
			Digest: digest,
		})
	}

	// Extract signature bytes
	sig, err := quoteResp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get signature: %w", err)
	}

	return &api.TPMQuote{
		Quote:     tpm2.Marshal(quoteResp.Quoted),
		Signature: sig.Sig.Buffer,
		Pcrs:      apiPCRs,
	}, nil
}

// GetAKPublic returns the AK public key bytes
func (a *Attestor) GetAKPublic() ([]byte, error) {
	if a.akHandle == 0 {
		return nil, fmt.Errorf("no AK loaded")
	}
	return tpm2.Marshal(a.akPublic), nil
}

// AKBlob holds the serialized AK data
type AKBlob struct {
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
}

// MarshalAKBlob serializes AK data for storage
func MarshalAKBlob(priv tpm2.TPM2BPrivate, pub tpm2.TPM2BPublic) []byte {
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

// UnmarshalAKBlob deserializes AK data
func UnmarshalAKBlob(blob []byte) (*AKBlob, error) {
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

	return &AKBlob{
		Private: *priv,
		Public:  *pub,
	}, nil
}

// ComputePCRDigest computes the digest of PCR values for quote verification
func ComputePCRDigest(pcrs map[int][]byte, pcrIndices []int) []byte {
	h := sha256.New()
	for _, idx := range pcrIndices {
		if digest, ok := pcrs[idx]; ok {
			h.Write(digest)
		}
	}
	return h.Sum(nil)
}
