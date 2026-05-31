package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"rootseal/pkg/api"
)

// akOptions controls the attributes of the synthetic AK public built for tests.
type akOptions struct {
	fixedTPM    bool
	fixedParent bool
	restricted  bool
	sign        bool
	decrypt     bool
}

func defaultAKOptions() akOptions {
	return akOptions{fixedTPM: true, fixedParent: true, restricted: true, sign: true, decrypt: false}
}

// buildAKPublic constructs a marshaled TPM2B_PUBLIC for an RSA AK whose modulus
// matches key, with the requested object attributes.
func buildAKPublic(t *testing.T, key *rsa.PrivateKey, opts akOptions) []byte {
	t.Helper()
	tmpl := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            opts.fixedTPM,
			FixedParent:         opts.fixedParent,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          opts.restricted,
			SignEncrypt:         opts.sign,
			Decrypt:             opts.decrypt,
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
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{
			Buffer: key.N.Bytes(),
		}),
	}
	pub := tpm2.New2B(tmpl)
	return tpm2.Marshal(pub)
}

// buildQuote constructs a TPM quote signed by key over the given nonce and PCR
// set. When magicOK is false the magic field is set to an invalid value.
func buildQuote(t *testing.T, key *rsa.PrivateKey, nonce []byte, pcrIndices []int, pcrDigests map[int][]byte, magicOK bool) *api.TPMQuote {
	t.Helper()

	mask, err := createPCRSelector(pcrIndices)
	if err != nil {
		t.Fatalf("createPCRSelector: %v", err)
	}

	pcrDigest := ComputePCRDigest(pcrDigests, pcrIndices)

	magic := tpm2.TPMGeneratedValue
	if !magicOK {
		magic = tpm2.TPMGenerated(0x11223344)
	}

	attest := tpm2.TPMSAttest{
		Magic:     magic,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{Hash: tpm2.TPMAlgSHA256, PCRSelect: mask},
				},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
		}),
	}

	attest2b := tpm2.New2B(attest)
	wire := tpm2.Marshal(attest2b)

	hashed := sha256.Sum256(attest2b.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	apiPCRs := make([]*api.PCRValue, 0, len(pcrDigests))
	for _, idx := range pcrIndices {
		apiPCRs = append(apiPCRs, &api.PCRValue{
			Index:  int32(idx),
			Digest: pcrDigests[idx],
		})
	}

	return &api.TPMQuote{Quote: wire, Signature: sig, Pcrs: apiPCRs}
}

func testNonce() []byte {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

func testPCRs() ([]int, map[int][]byte) {
	idx := []int{0, 7}
	digests := map[int][]byte{
		0: sha256.New().Sum([]byte("pcr0"))[:32],
		7: sha256.New().Sum([]byte("pcr7"))[:32],
	}
	// Normalize to exactly 32 bytes.
	for k, v := range digests {
		d := sha256.Sum256(v)
		digests[k] = d[:]
	}
	return idx, digests
}

func TestVerifyQuote_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	akPub := buildAKPublic(t, key, defaultAKOptions())
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err != nil {
		t.Fatalf("VerifyQuote: unexpected error: %v", err)
	}
}

func TestVerifyQuote_BadNonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPub := buildAKPublic(t, key, defaultAKOptions())
	idx, digests := testPCRs()
	q := buildQuote(t, key, testNonce(), idx, digests, true)

	v := NewVerifier()
	wrongNonce := make([]byte, 32) // all-zero, differs from testNonce
	if err := v.VerifyQuote(akPub, wrongNonce, q); err == nil {
		t.Fatal("VerifyQuote: expected nonce mismatch error, got nil")
	}
}

func TestVerifyQuote_EmptyNonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPub := buildAKPublic(t, key, defaultAKOptions())
	idx, digests := testPCRs()
	q := buildQuote(t, key, []byte{}, idx, digests, true)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, []byte{}, q); err == nil {
		t.Fatal("VerifyQuote: expected empty-nonce rejection, got nil")
	}
}

func TestVerifyQuote_WrongPCRDigest(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPub := buildAKPublic(t, key, defaultAKOptions())
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)

	// Tamper a reported PCR digest after signing; recomputed digest will differ.
	q.Pcrs[0].Digest = make([]byte, 32)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected PCR digest mismatch, got nil")
	}
}

func TestVerifyQuote_BadSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPub := buildAKPublic(t, key, defaultAKOptions())
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)
	q.Signature[0] ^= 0xff // corrupt signature

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected signature failure, got nil")
	}
}

func TestVerifyQuote_WrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	// AK public advertises `other`, but the quote is signed by `key`.
	akPub := buildAKPublic(t, other, defaultAKOptions())
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected verification failure with mismatched AK, got nil")
	}
}

func TestVerifyQuote_NonRestrictedAK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	opts := defaultAKOptions()
	opts.restricted = false // a non-restricted "AK" must be rejected
	akPub := buildAKPublic(t, key, opts)
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected rejection of non-restricted AK, got nil")
	}
}

func TestVerifyQuote_NonFixedTPMAK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	opts := defaultAKOptions()
	opts.fixedTPM = false // a software/duplicable key must be rejected
	akPub := buildAKPublic(t, key, opts)
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, true)

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected rejection of non-fixedTPM AK, got nil")
	}
}

func TestVerifyQuote_BadMagic(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	akPub := buildAKPublic(t, key, defaultAKOptions())
	nonce := testNonce()
	idx, digests := testPCRs()
	q := buildQuote(t, key, nonce, idx, digests, false) // invalid magic

	v := NewVerifier()
	if err := v.VerifyQuote(akPub, nonce, q); err == nil {
		t.Fatal("VerifyQuote: expected rejection of non-TPM_GENERATED magic, got nil")
	}
}
