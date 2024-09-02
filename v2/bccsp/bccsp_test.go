/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"fmt"
	"io/ioutil"

	bccsp "github.com/IBM/idemix/bccsp/types"
	idemix "github.com/IBM/idemix/v2/bccsp"
	"github.com/IBM/idemix/v2/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
)

// NewDummyKeyStore instantiate a dummy key store
// that neither loads nor stores keys
func NewDummyKeyStore() bccsp.KeyStore {
	return &dummyKeyStore{}
}

// dummyKeyStore is a read-only KeyStore that neither loads nor stores keys.
type dummyKeyStore struct {
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *dummyKeyStore) ReadOnly() bool {
	return true
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *dummyKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	return nil, errors.New("Key not found. This is a dummy KeyStore")
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *dummyKeyStore) StoreKey(k bccsp.Key) error {
	return errors.New("Cannot store key. This is a dummy read-only KeyStore")
}

var _ = Describe("Idemix Bridge", func() {
	testWithCurve(math.FP256BN_AMCL, &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]})
	testWithCurve(math.BN254, &amcl.Gurvy{C: math.Curves[math.BN254]})
	testWithCurve(math.FP256BN_AMCL_MIRACL, &amcl.Fp256bnMiracl{C: math.Curves[math.FP256BN_AMCL_MIRACL]})
	testWithCurve(math.BLS12_381, &amcl.Gurvy{C: math.Curves[math.BLS12_381]})
	testWithCurve(math.BLS12_377_GURVY, &amcl.Gurvy{C: math.Curves[math.BLS12_377_GURVY]})
	testWithCurve(math.BLS12_381_GURVY, &amcl.Gurvy{C: math.Curves[math.BLS12_381_GURVY]})
})

func curveName(id math.CurveID) string {
	switch id {
	case math.FP256BN_AMCL:
		return "FP256BN_AMCL"
	case math.BN254:
		return "BN254"
	case math.FP256BN_AMCL_MIRACL:
		return "FP256BN_AMCL_MIRACL"
	case math.BLS12_381:
		return "BLS12_381"
	case math.BLS12_377_GURVY:
		return "BLS12_377_GURVY"
	case math.BLS12_381_GURVY:
		return "BLS12_381_GURVY"
	default:
		panic(fmt.Sprintf("unknown curve %d", id))
	}
}

var _ = Describe("aries test", func() {
	testAries()
})

var _ = Describe("Idemix Bridge Compatibility", func() {

	Describe("setting up the environment with one issuer and one user", func() {
		var (
			CSP             bccsp.BCCSP
			IssuerKey       bccsp.Key
			IssuerPublicKey bccsp.Key
			AttributeNames  []string

			UserKey bccsp.Key
			// NymKey       bccsp.Key
			NymPublicKey bccsp.Key

			IssuerNonce []byte
			credRequest []byte

			credential []byte

			RevocationKey       bccsp.Key
			RevocationPublicKey bccsp.Key
			cri                 []byte
		)

		BeforeEach(func() {
			curve := math.Curves[math.FP256BN_AMCL]
			translator := &amcl.Fp256bn{C: curve}

			var err error
			CSP, err = idemix.New(NewDummyKeyStore(), curve, translator, true)
			Expect(err).NotTo(HaveOccurred())

			// Issuer
			AttributeNames = []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
			raw, err := ioutil.ReadFile("./testdata/old/issuerkey.sk")
			Expect(err).NotTo(HaveOccurred())
			IssuerKey, err = CSP.KeyImport(raw, &bccsp.IdemixIssuerKeyImportOpts{Temporary: true, AttributeNames: AttributeNames})
			Expect(err).NotTo(HaveOccurred())
			IssuerPublicKey, err = IssuerKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// User
			raw, err = ioutil.ReadFile("./testdata/old/userkey.sk")
			Expect(err).NotTo(HaveOccurred())
			UserKey, err = CSP.KeyImport(raw, &bccsp.IdemixUserSecretKeyImportOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())

			// User Nym Key
			// rawNymKeySk, err := ioutil.ReadFile("./testdata/old/nymkey.sk")
			// Expect(err).NotTo(HaveOccurred())
			rawNymKeyPk, err := ioutil.ReadFile("./testdata/old/nymkey.pk")
			Expect(err).NotTo(HaveOccurred())

			// NymKey, err = CSP.KeyImport(append(rawNymKeySk, rawNymKeyPk...), &bccsp.IdemixNymKeyImportOpts{Temporary: true})
			// Expect(err).NotTo(HaveOccurred())
			NymPublicKey, err = CSP.KeyImport(rawNymKeyPk, &bccsp.IdemixNymPublicKeyImportOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())

			// IssuerNonce = make([]byte, 32)
			// n, err := rand.Read(IssuerNonce)
			// Expect(n).To(BeEquivalentTo(32))
			// Expect(err).NotTo(HaveOccurred())
			IssuerNonce, err = ioutil.ReadFile("./testdata/old/issuer_nonce")
			Expect(err).NotTo(HaveOccurred())

			// Credential Request for User
			credRequest, err = ioutil.ReadFile("./testdata/old/cred_request.sign")
			Expect(err).NotTo(HaveOccurred())
			// credRequest, err = CSP.Sign(
			//	UserKey,
			//	nil,
			//	&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
			// )
			// Expect(err).NotTo(HaveOccurred())

			// Credential
			// credential, err = CSP.Sign(
			//	IssuerKey,
			//	credRequest,
			//	&bccsp.IdemixCredentialSignerOpts{
			//		Attributes: []bccsp.IdemixAttribute{
			//			{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
			//			{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
			//			{Type: bccsp.IdemixIntAttribute, Value: 1},
			//			{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
			//			{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2, 3}},
			//		},
			//	},
			// )
			// Expect(err).NotTo(HaveOccurred())
			credential, err = ioutil.ReadFile("./testdata/old/credential.sign")
			Expect(err).NotTo(HaveOccurred())

			// Revocation
			raw, err = ioutil.ReadFile("./testdata/old/revocation.sk")
			Expect(err).NotTo(HaveOccurred())
			RevocationKey, err = CSP.KeyImport(raw, &bccsp.IdemixRevocationKeyImportOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())
			RevocationPublicKey, err = RevocationKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// CRI
			// cri, err = CSP.Sign(
			//	RevocationKey,
			//	nil,
			//	&bccsp.IdemixCRISignerOpts{},
			// )
			// Expect(err).NotTo(HaveOccurred())
			cri, err = ioutil.ReadFile("./testdata/old/cri.sign")
			Expect(err).NotTo(HaveOccurred())
		})

		It("the environment is properly set", func() {
			// Verify CredRequest
			valid, err := CSP.Verify(
				IssuerPublicKey,
				credRequest,
				nil,
				&bccsp.IdemixCredentialRequestSignerOpts{IssuerNonce: IssuerNonce},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// Verify Credential
			valid, err = CSP.Verify(
				UserKey,
				credential,
				nil,
				&bccsp.IdemixCredentialSignerOpts{
					IssuerPK: IssuerPublicKey,
					Attributes: []bccsp.IdemixAttribute{
						{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
						{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1}},
						{Type: bccsp.IdemixIntAttribute, Value: 1},
						{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
						{Type: bccsp.IdemixBytesAttribute, Value: []byte{0, 1, 2, 3}},
					},
				},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// Verify CRI
			valid, err = CSP.Verify(
				RevocationPublicKey,
				cri,
				nil,
				&bccsp.IdemixCRISignerOpts{},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())
		})

		Describe("producing an idemix signature with no disclosed attribute", func() {
			var (
				digest    []byte
				signature []byte
			)

			BeforeEach(func() {
				var err error

				digest = []byte("a digest")

				// signature, err = CSP.Sign(
				//	UserKey,
				//	digest,
				//	&bccsp.IdemixSignerOpts{
				//		Credential: credential,
				//		Nym:        NymKey,
				//		IssuerPK:   IssuerPublicKey,
				//		Attributes: []bccsp.IdemixAttribute{
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//		},
				//		RhIndex: 4,
				//		Epoch:   0,
				//		CRI:     cri,
				//	},
				// )
				// Expect(err).NotTo(HaveOccurred())
				signature, err = ioutil.ReadFile("./testdata/old/signature_no_disclosed_attribute.sign")
				Expect(err).NotTo(HaveOccurred())
			})

			It("the signature is valid", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.IdemixSignerOpts{
						RevocationPublicKey: RevocationPublicKey,
						Attributes: []bccsp.IdemixAttribute{
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
						},
						RhIndex:  4,
						EidIndex: 2,
						Epoch:    0,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

		})

		Describe("producing an idemix signature with disclosed attributes", func() {
			var (
				digest    []byte
				signature []byte
			)

			BeforeEach(func() {
				var err error

				digest = []byte("a digest")

				// signature, err = CSP.Sign(
				//	UserKey,
				//	digest,
				//	&bccsp.IdemixSignerOpts{
				//		Credential: credential,
				//		Nym:        NymKey,
				//		IssuerPK:   IssuerPublicKey,
				//		Attributes: []bccsp.IdemixAttribute{
				//			{Type: bccsp.IdemixBytesAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixIntAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//			{Type: bccsp.IdemixHiddenAttribute},
				//		},
				//		RhIndex: 4,
				//		Epoch:   0,
				//		CRI:     cri,
				//	},
				// )
				// Expect(err).NotTo(HaveOccurred())
				signature, err = ioutil.ReadFile("./testdata/old/signature_with_disclosed_attribute.sign")
				Expect(err).NotTo(HaveOccurred())
			})

			It("the signature is valid", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.IdemixSignerOpts{
						RevocationPublicKey: RevocationPublicKey,
						Attributes: []bccsp.IdemixAttribute{
							{Type: bccsp.IdemixBytesAttribute, Value: []byte{0}},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixIntAttribute, Value: 1},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
						},
						RhIndex:  4,
						EidIndex: 2,
						Epoch:    0,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

		})

		Describe("producing an idemix nym signature", func() {
			var (
				digest    []byte
				signature []byte
			)

			BeforeEach(func() {
				var err error

				digest = []byte("a digest")

				// signature, err = CSP.Sign(
				//	UserKey,
				//	digest,
				//	&bccsp.IdemixNymSignerOpts{
				//		Nym:      NymKey,
				//		IssuerPK: IssuerPublicKey,
				//	},
				// )
				// Expect(err).NotTo(HaveOccurred())
				signature, err = ioutil.ReadFile("./testdata/old/nym_signature.sign")
				Expect(err).NotTo(HaveOccurred())
			})

			It("the signature is valid", func() {
				valid, err := CSP.Verify(
					NymPublicKey,
					signature,
					digest,
					&bccsp.IdemixNymSignerOpts{
						IssuerPK: IssuerPublicKey,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

		})
	})
})
