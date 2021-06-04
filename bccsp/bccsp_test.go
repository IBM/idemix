/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	idemix "github.com/IBM/idemix/bccsp"
	bccsp "github.com/IBM/idemix/bccsp/schemes"
	idemix1 "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	. "github.com/onsi/ginkgo"
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
	testWithCurve(math.BN256, &amcl.Gurvy{C: math.Curves[math.BN256]})
	testWithCurve(math.BN254, &amcl.Gurvy{C: math.Curves[math.BN254]})
	testWithCurve(math.FP256BN_AMCL_MIRACL, &amcl.Fp256bnMiracl{C: math.Curves[math.FP256BN_AMCL_MIRACL]})
})

func curveName(id math.CurveID) string {
	switch id {
	case math.BN256:
		return "BN256"
	case math.FP256BN_AMCL:
		return "FP256BN_AMCL"
	case math.BN254:
		return "BN254"
	case math.FP256BN_AMCL_MIRACL:
		return "FP256BN_AMCL_MIRACL"
	default:
		panic(fmt.Sprintf("unknown curve %d", id))
	}
}

func testWithCurve(id math.CurveID, translator idemix1.Translator) {
	Describe(fmt.Sprintf("setting up the environment with one issuer and one user with curve %s", curveName(id)), func() {
		var (
			CSP             bccsp.BCCSP
			IssuerKey       bccsp.Key
			IssuerPublicKey bccsp.Key
			AttributeNames  []string

			UserKey      bccsp.Key
			NymKey       bccsp.Key
			NymPublicKey bccsp.Key

			IssuerNonce []byte
			credRequest []byte

			credential []byte

			RevocationKey       bccsp.Key
			RevocationPublicKey bccsp.Key
			cri                 []byte
			rootDir             string
		)

		BeforeEach(func() {
			var err error

			rootDir, err = ioutil.TempDir(os.TempDir(), "idemixtest")
			Expect(err).NotTo(HaveOccurred())

			CSP, err = idemix.New(NewDummyKeyStore(), math.Curves[id], translator, true)
			Expect(err).NotTo(HaveOccurred())

			// Issuer
			AttributeNames = []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
			IssuerKey, err = CSP.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: AttributeNames})
			Expect(err).NotTo(HaveOccurred())
			IssuerPublicKey, err = IssuerKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			raw, err := IssuerKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "issuerkey.sk"), raw, 0666)).NotTo(HaveOccurred())
			raw, err = IssuerPublicKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "issuerkey.pk"), raw, 0666)).NotTo(HaveOccurred())

			// User
			UserKey, err = CSP.KeyGen(&bccsp.IdemixUserSecretKeyGenOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())

			raw, err = UserKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			// Expect(len(raw)).To(Equal(32))
			Expect(ioutil.WriteFile(path.Join(rootDir, "userkey.sk"), raw, 0666)).NotTo(HaveOccurred())

			// User Nym Key
			NymKey, err = CSP.KeyDeriv(UserKey, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: IssuerPublicKey})
			Expect(err).NotTo(HaveOccurred())
			NymPublicKey, err = NymKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			raw, err = NymKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "nymkey.sk"), raw, 0666)).NotTo(HaveOccurred())
			raw, err = NymPublicKey.Bytes()
			Expect(len(raw)).To(Equal(64))
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "nymkey.pk"), raw, 0666)).NotTo(HaveOccurred())

			IssuerNonce = make([]byte, 32)
			n, err := rand.Read(IssuerNonce)
			Expect(n).To(BeEquivalentTo(32))
			Expect(err).NotTo(HaveOccurred())

			// Credential Request for User
			credRequest, err = CSP.Sign(
				UserKey,
				nil,
				&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
			)
			Expect(err).NotTo(HaveOccurred())

			// Credential
			credential, err = CSP.Sign(
				IssuerKey,
				credRequest,
				&bccsp.IdemixCredentialSignerOpts{
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

			// Revocation
			RevocationKey, err = CSP.KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())
			RevocationPublicKey, err = RevocationKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			raw, err = RevocationKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "revocation.sk"), raw, 0666)).NotTo(HaveOccurred())
			raw, err = RevocationPublicKey.Bytes()
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "revocation.pk"), raw, 0666)).NotTo(HaveOccurred())

			// CRI
			cri, err = CSP.Sign(
				RevocationKey,
				nil,
				&bccsp.IdemixCRISignerOpts{},
			)
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

				signature, err = CSP.Sign(
					UserKey,
					digest,
					&bccsp.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
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
						CRI:      cri,
					},
				)
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.BestEffort,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid when we expect a standard signature", func() {
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectStandard,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect a signature with nym eid", func() {
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no EidNym provided but ExpectEidNym required"))
				Expect(valid).To(BeFalse())
			})

		})

		Describe("producing an idemix signature with an eid nym", func() {
			var (
				digest    []byte
				signature []byte
				signOpts  *bccsp.IdemixSignerOpts
			)

			BeforeEach(func() {
				var err error

				digest = []byte("a digest")

				signOpts = &bccsp.IdemixSignerOpts{
					Credential: credential,
					Nym:        NymKey,
					IssuerPK:   IssuerPublicKey,
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
					CRI:      cri,
					SigType:  bccsp.EidNym,
				}

				signature, err = CSP.Sign(
					UserKey,
					digest,
					signOpts,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(signOpts.Metadata).NotTo(BeNil())
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.BestEffort,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid when we expect an eid nym", func() {
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid when we expect an eid nym and request auditing of the eid nym", func() {
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect an eid nym and request auditing of the eid nym with a wrong randomness", func() {
				signOpts.Metadata.NymEIDAuditData.RNymEid = signOpts.Metadata.NymEIDAuditData.EID

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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym eid validation failed"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect a standard signature", func() {
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
						RhIndex:          4,
						EidIndex:         2,
						Epoch:            0,
						VerificationType: bccsp.ExpectStandard,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("EidNym available but ExpectStandard required"))
				Expect(valid).To(BeFalse())
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

				signature, err = CSP.Sign(
					UserKey,
					digest,
					&bccsp.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: []bccsp.IdemixAttribute{
							{Type: bccsp.IdemixBytesAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixIntAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
							{Type: bccsp.IdemixHiddenAttribute},
						},
						RhIndex:  4,
						EidIndex: 2,
						Epoch:    0,
						CRI:      cri,
					},
				)
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

				signature, err = CSP.Sign(
					UserKey,
					digest,
					&bccsp.IdemixNymSignerOpts{
						Nym:      NymKey,
						IssuerPK: IssuerPublicKey,
					},
				)
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

		Describe("Idemix Bridge Load", func() {

			Describe("setting up the environment with one issuer and one user", func() {
				var (
					CSP             bccsp.BCCSP
					IssuerKey       bccsp.Key
					IssuerPublicKey bccsp.Key
					AttributeNames  []string

					UserKey      bccsp.Key
					NymKey       bccsp.Key
					NymPublicKey bccsp.Key

					IssuerNonce []byte
					credRequest []byte

					credential []byte

					RevocationKey       bccsp.Key
					RevocationPublicKey bccsp.Key
					cri                 []byte
				)

				BeforeEach(func() {
					var err error
					CSP, err = idemix.New(NewDummyKeyStore(), math.Curves[id], translator, true)
					Expect(err).NotTo(HaveOccurred())

					// Issuer
					AttributeNames = []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
					raw, err := ioutil.ReadFile(path.Join(rootDir, "issuerkey.sk"))
					Expect(err).NotTo(HaveOccurred())
					IssuerKey, err = CSP.KeyImport(raw, &bccsp.IdemixIssuerKeyImportOpts{Temporary: true, AttributeNames: AttributeNames})
					Expect(err).NotTo(HaveOccurred())
					IssuerPublicKey, err = IssuerKey.PublicKey()
					Expect(err).NotTo(HaveOccurred())

					// User
					raw, err = ioutil.ReadFile(path.Join(rootDir, "userkey.sk"))
					Expect(err).NotTo(HaveOccurred())
					UserKey, err = CSP.KeyImport(raw, &bccsp.IdemixUserSecretKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())

					// User Nym Key
					rawNymKeySk, err := ioutil.ReadFile(path.Join(rootDir, "nymkey.sk"))
					Expect(err).NotTo(HaveOccurred())
					rawNymKeyPk, err := ioutil.ReadFile(path.Join(rootDir, "nymkey.pk"))
					Expect(err).NotTo(HaveOccurred())
					Expect(len(rawNymKeyPk)).To(Equal(64))

					NymKey, err = CSP.KeyImport(append(rawNymKeySk, rawNymKeyPk...), &bccsp.IdemixNymKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())
					NymPublicKey, err = CSP.KeyImport(rawNymKeyPk, &bccsp.IdemixNymPublicKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())

					IssuerNonce = make([]byte, 32)
					n, err := rand.Read(IssuerNonce)
					Expect(n).To(BeEquivalentTo(32))
					Expect(err).NotTo(HaveOccurred())

					// Credential Request for User
					credRequest, err = CSP.Sign(
						UserKey,
						nil,
						&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
					)
					Expect(err).NotTo(HaveOccurred())

					// Credential
					credential, err = CSP.Sign(
						IssuerKey,
						credRequest,
						&bccsp.IdemixCredentialSignerOpts{
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

					// Revocation
					raw, err = ioutil.ReadFile(path.Join(rootDir, "revocation.sk"))
					Expect(err).NotTo(HaveOccurred())
					RevocationKey, err = CSP.KeyImport(raw, &bccsp.IdemixRevocationKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())
					RevocationPublicKey, err = RevocationKey.PublicKey()
					Expect(err).NotTo(HaveOccurred())

					// CRI
					cri, err = CSP.Sign(
						RevocationKey,
						nil,
						&bccsp.IdemixCRISignerOpts{},
					)
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

						signature, err = CSP.Sign(
							UserKey,
							digest,
							&bccsp.IdemixSignerOpts{
								Credential: credential,
								Nym:        NymKey,
								IssuerPK:   IssuerPublicKey,
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
								CRI:      cri,
							},
						)
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

						signature, err = CSP.Sign(
							UserKey,
							digest,
							&bccsp.IdemixSignerOpts{
								Credential: credential,
								Nym:        NymKey,
								IssuerPK:   IssuerPublicKey,
								Attributes: []bccsp.IdemixAttribute{
									{Type: bccsp.IdemixBytesAttribute},
									{Type: bccsp.IdemixHiddenAttribute},
									{Type: bccsp.IdemixIntAttribute},
									{Type: bccsp.IdemixHiddenAttribute},
									{Type: bccsp.IdemixHiddenAttribute},
								},
								RhIndex:  4,
								EidIndex: 2,
								Epoch:    0,
								CRI:      cri,
							},
						)
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

						signature, err = CSP.Sign(
							UserKey,
							digest,
							&bccsp.IdemixNymSignerOpts{
								Nym:      NymKey,
								IssuerPK: IssuerPublicKey,
							},
						)
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
	})
}

var _ = Describe("Idemix Bridge Compatibility", func() {

	Describe("setting up the environment with one issuer and one user", func() {
		var (
			CSP             bccsp.BCCSP
			IssuerKey       bccsp.Key
			IssuerPublicKey bccsp.Key
			AttributeNames  []string

			UserKey bccsp.Key
			//NymKey       bccsp.Key
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
			//rawNymKeySk, err := ioutil.ReadFile("./testdata/old/nymkey.sk")
			//Expect(err).NotTo(HaveOccurred())
			rawNymKeyPk, err := ioutil.ReadFile("./testdata/old/nymkey.pk")
			Expect(err).NotTo(HaveOccurred())

			//NymKey, err = CSP.KeyImport(append(rawNymKeySk, rawNymKeyPk...), &bccsp.IdemixNymKeyImportOpts{Temporary: true})
			//Expect(err).NotTo(HaveOccurred())
			NymPublicKey, err = CSP.KeyImport(rawNymKeyPk, &bccsp.IdemixNymPublicKeyImportOpts{Temporary: true})
			Expect(err).NotTo(HaveOccurred())

			//IssuerNonce = make([]byte, 32)
			//n, err := rand.Read(IssuerNonce)
			//Expect(n).To(BeEquivalentTo(32))
			//Expect(err).NotTo(HaveOccurred())
			IssuerNonce, err = ioutil.ReadFile("./testdata/old/issuer_nonce")
			Expect(err).NotTo(HaveOccurred())

			// Credential Request for User
			credRequest, err = ioutil.ReadFile("./testdata/old/cred_request.sign")
			Expect(err).NotTo(HaveOccurred())
			//credRequest, err = CSP.Sign(
			//	UserKey,
			//	nil,
			//	&bccsp.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
			//)
			//Expect(err).NotTo(HaveOccurred())

			// Credential
			//credential, err = CSP.Sign(
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
			//)
			//Expect(err).NotTo(HaveOccurred())
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
			//cri, err = CSP.Sign(
			//	RevocationKey,
			//	nil,
			//	&bccsp.IdemixCRISignerOpts{},
			//)
			//Expect(err).NotTo(HaveOccurred())
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

				//signature, err = CSP.Sign(
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
				//)
				//Expect(err).NotTo(HaveOccurred())
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

				//signature, err = CSP.Sign(
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
				//)
				//Expect(err).NotTo(HaveOccurred())
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

				//signature, err = CSP.Sign(
				//	UserKey,
				//	digest,
				//	&bccsp.IdemixNymSignerOpts{
				//		Nym:      NymKey,
				//		IssuerPK: IssuerPublicKey,
				//	},
				//)
				//Expect(err).NotTo(HaveOccurred())
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
