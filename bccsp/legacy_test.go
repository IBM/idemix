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
	idemix1 "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	bccsp "github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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
			Expect(len(raw)).To(Equal(2 * math.Curves[id].CoordByteSize))
			Expect(err).NotTo(HaveOccurred())
			Expect(ioutil.WriteFile(path.Join(rootDir, "nymkey.pk"), raw, 0666)).NotTo(HaveOccurred())

			IssuerNonce = make([]byte, math.Curves[id].ScalarByteSize)
			n, err := rand.Read(IssuerNonce)
			Expect(n).To(BeEquivalentTo(math.Curves[id].ScalarByteSize))
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
						// VerificationType: bccsp.Basic,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid even when there's garbage in the nym eid field if we do basic verification", func() {
				sig := &idemix1.Signature{}
				err := proto.Unmarshal(signature, sig)
				Expect(err).NotTo(HaveOccurred())

				sig.EidNym = &idemix1.EIDNym{
					ProofSEid: []byte("invalid garbage"),
				}

				sigBytes, err := proto.Marshal(sig)
				Expect(err).NotTo(HaveOccurred())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					sigBytes,
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
						// VerificationType: bccsp.Basic,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when there's garbage in the nym eid field and we do ExpectStandard verification", func() {
				sig := &idemix1.Signature{}
				err := proto.Unmarshal(signature, sig)
				Expect(err).NotTo(HaveOccurred())

				sig.EidNym = &idemix1.EIDNym{
					ProofSEid: []byte("invalid garbage"),
				}

				sigBytes, err := proto.Marshal(sig)
				Expect(err).NotTo(HaveOccurred())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					sigBytes,
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

			It("the signature is not valid when there's garbage in the nym eid field and we do ExpectEidNym verification", func() {
				sig := &idemix1.Signature{}
				err := proto.Unmarshal(signature, sig)
				Expect(err).NotTo(HaveOccurred())

				sig.EidNym = &idemix1.EIDNym{
					ProofSEid: []byte("invalid garbage"),
				}

				sigBytes, err := proto.Marshal(sig)
				Expect(err).NotTo(HaveOccurred())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					sigBytes,
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

			It("the signature is not valid when there's garbage in the nym eid field and we do BestEffort verification", func() {
				sig := &idemix1.Signature{}
				err := proto.Unmarshal(signature, sig)
				Expect(err).NotTo(HaveOccurred())

				sig.EidNym = &idemix1.EIDNym{
					ProofSEid: []byte("invalid garbageinvalid garbageinvalid garbageinvalid garbageinvalid garbageinvalid garbageinvalid garbageinvalid garbage"),
					Nym:       translator.G1ToProto(math.Curves[id].GenG1),
				}

				sigBytes, err := proto.Marshal(sig)
				Expect(err).NotTo(HaveOccurred())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					sigBytes,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.BestEffort,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("zero-knowledge proof is invalid"))
				Expect(valid).To(BeFalse())
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
					EidIndex: 3,
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

			It("the signature is not valid if we use basic verification", func() {
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
						EidIndex: 3,
						Epoch:    0,
						// VerificationType: bccsp.Basic,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("zero-knowledge proof is invalid"))
				Expect(valid).To(BeFalse())
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
						EidIndex:         3,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid when we expect an eid nym and supply the right one", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: signOpts.Metadata.EidNym,
						},
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect an eid nym and supply the wrong one", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: math.Curves[id].GenG1.Bytes(),
						},
					},
				)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym eid validation failed, signature nym eid does not match metadata"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect an eid nym and supply garbage", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: []byte("garbage"),
						},
					},
				)
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym eid validation failed, failed to unmarshal meta nym eid"))
				Expect(valid).To(BeFalse())
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect an eid nym and request auditing of the eid nym with a wrong randomness", func() {
				signOpts.Metadata.EidNymAuditData.Rand = signOpts.Metadata.EidNymAuditData.Attr

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
						EidIndex:         3,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectStandard,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("EidNym available but ExpectStandard required"))
				Expect(valid).To(BeFalse())
			})

			It("nym eid auditing with the right enrollment ID succeeds", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.EidNymAuditOpts{
						EidIndex:     3,
						EnrollmentID: string([]byte{0, 1, 2}),
						RNymEid:      signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.EidNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.EidNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNym,
						EidIndex:              3,
						EnrollmentID:          string([]byte{0, 1, 2}),
						RNymEid:               signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("nym eid auditing with the wrong enrollment ID fails", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.EidNymAuditOpts{
						EidIndex:     3,
						EnrollmentID: "Have you seen the writing on the wall?",
						RNymEid:      signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.EidNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.EidNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNym,
						EidIndex:              3,
						EnrollmentID:          "Have you seen the writing on the wall?",
						RNymEid:               signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())
			})

			It("valid signature against meta", func() {
				signOpts2 := &bccsp.IdemixSignerOpts{
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
					EidIndex: 3,
					Epoch:    0,
					CRI:      cri,
					SigType:  bccsp.EidNym,
					Metadata: signOpts.Metadata,
				}
				signature2, err := CSP.Sign(
					UserKey,
					digest,
					signOpts2,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(signOpts2.Metadata).NotTo(BeNil())

				Expect(signOpts2.Metadata.EidNymAuditData.Nym.Equals(signOpts.Metadata.EidNymAuditData.Nym)).To(BeTrue())
				Expect(signOpts2.Metadata.EidNymAuditData.Attr.Equals(signOpts2.Metadata.EidNymAuditData.Attr)).To(BeTrue())
				Expect(signOpts2.Metadata.EidNymAuditData.Rand.Equals(signOpts.Metadata.EidNymAuditData.Rand)).To(BeTrue())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature2,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signature2,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
						Metadata:         signOpts2.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

		})

		Describe("producing an idemix signature with an eid nym and rh nym", func() {
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
					EidIndex: 3,
					Epoch:    0,
					CRI:      cri,
					SigType:  bccsp.EidNymRhNym,
				}

				signature, err = CSP.Sign(
					UserKey,
					digest,
					signOpts,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(signOpts.Metadata).NotTo(BeNil())
			})

			It("the signature is not valid if we use basic verification", func() {
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
						EidIndex: 3,
						Epoch:    0,
						// VerificationType: bccsp.Basic,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("zero-knowledge proof is invalid"))
				Expect(valid).To(BeFalse())
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.BestEffort,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect only an eid nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNym,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("zero-knowledge proof is invalid"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is valid when we expect both an eid nym and rh nym and request auditing of the eid nym and the rh nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is valid when we expect both an eid nym and rh nym and supply the right eid nym and rh nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: signOpts.Metadata.EidNym,
							RhNym:  signOpts.Metadata.RhNym,
						},
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("the signature is not valid when we expect both an eid nym and rh nym and supply the right eid nym and the wrong rh nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: signOpts.Metadata.EidNym,
							RhNym:  math.Curves[id].GenG1.Bytes(),
						},
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym rh validation failed, signature nym rh does not match metadata"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect both an eid nym and rh nym and supply the right eid nym and garbage rh nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: signOpts.Metadata.EidNym,
							RhNym:  []byte("garbage"),
						},
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym rh validation failed, failed to unmarshal meta nym rh"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect both an eid nym and rh nym and supply the wrong eid nym and the right rh nym", func() {
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata: &bccsp.IdemixSignerMetadata{
							EidNym: math.Curves[id].GenG1.Bytes(),
							RhNym:  signOpts.Metadata.RhNym,
						},
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym eid validation failed, signature nym eid does not match metadata"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect both an eid nym and rh nym and request auditing of the eid nym with a wrong randomness", func() {
				signOpts.Metadata.EidNymAuditData.Rand = signOpts.Metadata.EidNymAuditData.Attr

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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym eid validation failed"))
				Expect(valid).To(BeFalse())
			})

			It("the signature is not valid when we expect both an eid nym and rh nym and request auditing of the rh nym with a wrong randomness", func() {
				signOpts.Metadata.RhNymAuditData.Rand = signOpts.Metadata.RhNymAuditData.Attr

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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signature invalid: nym rh validation failed"))
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectStandard,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RhNym available but ExpectStandard required"))
				Expect(valid).To(BeFalse())
			})

			It("nym eid auditing with the right enrollment ID succeeds", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.EidNymAuditOpts{
						EidIndex:     3,
						EnrollmentID: string([]byte{0, 1, 2}),
						RNymEid:      signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.EidNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.EidNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNym,
						EidIndex:              3,
						EnrollmentID:          string([]byte{0, 1, 2}),
						RNymEid:               signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("nym eid auditing with the wrong enrollment ID fails", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.EidNymAuditOpts{
						EidIndex:     3,
						EnrollmentID: "Have you seen the writing on the wall?",
						RNymEid:      signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.EidNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.EidNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNym,
						EidIndex:              3,
						EnrollmentID:          "Have you seen the writing on the wall?",
						RNymEid:               signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())
			})

			It("nym rh auditing with the right revocation handle succeeds", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.RhNymAuditOpts{
						RhIndex:          4,
						RevocationHandle: string([]byte{0, 1, 2, 3}),
						RNymRh:           signOpts.Metadata.RhNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.RhNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.RhNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNymRhNym,
						RhIndex:               4,
						RevocationHandle:      string([]byte{0, 1, 2, 3}),
						RNymRh:                signOpts.Metadata.RhNymAuditData.Rand,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("nym eid auditing with the wrong enrollment ID fails", func() {
				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&bccsp.EidNymAuditOpts{
						EidIndex:     3,
						EnrollmentID: "Have you seen the writing on the wall?",
						RNymEid:      signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signOpts.Metadata.EidNymAuditData.Nym.Bytes(),
					digest,
					&bccsp.EidNymAuditOpts{
						AuditVerificationType: bccsp.AuditExpectEidNym,
						EidIndex:              3,
						EnrollmentID:          "Have you seen the writing on the wall?",
						RNymEid:               signOpts.Metadata.EidNymAuditData.Rand,
					},
				)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("eid nym does not match"))
				Expect(valid).To(BeFalse())
			})

			It("valid signature against meta", func() {
				signOpts2 := &bccsp.IdemixSignerOpts{
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
					EidIndex: 3,
					Epoch:    0,
					CRI:      cri,
					SigType:  bccsp.EidNymRhNym,
					Metadata: signOpts.Metadata,
				}
				signature2, err := CSP.Sign(
					UserKey,
					digest,
					signOpts2,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(signOpts2.Metadata).NotTo(BeNil())

				Expect(signOpts2.Metadata.EidNymAuditData.Nym.Equals(signOpts.Metadata.EidNymAuditData.Nym)).To(BeTrue())
				Expect(signOpts2.Metadata.EidNymAuditData.Attr.Equals(signOpts2.Metadata.EidNymAuditData.Attr)).To(BeTrue())
				Expect(signOpts2.Metadata.EidNymAuditData.Rand.Equals(signOpts.Metadata.EidNymAuditData.Rand)).To(BeTrue())

				Expect(signOpts2.Metadata.RhNymAuditData.Nym.Equals(signOpts.Metadata.RhNymAuditData.Nym)).To(BeTrue())
				Expect(signOpts2.Metadata.RhNymAuditData.Attr.Equals(signOpts2.Metadata.RhNymAuditData.Attr)).To(BeTrue())
				Expect(signOpts2.Metadata.RhNymAuditData.Rand.Equals(signOpts.Metadata.RhNymAuditData.Rand)).To(BeTrue())

				valid, err := CSP.Verify(
					IssuerPublicKey,
					signature2,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata:         signOpts.Metadata,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = CSP.Verify(
					IssuerPublicKey,
					signature2,
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
						EidIndex:         3,
						Epoch:            0,
						VerificationType: bccsp.ExpectEidNymRhNym,
						Metadata:         signOpts2.Metadata,
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
					Expect(len(rawNymKeyPk)).To(Equal(2 * math.Curves[id].CoordByteSize))

					NymKey, err = CSP.KeyImport(append(rawNymKeySk, rawNymKeyPk...), &bccsp.IdemixNymKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())
					NymPublicKey, err = CSP.KeyImport(rawNymKeyPk, &bccsp.IdemixNymPublicKeyImportOpts{Temporary: true})
					Expect(err).NotTo(HaveOccurred())

					IssuerNonce = make([]byte, math.Curves[id].ScalarByteSize)
					n, err := rand.Read(IssuerNonce)
					Expect(n).To(BeEquivalentTo(math.Curves[id].ScalarByteSize))
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
