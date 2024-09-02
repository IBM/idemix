/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package bridge_test

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/IBM/idemix/bccsp/types"
	"github.com/IBM/idemix/bccsp/types/mock"
	"github.com/IBM/idemix/v2/bccsp/handlers"
	"github.com/IBM/idemix/v2/bccsp/schemes/dlog/bridge"
	idemix "github.com/IBM/idemix/v2/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/v2/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func rndOrPanic(curve *math.Curve) io.Reader {
	rnd, err := curve.Rand()
	if err != nil {
		panic(err)
	}

	return rnd
}

var _ = Describe("Idemix Bridge", func() {
	var (
		userSecretKey   *math.Zr
		issuerPublicKey types.IssuerPublicKey
		issuerSecretKey types.IssuerSecretKey
		nymPublicKey    *math.G1
		nymSecretKey    *math.Zr
	)

	BeforeEach(func() {
		userSecretKey = math.Curves[math.FP256BN_AMCL].NewZrFromInt(0)
		issuerPublicKey = &bridge.IssuerPublicKey{}
		issuerSecretKey = &bridge.IssuerSecretKey{}
		nymPublicKey = math.Curves[math.FP256BN_AMCL].GenG1
		nymSecretKey = math.Curves[math.FP256BN_AMCL].NewZrFromInt(0)
	})

	Describe("issuer", func() {
		var (
			Issuer *bridge.Issuer
		)

		BeforeEach(func() {
			Issuer = &bridge.Issuer{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
		})

		Context("key generation", func() {

			Context("successful generation", func() {
				var (
					key        types.IssuerSecretKey
					err        error
					attributes []string
				)

				It("with valid attributes", func() {
					attributes = []string{"A", "B"}
					key, err = Issuer.NewKey(attributes)
					Expect(err).NotTo(HaveOccurred())
					Expect(key).NotTo(BeNil())
				})

				It("with empty attributes", func() {
					attributes = nil
					key, err = Issuer.NewKey(attributes)
					Expect(err).NotTo(HaveOccurred())
					Expect(key).NotTo(BeNil())
				})

				AfterEach(func() {
					raw, err := key.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw).NotTo(BeEmpty())

					pk := key.Public()
					Expect(pk).NotTo(BeNil())

					h := pk.Hash()
					Expect(h).NotTo(BeEmpty())

					raw, err = pk.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw).NotTo(BeEmpty())

					pk2, err := Issuer.NewPublicKeyFromBytes(raw, attributes)
					Expect(err).NotTo(HaveOccurred())

					raw2, err := pk2.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw2).NotTo(BeEmpty())
					Expect(pk2.Hash()).To(BeEquivalentTo(pk.Hash()))
					Expect(raw2).To(BeEquivalentTo(raw))
				})
			})
		})

		Context("public key import", func() {

			It("fails to unmarshal issuer public key", func() {
				pk, err := Issuer.NewPublicKeyFromBytes([]byte{0, 1, 2, 3, 4}, nil)
				Expect(err.Error()).To(ContainSubstring("failed to unmarshal issuer public key: proto"))
				Expect(pk).To(BeNil())
			})

			It("fails to unmarshal issuer public key", func() {
				pk, err := Issuer.NewPublicKeyFromBytes(nil, nil)
				Expect(err).To(MatchError(ContainSubstring("nil argument")))
				Expect(pk).To(BeNil())
			})

			Context("and it is modified", func() {
				var (
					pk types.IssuerPublicKey
				)
				BeforeEach(func() {
					attributes := []string{"A", "B"}
					key, err := Issuer.NewKey(attributes)
					Expect(err).NotTo(HaveOccurred())
					pk = key.Public()
					Expect(pk).NotTo(BeNil())
				})

				It("fails to validate invalid issuer public key", func() {
					if pk.(*bridge.IssuerPublicKey).PK.ProofC[0] != 1 {
						pk.(*bridge.IssuerPublicKey).PK.ProofC[0] = 1
					} else {
						pk.(*bridge.IssuerPublicKey).PK.ProofC[0] = 0
					}
					raw, err := pk.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw).NotTo(BeEmpty())

					pk, err = Issuer.NewPublicKeyFromBytes(raw, nil)
					Expect(err).To(MatchError("invalid issuer public key: zero knowledge proof in public key invalid"))
					Expect(pk).To(BeNil())
				})

				It("fails to verify attributes, different length", func() {
					raw, err := pk.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw).NotTo(BeEmpty())

					pk, err := Issuer.NewPublicKeyFromBytes(raw, []string{"A"})
					Expect(err).To(MatchError("invalid number of attributes, expected [2], got [1]"))
					Expect(pk).To(BeNil())
				})

				It("fails to verify attributes, different attributes", func() {
					raw, err := pk.Bytes()
					Expect(err).NotTo(HaveOccurred())
					Expect(raw).NotTo(BeEmpty())

					pk, err := Issuer.NewPublicKeyFromBytes(raw, []string{"A", "C"})
					Expect(err).To(MatchError("invalid attribute name at position [1]"))
					Expect(pk).To(BeNil())
				})
			})

		})
	})

	Describe("user", func() {
		var (
			User *bridge.User
		)

		BeforeEach(func() {
			User = &bridge.User{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
		})

		Context("secret key import", func() {
			It("success", func() {
				key, err := User.NewKey()
				Expect(err).NotTo(HaveOccurred())

				raw := key.Bytes()
				Expect(raw).NotTo(BeNil())

				key2, err := User.NewKeyFromBytes(raw)
				Expect(err).NotTo(HaveOccurred())

				raw2 := key2.Bytes()
				Expect(raw2).NotTo(BeNil())

				Expect(raw2).To(BeEquivalentTo(raw))
			})

			It("fails on nil raw", func() {
				key, err := User.NewKeyFromBytes(nil)
				Expect(err).To(MatchError("invalid length, expected [32], got [0]"))
				Expect(key).To(BeNil())
			})

			It("fails on invalid raw", func() {
				key, err := User.NewKeyFromBytes([]byte{0, 1, 2, 3})
				Expect(err).To(MatchError("invalid length, expected [32], got [4]"))
				Expect(key).To(BeNil())
			})
		})

		Context("nym generation", func() {

			It("fails on nil issuer public key", func() {
				r1, r2, err := User.MakeNym(userSecretKey, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
				Expect(r1).To(BeNil())
				Expect(r2).To(BeNil())
			})

			It("fails on invalid issuer public key", func() {
				r1, r2, err := User.MakeNym(userSecretKey, &mock.IssuerPublicKey{})
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [*mock.IssuerPublicKey]"))
				Expect(r1).To(BeNil())
				Expect(r2).To(BeNil())
			})
		})

		Context("public nym import", func() {
			It("success", func() {
				curve := math.Curves[math.FP256BN_AMCL]
				rng, err := curve.Rand()
				Expect(err).NotTo(HaveOccurred())

				g := curve.GenG1
				r := curve.NewRandomZr(rng)
				h := g.Mul(r)

				npk := handlers.NewNymPublicKey(h, &amcl.Fp256bn{C: curve})
				raw, err := npk.Bytes()
				Expect(err).NotTo(HaveOccurred())
				Expect(raw).NotTo(BeNil())

				npk2, err := User.NewPublicNymFromBytes(raw)
				Expect(err).NotTo(HaveOccurred())

				Expect(npk2.Equals(h)).To(BeTrue())

				raw2, err := handlers.NewNymPublicKey(npk2, &amcl.Fp256bn{C: curve}).Bytes()
				Expect(err).NotTo(HaveOccurred())
				Expect(raw2).NotTo(BeNil())

				Expect(raw2).To(BeEquivalentTo(raw))
			})

			It("panic on nil raw", func() {
				key, err := User.NewPublicNymFromBytes(nil)
				Expect(err).To(MatchError("invalid marshalled length"))
				Expect(key).To(BeNil())
			})

			It("failure unmarshalling invalid raw", func() {
				key, err := User.NewPublicNymFromBytes([]byte{0, 1, 2, 3})
				Expect(err).To(MatchError("invalid marshalled length"))
				Expect(key).To(BeNil())
			})

		})
	})

	Describe("credential request", func() {
		var (
			CredRequest *bridge.CredRequest
			IssuerNonce []byte
		)
		BeforeEach(func() {
			CredRequest = &bridge.CredRequest{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			IssuerNonce = make([]byte, 32)
			n, err := rand.Read(IssuerNonce)
			Expect(n).To(BeEquivalentTo(32))
			Expect(err).NotTo(HaveOccurred())
		})

		Context("sign", func() {
			It("fail on nil issuer public key", func() {
				raw, err := CredRequest.Sign(userSecretKey, nil, IssuerNonce)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
				Expect(raw).To(BeNil())
			})

			It("fail on invalid issuer public key", func() {
				raw, err := CredRequest.Sign(userSecretKey, &mock.IssuerPublicKey{}, IssuerNonce)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [*mock.IssuerPublicKey]"))
				Expect(raw).To(BeNil())
			})

			It("fail on nil nonce", func() {
				raw, err := CredRequest.Sign(userSecretKey, issuerPublicKey, nil)
				Expect(err).To(MatchError("invalid issuer nonce, expected length 32, got 0"))
				Expect(raw).To(BeNil())
			})

			It("fail on empty nonce", func() {
				raw, err := CredRequest.Sign(userSecretKey, issuerPublicKey, []byte{})
				Expect(err).To(MatchError("invalid issuer nonce, expected length 32, got 0"))
				Expect(raw).To(BeNil())
			})
		})

		Context("verify", func() {
			It("panic on nil credential request", func() {
				err := CredRequest.Verify(nil, issuerPublicKey, IssuerNonce)
				Expect(err).To(MatchError(ContainSubstring("nil argument")))
			})

			It("fail on invalid credential request", func() {
				err := CredRequest.Verify([]byte{0, 1, 2, 3, 4}, issuerPublicKey, IssuerNonce)
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
			})

			It("fail on nil issuer public key", func() {
				err := CredRequest.Verify(nil, nil, IssuerNonce)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
			})

			It("fail on invalid issuer public key", func() {
				err := CredRequest.Verify(nil, &mock.IssuerPublicKey{}, IssuerNonce)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [*mock.IssuerPublicKey]"))
			})

		})
	})

	Describe("credential", func() {
		var (
			Credential types.Credential
		)
		BeforeEach(func() {
			Credential = &bridge.Credential{
				Idemix: &idemix.Idemix{
					Curve: math.Curves[math.FP256BN_AMCL],
				},
			}
		})

		Context("sign", func() {

			It("fail on nil issuer secret key", func() {
				raw, err := Credential.Sign(nil, []byte{0, 1, 2, 3, 4}, nil)
				Expect(err).To(MatchError("invalid issuer secret key, expected *Big, got [<nil>]"))
				Expect(raw).To(BeNil())
			})

			It("fail on invalid credential request", func() {
				raw, err := Credential.Sign(issuerSecretKey, []byte{0, 1, 2, 3, 4}, nil)
				Expect(err.Error()).To(ContainSubstring("failed unmarshalling credential request: proto"))
				Expect(raw).To(BeNil())
			})

			It("fail on nil inputs", func() {
				raw, err := Credential.Sign(issuerSecretKey, nil, nil)
				Expect(err).To(MatchError("failure [runtime error: invalid memory address or nil pointer dereference]"))
				Expect(raw).To(BeNil())
			})

			It("fail on invalid attributes", func() {
				raw, err := Credential.Sign(issuerSecretKey, nil, []types.IdemixAttribute{
					{Type: 5, Value: nil},
				})
				Expect(err).To(MatchError("attribute type not allowed or supported [5] at position [0]"))
				Expect(raw).To(BeNil())
			})
		})

		Context("verify", func() {
			It("fail on nil issuer public  key", func() {
				err := Credential.Verify(userSecretKey, nil, nil, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [*math.Zr]"))
			})

			It("fail on invalid issuer public  key", func() {
				err := Credential.Verify(userSecretKey, &mock.IssuerPublicKey{}, nil, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [*math.Zr]"))
			})

			It("fail on invalid attributes", func() {
				err := Credential.Verify(userSecretKey, issuerPublicKey, nil, []types.IdemixAttribute{
					{Type: 5, Value: nil},
				})
				Expect(err).To(MatchError("attribute type not allowed or supported [5] at position [0]"))
			})
		})
	})

	Describe("revocation", func() {
		var (
			Revocation types.Revocation
		)
		BeforeEach(func() {
			Revocation = &bridge.Revocation{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}}
		})

		Context("sign", func() {

			It("fail on nil inputs", func() {
				raw, err := Revocation.Sign(nil, nil, 0, 0)
				Expect(err).To(MatchError("failed creating CRI: CreateCRI received nil input"))
				Expect(raw).To(BeNil())
			})

			It("fail on invalid handlers", func() {
				raw, err := Revocation.Sign(nil, [][]byte{{0, 2, 3, 4}}, 0, 0)
				Expect(err).To(MatchError(ContainSubstring("CreateCRI received nil input")))
				Expect(raw).To(BeNil())
			})
		})

		Context("verify", func() {
			It("fail on nil inputs", func() {
				err := Revocation.Verify(nil, nil, 0, 0)
				Expect(err).To(MatchError("EpochPK invalid: received nil input"))
			})

			It("fail on malformed cri", func() {
				err := Revocation.Verify(nil, []byte{0, 1, 2, 3, 4}, 0, 0)
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
			})
		})
	})

	Describe("signature", func() {
		var (
			SignatureScheme types.SignatureScheme
		)
		BeforeEach(func() {
			SignatureScheme = &bridge.SignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}}
		})

		Context("sign", func() {
			It("fail on nil issuer public key", func() {
				signature, _, err := SignatureScheme.Sign(nil, userSecretKey, nymPublicKey, nymSecretKey, nil, nil, nil, 0, 0, nil, 0, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
				Expect(signature).To(BeNil())
			})
		})

		Context("verify", func() {
			It("fail on nil issuer Public key", func() {
				err := SignatureScheme.Verify(nil, nil, nil, nil, 0, 2, 1, nil, 0, 0, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
			})

			It("fail on nil signature", func() {
				err := SignatureScheme.Verify(issuerPublicKey, nil, nil, nil, 0, 2, 1, nil, 0, 0, nil)
				Expect(err).To(MatchError("cannot verify idemix signature: received nil input"))
			})

			It("fail on invalid signature", func() {
				err := SignatureScheme.Verify(issuerPublicKey, []byte{0, 1, 2, 3, 4}, nil, nil, 0, 2, 1, nil, 0, 0, nil)
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
			})

			It("fail on invalid attributes", func() {
				err := SignatureScheme.Verify(issuerPublicKey, nil, nil,
					[]types.IdemixAttribute{{Type: -1}}, 0, 2, 1, nil, 0, 0, nil)
				Expect(err).To(MatchError("attribute type not allowed or supported [-1] at position [0]"))
			})
		})
	})

	Describe("nym signature", func() {
		var (
			NymSignatureScheme types.NymSignatureScheme
		)
		BeforeEach(func() {
			NymSignatureScheme = &bridge.NymSignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
		})

		Context("sign", func() {
			It("fail on nil issuer public key", func() {
				signature, err := NymSignatureScheme.Sign(userSecretKey, nymPublicKey, nymSecretKey, nil, nil)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
				Expect(signature).To(BeNil())
			})
		})

		Context("verify", func() {
			It("fail on nil issuer Public key", func() {
				err := NymSignatureScheme.Verify(nil, nil, nil, nil, 0)
				Expect(err).To(MatchError("invalid issuer public key, expected *IssuerPublicKey, got [<nil>]"))
			})

			It("panic on nil signature", func() {
				err := NymSignatureScheme.Verify(issuerPublicKey, nymPublicKey, nil, nil, 0)
				Expect(err).To(MatchError(ContainSubstring("failure [runtime error: invalid memory address or nil pointer dereference]")))
			})

			It("fail on invalid signature", func() {
				err := NymSignatureScheme.Verify(issuerPublicKey, nymPublicKey, []byte{0, 1, 2, 3, 4}, nil, 0)
				Expect(err.Error()).To(ContainSubstring("error unmarshalling signature"))
			})

		})
	})

	Describe("setting up the environment with one issuer and one user", func() {
		var (
			Issuer          types.Issuer
			IssuerKeyGen    *handlers.IssuerKeyGen
			IssuerKey       types.Key
			IssuerPublicKey types.Key
			AttributeNames  []string

			User             types.User
			UserKeyGen       *handlers.UserKeyGen
			UserKey          types.Key
			NymKeyDerivation *handlers.NymKeyDerivation
			NymKey           types.Key
			NymPublicKey     types.Key

			CredRequest               types.CredRequest
			CredentialRequestSigner   *handlers.CredentialRequestSigner
			CredentialRequestVerifier *handlers.CredentialRequestVerifier
			IssuerNonce               []byte
			credRequest               []byte

			Credential         types.Credential
			CredentialSigner   *handlers.CredentialSigner
			CredentialVerifier *handlers.CredentialVerifier
			credential         []byte

			Revocation          types.Revocation
			RevocationKeyGen    *handlers.RevocationKeyGen
			RevocationKey       types.Key
			RevocationPublicKey types.Key
			CriSigner           *handlers.CriSigner
			CriVerifier         *handlers.CriVerifier
			cri                 []byte
		)

		BeforeEach(func() {
			// Issuer
			var err error
			Issuer = &bridge.Issuer{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			IssuerKeyGen = &handlers.IssuerKeyGen{Issuer: Issuer}
			AttributeNames = []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
			IssuerKey, err = IssuerKeyGen.KeyGen(&types.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: AttributeNames})
			Expect(err).NotTo(HaveOccurred())
			IssuerPublicKey, err = IssuerKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// User
			User = &bridge.User{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			UserKeyGen = &handlers.UserKeyGen{User: User}
			UserKey, err = UserKeyGen.KeyGen(&types.IdemixUserSecretKeyGenOpts{})
			Expect(err).NotTo(HaveOccurred())

			// User Nym Key
			NymKeyDerivation = &handlers.NymKeyDerivation{User: User, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			NymKey, err = NymKeyDerivation.KeyDeriv(UserKey, &types.IdemixNymKeyDerivationOpts{IssuerPK: IssuerPublicKey})
			Expect(err).NotTo(HaveOccurred())
			NymPublicKey, err = NymKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// Credential Request for User
			IssuerNonce = make([]byte, 32)
			n, err := rand.Read(IssuerNonce)
			Expect(n).To(BeEquivalentTo(32))
			Expect(err).NotTo(HaveOccurred())

			CredRequest = &bridge.CredRequest{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			CredentialRequestSigner = &handlers.CredentialRequestSigner{CredRequest: CredRequest}
			CredentialRequestVerifier = &handlers.CredentialRequestVerifier{CredRequest: CredRequest}
			credRequest, err = CredentialRequestSigner.Sign(
				UserKey,
				nil,
				&types.IdemixCredentialRequestSignerOpts{IssuerPK: IssuerPublicKey, IssuerNonce: IssuerNonce},
			)
			Expect(err).NotTo(HaveOccurred())

			// Credential
			Credential = &bridge.Credential{
				Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]},
				Idemix: &idemix.Idemix{
					Curve: math.Curves[math.FP256BN_AMCL],
				},
			}
			CredentialSigner = &handlers.CredentialSigner{Credential: Credential}
			CredentialVerifier = &handlers.CredentialVerifier{Credential: Credential}
			credential, err = CredentialSigner.Sign(
				IssuerKey,
				credRequest,
				&types.IdemixCredentialSignerOpts{
					Attributes: []types.IdemixAttribute{
						{Type: types.IdemixBytesAttribute, Value: []byte{0}},
						{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
						{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
						{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
						{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2, 3}},
					},
				},
			)
			Expect(err).NotTo(HaveOccurred())

			// Revocation
			Revocation = &bridge.Revocation{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			RevocationKeyGen = &handlers.RevocationKeyGen{Revocation: Revocation}
			RevocationKey, err = RevocationKeyGen.KeyGen(&types.IdemixRevocationKeyGenOpts{})
			Expect(err).NotTo(HaveOccurred())
			RevocationPublicKey, err = RevocationKey.PublicKey()
			Expect(err).NotTo(HaveOccurred())

			// CRI
			CriSigner = &handlers.CriSigner{Revocation: Revocation}
			CriVerifier = &handlers.CriVerifier{Revocation: Revocation}
			cri, err = CriSigner.Sign(
				RevocationKey,
				nil,
				&types.IdemixCRISignerOpts{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("the environment is properly set", func() {
			// Verify CredRequest
			valid, err := CredentialRequestVerifier.Verify(
				IssuerPublicKey,
				credRequest,
				nil,
				&types.IdemixCredentialRequestSignerOpts{IssuerNonce: IssuerNonce},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// Verify Credential
			valid, err = CredentialVerifier.Verify(
				UserKey,
				credential,
				nil,
				&types.IdemixCredentialSignerOpts{
					IssuerPK: IssuerPublicKey,
					Attributes: []types.IdemixAttribute{
						{Type: types.IdemixBytesAttribute, Value: []byte{0}},
						{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
						{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
						{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
						{Type: types.IdemixHiddenAttribute},
					},
				},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// Verify CRI
			valid, err = CriVerifier.Verify(
				RevocationPublicKey,
				cri,
				nil,
				&types.IdemixCRISignerOpts{},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())
		})

		Context("the environment is not valid with the respect to different parameters", func() {

			It("invalid credential request nonce", func() {
				valid, err := CredentialRequestVerifier.Verify(
					IssuerPublicKey,
					credRequest,
					nil,
					&types.IdemixCredentialRequestSignerOpts{IssuerNonce: []byte("pine-apple-pine-apple-pine-apple")},
				)
				Expect(err).To(MatchError(fmt.Sprintf("invalid nonce, expected [%v], got [%v]", []byte("pine-apple-pine-apple-pine-apple"), IssuerNonce)))
				Expect(valid).NotTo(BeTrue())
			})

			It("invalid credential request nonce, too short", func() {
				valid, err := CredentialRequestVerifier.Verify(
					IssuerPublicKey,
					credRequest,
					nil,
					&types.IdemixCredentialRequestSignerOpts{IssuerNonce: []byte("pin-apple-pine-apple-pineapple")},
				)
				Expect(err).To(MatchError("invalid issuer nonce, expected length 32, got 30"))
				Expect(valid).NotTo(BeTrue())
			})

			It("invalid credential request", func() {
				if credRequest[4] == 0 {
					credRequest[4] = 1
				} else {
					credRequest[4] = 0
				}
				valid, err := CredentialRequestVerifier.Verify(
					IssuerPublicKey,
					credRequest,
					nil,
					&types.IdemixCredentialRequestSignerOpts{IssuerNonce: IssuerNonce},
				)
				Expect(err).To(MatchError("zero knowledge proof is invalid"))
				Expect(valid).NotTo(BeTrue())
			})

			It("invalid credential request in verifying credential", func() {
				if credRequest[4] == 0 {
					credRequest[4] = 1
				} else {
					credRequest[4] = 0
				}
				credential, err := CredentialSigner.Sign(
					IssuerKey,
					credRequest,
					&types.IdemixCredentialSignerOpts{
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2, 3}},
						},
					},
				)
				Expect(err).To(MatchError("failed creating new credential: zero knowledge proof is invalid"))
				Expect(credential).To(BeNil())
			})

			It("nil credential", func() {
				// Verify Credential
				valid, err := CredentialVerifier.Verify(
					UserKey,
					nil,
					nil,
					&types.IdemixCredentialSignerOpts{
						IssuerPK: IssuerPublicKey,
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixHiddenAttribute},
						},
					},
				)
				Expect(err).To(MatchError("invalid signature, it must not be empty"))
				Expect(valid).To(BeFalse())
			})

			It("malformed credential", func() {
				// Verify Credential
				valid, err := CredentialVerifier.Verify(
					UserKey,
					[]byte{0, 1, 2, 3, 4},
					nil,
					&types.IdemixCredentialSignerOpts{
						IssuerPK: IssuerPublicKey,
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixHiddenAttribute},
						},
					},
				)
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
				Expect(valid).To(BeFalse())
			})

			It("invalid credential", func() {
				// Invalidate credential by changing it in one position
				if credential[4] == 0 {
					credential[4] = 1
				} else {
					credential[4] = 0
				}

				// Verify Credential
				valid, err := CredentialVerifier.Verify(
					UserKey,
					credential,
					nil,
					&types.IdemixCredentialSignerOpts{
						IssuerPK: IssuerPublicKey,
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{2, 1, 0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixHiddenAttribute},
						},
					},
				)
				Expect(err).To(MatchError("credential is not cryptographically valid"))
				Expect(valid).To(BeFalse())
			})

			It("invalid byte array in credential", func() {
				// Verify Credential
				valid, err := CredentialVerifier.Verify(
					UserKey,
					credential,
					nil,
					&types.IdemixCredentialSignerOpts{
						IssuerPK: IssuerPublicKey,
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{1}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixIntAttribute, Value: 1},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixHiddenAttribute},
						},
					},
				)
				Expect(err).To(MatchError("credential does not contain the correct attribute value at position [0]"))
				Expect(valid).To(BeFalse())
			})

			It("invalid int in credential", func() {
				// Verify Credential
				valid, err := CredentialVerifier.Verify(
					UserKey,
					credential,
					nil,
					&types.IdemixCredentialSignerOpts{
						IssuerPK: IssuerPublicKey,
						Attributes: []types.IdemixAttribute{
							{Type: types.IdemixBytesAttribute, Value: []byte{0}},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1}},
							{Type: types.IdemixIntAttribute, Value: 2},
							{Type: types.IdemixBytesAttribute, Value: []byte{0, 1, 2}},
							{Type: types.IdemixHiddenAttribute},
						},
					},
				)
				Expect(err).To(MatchError("credential does not contain the correct attribute value at position [2]"))
				Expect(valid).To(BeFalse())

			})

			It("invalid cri", func() {
				// Verify CRI
				cri[8] = 0
				valid, err := CriVerifier.Verify(
					RevocationPublicKey,
					cri,
					nil,
					&types.IdemixCRISignerOpts{},
				)
				Expect(err).To(MatchError("EpochPKSig invalid"))
				Expect(valid).To(BeFalse())
			})
		})

		Describe("the environment is not properly set", func() {

			Describe("issuer", func() {
				Context("duplicate attribute", func() {
					It("returns an error", func() {
						AttributeNames = []string{"A", "A"}
						IssuerKey, err := IssuerKeyGen.KeyGen(&types.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: AttributeNames})
						Expect(err).To(MatchError("attribute A appears multiple times in AttributeNames"))
						Expect(IssuerKey).To(BeNil())
					})
				})
			})

		})

		Describe("producing a signature with a nym eid", func() {
			var (
				SignatureScheme types.SignatureScheme
				Signer          *handlers.Signer
				Verifier        *handlers.Verifier

				digest     []byte
				SignerOpts *types.IdemixSignerOpts
				signature  []byte
			)

			BeforeEach(func() {
				SignatureScheme = &bridge.SignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				Signer = &handlers.Signer{SignatureScheme: SignatureScheme}
				Verifier = &handlers.Verifier{SignatureScheme: SignatureScheme}

				digest = []byte("a digest")
				SignerOpts = &types.IdemixSignerOpts{
					Credential: credential,
					Nym:        NymKey,
					IssuerPK:   IssuerPublicKey,
					Attributes: []types.IdemixAttribute{
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
					},
					RhIndex:  2,
					EidIndex: 3,
					SigType:  types.EidNym,
				}

				var err error
				signature, err = Signer.Sign(UserKey, digest, SignerOpts)
				Expect(err).NotTo(HaveOccurred())
			})

			It("nym eid audit succeed", func() {
				valid, err := Verifier.AuditNymEid(IssuerPublicKey, signature, digest, &types.EidNymAuditOpts{
					EidIndex:              3,
					RNymEid:               SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID:          string([]byte{0, 1, 2}),
					AuditVerificationType: types.AuditExpectSignature,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = Verifier.AuditNymEid(IssuerPublicKey, SignerOpts.Metadata.EidNymAuditData.Nym.Bytes(), digest, &types.EidNymAuditOpts{
					EidIndex:              3,
					RNymEid:               SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID:          string([]byte{0, 1, 2}),
					AuditVerificationType: types.AuditExpectEidNym,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())

				valid, err = Verifier.AuditNymEid(IssuerPublicKey, SignerOpts.Metadata.EidNymAuditData.Nym.Bytes(), digest, &types.EidNymAuditOpts{
					EidIndex:              3,
					RNymEid:               SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID:          string([]byte{0, 1, 2}),
					AuditVerificationType: types.AuditExpectEidNymRhNym,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			It("fails because it gets the wrong type of signature", func() {
				valid, err := Verifier.AuditNymEid(IssuerPublicKey, []byte("To ride the storm, to an empire of the clouds"), digest, &types.EidNymAuditOpts{
					EidIndex:     3,
					RNymEid:      SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID: string([]byte{0, 1, 2}),
				})
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
				Expect(valid).To(BeFalse())
			})
		})

		Describe("producing a signature with a nym eid and a nym rh", func() {
			var (
				SignatureScheme types.SignatureScheme
				Signer          *handlers.Signer
				Verifier        *handlers.Verifier

				digest     []byte
				SignerOpts *types.IdemixSignerOpts
				signature  []byte
			)

			BeforeEach(func() {
				SignatureScheme = &bridge.SignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				Signer = &handlers.Signer{SignatureScheme: SignatureScheme}
				Verifier = &handlers.Verifier{SignatureScheme: SignatureScheme}

				digest = []byte("a digest")
				SignerOpts = &types.IdemixSignerOpts{
					Credential: credential,
					Nym:        NymKey,
					IssuerPK:   IssuerPublicKey,
					Attributes: []types.IdemixAttribute{
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
						{Type: types.IdemixHiddenAttribute},
					},
					RhIndex:  2,
					EidIndex: 3,
					SigType:  types.EidNymRhNym,
				}

				var err error
				signature, err = Signer.Sign(UserKey, digest, SignerOpts)
				Expect(err).NotTo(HaveOccurred())
			})

			It("nym eid  and rh audit succeed", func() {
				validNymEid, err := Verifier.AuditNymEid(IssuerPublicKey, signature, digest, &types.EidNymAuditOpts{
					EidIndex:     3,
					RNymEid:      SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID: string([]byte{0, 1, 2}),
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(validNymEid).To(BeTrue())

				validNymRh, err := Verifier.AuditNymRh(IssuerPublicKey, signature, digest, &types.RhNymAuditOpts{
					RhIndex:               2,
					RNymRh:                SignerOpts.Metadata.RhNymAuditData.Rand,
					RevocationHandle:      string([]byte{2, 1, 0}),
					AuditVerificationType: types.AuditExpectSignature,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(validNymRh).To(BeTrue())

				validNymRh, err = Verifier.AuditNymRh(IssuerPublicKey, SignerOpts.Metadata.RhNymAuditData.Nym.Bytes(), digest, &types.RhNymAuditOpts{
					RhIndex:               2,
					RNymRh:                SignerOpts.Metadata.RhNymAuditData.Rand,
					RevocationHandle:      string([]byte{2, 1, 0}),
					AuditVerificationType: types.AuditExpectEidNymRhNym,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(validNymRh).To(BeTrue())

				_, err = Verifier.AuditNymRh(IssuerPublicKey, SignerOpts.Metadata.RhNymAuditData.Nym.Bytes(), digest, &types.RhNymAuditOpts{
					RhIndex:               2,
					RNymRh:                SignerOpts.Metadata.RhNymAuditData.Rand,
					RevocationHandle:      string([]byte{2, 1, 0}),
					AuditVerificationType: types.AuditExpectEidNym,
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid audit type [1]"))
			})

			It("fails because it gets the wrong type of signature", func() {
				validNymEid, err := Verifier.AuditNymEid(IssuerPublicKey, []byte("To ride the storm, to an empire of the clouds"), digest, &types.EidNymAuditOpts{
					EidIndex:     3,
					RNymEid:      SignerOpts.Metadata.EidNymAuditData.Rand,
					EnrollmentID: string([]byte{0, 1, 2}),
				})
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
				Expect(validNymEid).To(BeFalse())

				validNymRh, err := Verifier.AuditNymRh(IssuerPublicKey, []byte("To ride the storm, to an empire of the clouds"), digest, &types.RhNymAuditOpts{
					RhIndex:          2,
					RNymRh:           SignerOpts.Metadata.RhNymAuditData.Rand,
					RevocationHandle: string([]byte{2, 1, 0}),
				})
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
				Expect(validNymRh).To(BeFalse())
			})
		})

		Describe("producing and verifying idemix signature with different sets of attributes", func() {
			var (
				SignatureScheme types.SignatureScheme
				Signer          *handlers.Signer
				Verifier        *handlers.Verifier
				digest          []byte
				signature       []byte

				SignAttributes   []types.IdemixAttribute
				VerifyAttributes []types.IdemixAttribute
				RhIndex          int
				Epoch            int
				errMessage       string
				validity         bool
			)

			BeforeEach(func() {
				SignatureScheme = &bridge.SignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				Signer = &handlers.Signer{SignatureScheme: SignatureScheme}
				Verifier = &handlers.Verifier{SignatureScheme: SignatureScheme}

				digest = []byte("a digest")
				RhIndex = 4
				Epoch = 0
				errMessage = ""
			})

			It("the signature with no disclosed attributes is valid", func() {
				validity = true
				SignAttributes = []types.IdemixAttribute{
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				VerifyAttributes = SignAttributes
			})

			It("the signature with disclosed attributes is valid", func() {
				validity = true
				SignAttributes = []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute, Value: []byte{0}},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				VerifyAttributes = SignAttributes
			})

			It("the signature with different disclosed attributes is not valid", func() {
				validity = false
				errMessage = "signature invalid: zero-knowledge proof is invalid"
				SignAttributes = []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixIntAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				VerifyAttributes = []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute, Value: []byte{1}},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixIntAttribute, Value: 1},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
			})

			It("the signature with different disclosed attributes is not valid", func() {
				validity = false
				errMessage = "signature invalid: zero-knowledge proof is invalid"
				SignAttributes = []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixIntAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				VerifyAttributes = []types.IdemixAttribute{
					{Type: types.IdemixBytesAttribute, Value: []byte{0}},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixIntAttribute, Value: 10},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
			})

			AfterEach(func() {
				var err error
				signature, err = Signer.Sign(
					UserKey,
					digest,
					&types.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    RhIndex,
						EidIndex:   2,
						Epoch:      Epoch,
						CRI:        cri,
					},
				)
				Expect(err).NotTo(HaveOccurred())

				valid, err := Verifier.Verify(
					IssuerPublicKey,
					signature,
					digest,
					&types.IdemixSignerOpts{
						RevocationPublicKey: RevocationPublicKey,
						Attributes:          VerifyAttributes,
						RhIndex:             RhIndex,
						EidIndex:            2,
						Epoch:               Epoch,
					},
				)

				if errMessage == "" {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(MatchError(errMessage))
				}
				Expect(valid).To(BeEquivalentTo(validity))
			})

		})

		Context("producing an idemix signature", func() {
			var (
				SignatureScheme types.SignatureScheme
				Signer          *handlers.Signer
				SignAttributes  []types.IdemixAttribute
				Verifier        *handlers.Verifier
			)

			BeforeEach(func() {
				SignatureScheme = &bridge.SignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				Signer = &handlers.Signer{SignatureScheme: SignatureScheme}
				SignAttributes = []types.IdemixAttribute{
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
					{Type: types.IdemixHiddenAttribute},
				}
				Verifier = &handlers.Verifier{SignatureScheme: SignatureScheme}
			})

			It("fails when the credential is malformed", func() {
				signature, err := Signer.Sign(
					UserKey,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						Credential: []byte{0, 1, 2, 3},
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    4,
						EidIndex:   2,
						Epoch:      0,
						CRI:        cri,
					},
				)
				Expect(err.Error()).To(ContainSubstring("cannot parse invalid wire-format data"))
				Expect(signature).To(BeNil())
			})

			It("fails when the cri is malformed", func() {
				signature, err := Signer.Sign(
					UserKey,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    4,
						EidIndex:   2,
						Epoch:      0,
						CRI:        []byte{0, 1, 2, 3, 4},
					},
				)
				Expect(err.Error()).To(ContainSubstring("failed unmarshalling credential revocation information: proto"))
				Expect(signature).To(BeNil())
			})

			It("fails when invalid rhIndex is passed", func() {
				signature, err := Signer.Sign(
					UserKey,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    5,
						EidIndex:   2,
						Epoch:      0,
						CRI:        cri,
					},
				)
				Expect(err).To(MatchError("failed creating new signature: cannot create idemix signature: received invalid input"))
				Expect(signature).To(BeNil())
			})

			It("fails when the credential is invalid", func() {
				if credential[4] != 0 {
					credential[4] = 0
				} else {
					credential[4] = 1
				}

				signature, err := Signer.Sign(
					UserKey,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						Credential: credential,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    4,
						EidIndex:   2,
						Epoch:      0,
						CRI:        cri,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(signature).NotTo(BeNil())

				valid, err := Verifier.Verify(
					IssuerPublicKey,
					signature,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						RevocationPublicKey: RevocationPublicKey,
						Attributes:          SignAttributes,
						RhIndex:             0,
						EidIndex:            2,
						Epoch:               0,
					},
				)
				Expect(err).To(MatchError("signature invalid: APrime = 1"))
				Expect(valid).To(BeFalse())

			})

			It("fails when the credential is nil", func() {
				credential[4] = 0
				signature, err := Signer.Sign(
					UserKey,
					[]byte("a message"),
					&types.IdemixSignerOpts{
						Credential: nil,
						Nym:        NymKey,
						IssuerPK:   IssuerPublicKey,
						Attributes: SignAttributes,
						RhIndex:    4,
						EidIndex:   2,
						Epoch:      0,
						CRI:        cri,
					},
				)
				Expect(err).To(MatchError(ContainSubstring("nil argument")))
				Expect(signature).To(BeNil())
			})
		})

		Describe("producing an idemix nym signature", func() {
			var (
				NymSignatureScheme *bridge.NymSignatureScheme
				NymSigner          *handlers.NymSigner
				NymVerifier        *handlers.NymVerifier
				digest             []byte
				signature          []byte
			)

			BeforeEach(func() {
				var err error
				NymSignatureScheme = &bridge.NymSignatureScheme{Idemix: &idemix.Idemix{Curve: math.Curves[math.FP256BN_AMCL]}, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				NymSigner = &handlers.NymSigner{NymSignatureScheme: NymSignatureScheme}
				NymVerifier = &handlers.NymVerifier{NymSignatureScheme: NymSignatureScheme}

				digest = []byte("a digest")

				signature, err = NymSigner.Sign(
					UserKey,
					digest,
					&types.IdemixNymSignerOpts{
						Nym:      NymKey,
						IssuerPK: IssuerPublicKey,
					},
				)
				Expect(err).NotTo(HaveOccurred())
			})

			It("the signature is valid", func() {
				valid, err := NymVerifier.Verify(
					NymPublicKey,
					signature,
					digest,
					&types.IdemixNymSignerOpts{
						IssuerPK: IssuerPublicKey,
					},
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(valid).To(BeTrue())
			})

			Context("the signature is malformed", func() {
				var nymSignature *idemix.NymSignature

				BeforeEach(func() {
					nymSignature = &idemix.NymSignature{}
					err := proto.Unmarshal(signature, nymSignature)
					Expect(err).NotTo(HaveOccurred())
				})

				marshalAndVerify := func(nymSignature *idemix.NymSignature) (bool, error) {
					signature, err := proto.Marshal(nymSignature)
					Expect(err).NotTo(HaveOccurred())

					return NymVerifier.Verify(
						NymPublicKey,
						signature,
						digest,
						&types.IdemixNymSignerOpts{
							IssuerPK: IssuerPublicKey,
						},
					)
				}

				Context("cause nonce does not encode a proper Big", func() {
					It("returns an error", func() {
						nymSignature.Nonce = []byte{0, 1, 2, 3, 4}
						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause nonce is nil", func() {
					It("returns an error", func() {
						nymSignature.Nonce = nil
						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause nonce encode a different thing", func() {
					It("returns an error", func() {
						var err error
						nymSignature.Nonce = math.Curves[math.FP256BN_AMCL].NewZrFromInt(1).Bytes()

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError("pseudonym signature invalid: zero-knowledge proof is invalid"))
					})
				})

				Context("cause ProofC is not encoded properly", func() {
					It("returns an error", func() {
						nymSignature.ProofC = []byte{0, 1, 2, 3, 4}

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofC is nil", func() {
					It("returns an error", func() {
						nymSignature.ProofC = nil

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofC encode a different thing", func() {
					It("returns an error", func() {
						var err error
						nymSignature.Nonce = math.Curves[math.FP256BN_AMCL].NewZrFromInt(1).Bytes()

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError("pseudonym signature invalid: zero-knowledge proof is invalid"))
					})
				})

				Context("cause ProofSRNym is not encoded properly", func() {
					It("returns an error", func() {
						nymSignature.ProofSRNym = []byte{0, 1, 2, 3, 4}

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofSRNym is nil", func() {
					It("returns an error", func() {
						nymSignature.ProofSRNym = nil
						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofSRNym encode a different thing", func() {
					It("returns an error", func() {
						var err error
						nymSignature.Nonce = math.Curves[math.FP256BN_AMCL].NewZrFromInt(1).Bytes()

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError("pseudonym signature invalid: zero-knowledge proof is invalid"))
					})
				})

				Context("cause ProofSSk is not encoded properly", func() {
					It("returns an error", func() {
						nymSignature.ProofSSk = []byte{0, 1, 2, 3, 4}

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofSSk is nil", func() {
					It("returns an error", func() {
						nymSignature.ProofSSk = nil

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError(ContainSubstring("pseudonym signature invalid: zero-knowledge proof is invalid")))
					})
				})

				Context("cause ProofSSk encode a different thing", func() {
					It("returns an error", func() {
						var err error
						nymSignature.Nonce = math.Curves[math.FP256BN_AMCL].NewZrFromInt(1).Bytes()

						valid, err := marshalAndVerify(nymSignature)
						Expect(valid).To(BeFalse())
						Expect(err).To(MatchError("pseudonym signature invalid: zero-knowledge proof is invalid"))
					})
				})
			})
		})

		Context("importing nym key", func() {
			var (
				NymPublicKeyImporter *handlers.NymPublicKeyImporter
			)

			BeforeEach(func() {
				NymPublicKeyImporter = &handlers.NymPublicKeyImporter{User: User, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
			})

			It("nym key import is successful", func() {
				// User Nym Key
				NymKeyDerivation = &handlers.NymKeyDerivation{User: User, Translator: &amcl.Fp256bn{C: math.Curves[math.FP256BN_AMCL]}}
				NymKey, err := NymKeyDerivation.KeyDeriv(UserKey, &types.IdemixNymKeyDerivationOpts{IssuerPK: IssuerPublicKey})
				Expect(err).NotTo(HaveOccurred())
				NymPublicKey, err = NymKey.PublicKey()
				Expect(err).NotTo(HaveOccurred())

				raw, err := NymPublicKey.Bytes()
				Expect(err).NotTo(HaveOccurred())
				Expect(raw).NotTo(BeEmpty())

				k, err := NymPublicKeyImporter.KeyImport(raw, nil)
				Expect(err).NotTo(HaveOccurred())
				raw2, err := k.Bytes()
				Expect(err).NotTo(HaveOccurred())
				Expect(raw2).To(BeEquivalentTo(raw))
			})
		})
	})
})
