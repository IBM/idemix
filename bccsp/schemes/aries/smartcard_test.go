/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

const (
	// AttributeNameOU is the attribute name of the Organization Unit attribute
	AttributeNameOU = "OU"

	// AttributeNameRole is the attribute name of the Role attribute
	AttributeNameRole = "Role"

	// AttributeNameEnrollmentId is the attribute name of the Enrollment ID attribute
	AttributeNameEnrollmentId = "EnrollmentID"

	// AttributeNameRevocationHandle is the attribute name of the revocation handle attribute
	AttributeNameRevocationHandle = "RevocationHandle"
)

var AttributeNames = []string{AttributeNameOU, AttributeNameRole, AttributeNameEnrollmentId, AttributeNameRevocationHandle}

func getSmartcardFromFile(ipkFileName, signerFileName string, t *testing.T) (*aries.Smartcard, *math.Curve) {
	c := math.Curves[math.FP256BN_AMCL_MIRACL]

	rng, err := c.Rand()
	assert.NoError(t, err)

	k0, err := hex.DecodeString("4669650c993c43ef45742c3aa8aeb842")
	assert.NoError(t, err)
	k1, err := hex.DecodeString("358abd275e6a945d680d40474f5f16c7")
	assert.NoError(t, err)

	ciph0, err := aes.NewCipher(k0)
	assert.NoError(t, err)
	ciph1, err := aes.NewCipher(k1)
	assert.NoError(t, err)

	ipkBytes, err := os.ReadFile(ipkFileName)
	assert.NoError(t, err)
	issuer := &aries.Issuer{c}
	_ipk, err := issuer.NewPublicKeyFromBytes(ipkBytes, AttributeNames)
	assert.NoError(t, err)
	ipk := _ipk.(*aries.IssuerPublicKey)

	h0 := ipk.PKwG.H0
	h1 := ipk.PKwG.H[0]
	h2 := ipk.PKwG.H[3]

	signerBytes, err := os.ReadFile(signerFileName)
	assert.NoError(t, err)
	signerConfig := &IdemixMSPSignerConfig{}
	err = proto.Unmarshal(signerBytes, signerConfig)
	assert.NoError(t, err)

	eid := bbs12381g2pub.FrFromOKM([]byte(signerConfig.EnrollmentId), c)

	sk := c.NewZrFromBytes(signerConfig.Sk)

	return &aries.Smartcard{
		H0:     h0,
		H1:     h1,
		H2:     h2,
		Uid_sk: sk,
		EID:    eid,
		PRF_K0: ciph0,
		PRF_K1: ciph1,
		Curve:  c,
		Rng:    rng,
	}, c
}

func getSmartcard(t *testing.T) (*aries.Smartcard, *math.Curve) {
	c := math.Curves[math.FP256BN_AMCL_MIRACL]

	rng, err := c.Rand()
	assert.NoError(t, err)

	k0, err := hex.DecodeString("4669650c993c43ef45742c3aa8aeb842")
	assert.NoError(t, err)
	k1, err := hex.DecodeString("358abd275e6a945d680d40474f5f16c7")
	assert.NoError(t, err)

	ciph0, err := aes.NewCipher(k0)
	assert.NoError(t, err)
	ciph1, err := aes.NewCipher(k1)
	assert.NoError(t, err)

	h0Bytes, err := hex.DecodeString("0441c48875b5045400ce6bb4ce5b9c733f6d539a89f1ec2c24e0e04f56932c52ffd918f0679996b017363c591df413e1ac0be63e919defd6edc0686d41b1fcd68d")
	assert.NoError(t, err)
	h0, err := c.NewG1FromBytes(h0Bytes)
	assert.NoError(t, err)

	h1Bytes, err := hex.DecodeString("041e304080e9afd0d04317d12b5cb058cd4f322a1cddb71e64a47528353d51f7a8324fce4698dff52cd8d4c7dd2c8c94c6fba8ce12493d182e4d849106dc5c46de")
	assert.NoError(t, err)
	h1, err := c.NewG1FromBytes(h1Bytes)
	assert.NoError(t, err)

	h2Bytes, err := hex.DecodeString("04196c48c6d0249de961b97433a577da537c341ad0ea0cde4dfa40ef6bab9b59f274a07a3665518401119957a52a32a18256d7215e4f1d0ce6c9e2646d939c07f9")
	assert.NoError(t, err)
	h2, err := c.NewG1FromBytes(h2Bytes)
	assert.NoError(t, err)

	eidBytes, err := hex.DecodeString("003522e297a5f7db7521e23d9f9b87378126acd80429cf4ec07344f06bd9f7d5")
	assert.NoError(t, err)
	eid := c.NewZrFromBytes(eidBytes)

	skBytes, err := hex.DecodeString("00f022e297a5f7db7521e23d9f9b87378182acd80429cf4ec07344f06bd9f7d5")
	assert.NoError(t, err)
	sk := c.NewZrFromBytes(skBytes)

	return &aries.Smartcard{
		H0:     h0,
		H1:     h1,
		H2:     h2,
		Uid_sk: sk,
		EID:    eid,
		PRF_K0: ciph0,
		PRF_K1: ciph1,
		Curve:  c,
		Rng:    rng,
	}, c
}

func TestAll(t *testing.T) {
	sc, curve := getSmartcard(t)

	pubKey, privKey, err := generateKeyPairRandom(curve)
	assert.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	assert.NoError(t, err)

	pkwg, err := pubKey.ToPublicKeyWithGenerators(5)
	assert.NoError(t, err)

	sc.H0 = pkwg.H0
	sc.H1 = pkwg.H[0]
	sc.H2 = pkwg.H[3]

	proofBytes, err := sc.NymSign(nil)
	assert.NoError(t, err)

	seed := proofBytes[0:16]
	r := sc.PRF(seed, sc.PRF_K1)

	B, err := sc.Curve.NewG1FromBytes(proofBytes[16 : 16+curve.G1ByteSize])
	assert.NoError(t, err)

	ou, role, eid, rh := "ou", "role", "eid", "rh"
	messagesCount := 5 // includes the sk

	sig_, err := aries.BlindSign([]*bbs12381g2pub.SignatureMessage{
		{
			Idx: 1,
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou), curve),
		},
		{
			Idx: 2,
			FR:  bbs12381g2pub.FrFromOKM([]byte(role), curve),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid), curve),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh), curve),
		},
	}, messagesCount, B, privKeyBytes, curve)
	assert.NoError(t, err)

	sigBytes, err := aries.UnblindSign(sig_, r, curve)
	assert.NoError(t, err)

	sig, err := bbs12381g2pub.NewBBSLib(curve).ParseSignature(sigBytes)
	assert.NoError(t, err)

	messagesFr := []*bbs12381g2pub.SignatureMessage{
		{
			Idx: 0,
			FR:  sc.Uid_sk,
		},
		{
			Idx: 1,
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou), curve),
		},
		{
			Idx: 2,
			FR:  bbs12381g2pub.FrFromOKM([]byte(role), curve),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid), curve),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh), curve),
		},
	}

	err = sig.Verify(messagesFr, pkwg)
	assert.NoError(t, err)

	/*********************************************************************/
	/*********************************************************************/

	pok_, err := bbs12381g2pub.NewBBSLib(curve).NewPoKOfSignature(sig, messagesFr, []int{1, 2}, pkwg)
	assert.NoError(t, err)

	c := curve.NewRandomZr(rand.Reader)

	pok := pok_.GenerateProof(c)

	err = pok.Verify(c, pkwg, map[int]*bbs12381g2pub.SignatureMessage{1: {}, 2: {}}, []*bbs12381g2pub.SignatureMessage{messagesFr[1], messagesFr[2]})
	assert.NoError(t, err)

	/*********************************************************************/

	/*********************************************************************/

	C := B.Copy()
	C.Sub(sc.H0.Mul(r))
	assert.True(t, C.Equals(sc.H1.Mul(sc.Uid_sk)))

	pok_, err = bbs12381g2pub.NewBBSLib(curve).NewPoKOfSignatureExt(sig, messagesFr[1:], []int{0, 1}, pkwg, B, r, C)
	assert.NoError(t, err)

	c = curve.NewRandomZr(rand.Reader)

	pok = pok_.GenerateProof(c)

	err = pok.VerifyExt(c, pkwg, map[int]*bbs12381g2pub.SignatureMessage{1: {}, 2: {}}, []*bbs12381g2pub.SignatureMessage{messagesFr[1], messagesFr[2]}, B)
	assert.NoError(t, err)

	/*********************************************************************/

	/*********************************************************************/

	r1, r2 := curve.NewRandomZr(rand.Reader), curve.NewRandomZr(rand.Reader)

	b := computeB(sig.S, messagesFr, pkwg, curve)
	aPrime := sig.A.Mul(r1)

	aBarDenom := aPrime.Mul(sig.E)

	aBar := b.Mul(r1)
	aBar.Sub(aBarDenom)

	r2D := r2.Copy()
	r2D.Neg()

	commitmentBasesCount := 2
	cb := bbs12381g2pub.NewCommitmentBuilder(commitmentBasesCount)
	cb.Add(b, r1)
	cb.Add(pkwg.H0, r2D)

	d := cb.Build()
	r3 := r1.Copy()
	r3.InvModP(curve.GroupOrder)

	sPrime := r2.Mul(r3)
	sPrime.Neg()
	sPrime = sPrime.Plus(sig.S)

	/***********************************/
	/*      custom validation here     */
	/***********************************/

	lhs := curve.GenG1.Mul(curve.NewZrFromInt(1))
	lhs.Add(pkwg.H[1].Mul(messagesFr[1].FR))
	lhs.Add(pkwg.H[2].Mul(messagesFr[2].FR))

	rhs := d.Mul(r3)
	rhs.Add(pkwg.H0.Mul(curve.NewZrFromInt(0).Minus(sPrime)))
	rhs.Add(pkwg.H[0].Mul(curve.NewZrFromInt(0).Minus(messagesFr[0].FR)))
	rhs.Add(pkwg.H[3].Mul(curve.NewZrFromInt(0).Minus(messagesFr[3].FR)))
	rhs.Add(pkwg.H[4].Mul(curve.NewZrFromInt(0).Minus(messagesFr[4].FR)))

	assert.True(t, lhs.Equals(rhs))

	/***********************************/
	/*      custom validation here     */
	/***********************************/

	/***********************************/
	/*      custom validation here     */
	/***********************************/

	lhs = curve.GenG1.Mul(curve.NewZrFromInt(1))
	lhs.Add(pkwg.H[1].Mul(messagesFr[1].FR))
	lhs.Add(pkwg.H[2].Mul(messagesFr[2].FR))
	lhs.Add(B)

	rhs = d.Mul(r3)
	rhs.Add(pkwg.H0.Mul(curve.NewZrFromInt(0).Minus(sPrime.Minus(r))))
	// rhs.Add(pkwg.H[0].Mul(curve.NewZrFromInt(0).Minus(messagesFr[0].FR)))
	rhs.Add(pkwg.H[3].Mul(curve.NewZrFromInt(0).Minus(messagesFr[3].FR)))
	rhs.Add(pkwg.H[4].Mul(curve.NewZrFromInt(0).Minus(messagesFr[4].FR)))

	assert.True(t, lhs.Equals(rhs))

	/***********************************/
	/*      custom validation here     */
	/***********************************/

	revealedMessages := make(map[int]*bbs12381g2pub.SignatureMessage, 2)
	revealedMessages[1] = messagesFr[1]
	revealedMessages[2] = messagesFr[2]

	// DELTA: we pass sPrime.Minus(r) as sPrime and drop the first message in messagesFr
	pokVC2, secrets2 := newModifiedVC2Signature(d, r3, pkwg, sPrime.Minus(r), messagesFr[1:], revealedMessages, curve)

	/*************/

	c = curve.NewRandomZr(rand.Reader)
	pi := pokVC2.GenerateProof(c, secrets2)

	/*************/

	revealedMessagesCount := len(revealedMessages)

	basesVC2 := make([]*math.G1, 0, 2+messagesCount-revealedMessagesCount)
	basesVC2 = append(basesVC2, d, pkwg.H0)

	basesDisclosed := make([]*math.G1, 0, 1+revealedMessagesCount)
	exponents := make([]*math.Zr, 0, 1+revealedMessagesCount)

	basesDisclosed = append(basesDisclosed, curve.GenG1)
	exponents = append(exponents, curve.NewZrFromInt(1))

	for i := range pkwg.H {
		// DELTA: we skip pkwg.H[0]
		if i == 0 {
			continue
		}

		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pkwg.H[i])
			exponents = append(exponents, messagesFr[i].FR)
		} else {
			basesVC2 = append(basesVC2, pkwg.H[i])
		}
	}

	// DELTA: we add B
	basesDisclosed = append(basesDisclosed, B)
	exponents = append(exponents, curve.NewZrFromInt(1))

	// TODO: expose 0
	pr := curve.GenG1.Copy()
	pr.Sub(curve.GenG1)

	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := b.Mul(s)
		pr.Add(g)
	}

	assert.True(t, lhs.Equals(pr))

	pr.Neg()

	err = pi.Verify(basesVC2, pr, c)
	assert.NoError(t, err)
}

func computeB(s *math.Zr, messages []*bbs12381g2pub.SignatureMessage, key *bbs12381g2pub.PublicKeyWithGenerators, curve *math.Curve) *math.G1 {
	const basesOffset = 2

	cb := bbs12381g2pub.NewCommitmentBuilder(len(messages) + basesOffset)

	cb.Add(curve.GenG1, curve.NewZrFromInt(1))
	cb.Add(key.H0, s)

	for i := 0; i < len(messages); i++ {
		cb.Add(key.H[messages[i].Idx], messages[i].FR)
	}

	return cb.Build()
}

func newModifiedVC2Signature(
	d *math.G1,
	r3 *math.Zr,
	pubKey *bbs12381g2pub.PublicKeyWithGenerators,
	sPrime *math.Zr,
	messages []*bbs12381g2pub.SignatureMessage,
	revealedMessages map[int]*bbs12381g2pub.SignatureMessage,
	curve *math.Curve,
) (*bbs12381g2pub.ProverCommittedG1, []*math.Zr) {

	messagesCount := len(messages)
	committing2 := bbs12381g2pub.NewBBSLib(curve).NewProverCommittingG1()
	baseSecretsCount := 2
	secrets2 := make([]*math.Zr, 0, baseSecretsCount+messagesCount)

	committing2.Commit(d)

	r3D := r3.Copy()
	r3D.Neg()

	secrets2 = append(secrets2, r3D)

	committing2.Commit(pubKey.H0)

	secrets2 = append(secrets2, sPrime)

	for i := 0; i < messagesCount; i++ {
		if _, ok := revealedMessages[messages[i].Idx]; ok {
			continue
		}

		committing2.Commit(pubKey.H[messages[i].Idx])

		sourceFR := messages[i].FR
		hiddenFRCopy := sourceFR.Copy()

		secrets2 = append(secrets2, hiddenFRCopy)
	}

	pokVC2 := committing2.Finish()

	return pokVC2, secrets2
}

func TestPRF(t *testing.T) {
	sc, _ := getSmartcard(t)

	seed, err := hex.DecodeString("62189E8BFAC71BA9894ACEC9FCE45FE7")
	assert.NoError(t, err)

	r := sc.PRF(seed, sc.PRF_K1)

	rExpected, err := hex.DecodeString("87e904087f9c5e975a0334534db8d5ed1ba4d75df1ba61349817ce0469168488")
	assert.NoError(t, err)
	assert.Equal(t, rExpected, r.Bytes())
}

func TestVerifyFromCard(t *testing.T) {
	sc, _ := getSmartcard(t)

	_, tau0 := sc.NymEid()

	proof, err := hex.DecodeString("751A2CB0ECE86ACCCA5846E578DA045E04C10FE2D02FED20CED167BB12C94B52C82C3269AB423BC977B1052D9A891E78321BCDB9AAD44A79922611DEA4832F1DD310F18FAA24B01A273C6BCFE2044FF11804B00567E220E1E8C0E76E2EA7DBAEE8F9ABCF8B7CACB562086D827345A02D76F83BB7DFD533745D57E4AD618D4CE8DF031F437B6220EE97C19B78B2DBFCCBFC69C0733191905FC5550BCC4D0F5DCE10780558E99DA037155CCE0452EC298390D186DAC6BA386550952467A45C366175E8A5465B8FBD30AC64885630309F9E73BD9000")
	assert.NoError(t, err)

	nonce, err := hex.DecodeString("00e7a59abb5692a91b3e41d483af1279216b0f855ff9f688335a7d2cd92f877d")
	assert.NoError(t, err)

	tau, err := hex.DecodeString("a622f6dc87e125705980c7185f2b5b7766ec3cb6a21d78108e01865bf02ea9ddc449793856bf9a7ea7c3e6ce39cae9c4c3d5c39a1e37e436d60ccf2cdd8339ea")
	assert.NoError(t, err)

	err = sc.NymVerify(proof, tau0, append(append([]byte{}, tau...), nonce...))
	assert.NoError(t, err)
}

func TestSmartcard(t *testing.T) {
	sc, curve := getSmartcard(t)

	_, nymEid := sc.NymEid()

	tau0Expected, err := hex.DecodeString("049a82e7816bc68a24ffb9331158c5112473f60cb3c738f8bcf9eca9b2a914d1cc519e3b3c1792cc1447a7c5c1edb6d8ae0b40c49dec4b6f40ccfbc39df31e01cd")
	assert.NoError(t, err)
	assert.Equal(t, tau0Expected, nymEid.Bytes())

	nonce := []byte("nonce")
	tau := []byte("tau")

	pi, err := sc.NymSign(append(append([]byte{}, tau...), nonce...))
	assert.NoError(t, err)
	assert.Len(t, pi, 16+2*curve.G1ByteSize+2*curve.ScalarByteSize)

	err = sc.NymVerify(pi, nymEid, append(append([]byte{}, tau...), nonce...))
	assert.NoError(t, err)
}
