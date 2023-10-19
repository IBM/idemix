/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries_test

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	bbs12381g2pub.SetCurve(math.Curves[math.FP256BN_AMCL_MIRACL])

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
	issuer := &aries.Issuer{}
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

	eid := bbs12381g2pub.FrFromOKM([]byte(signerConfig.EnrollmentId))

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
	bbs12381g2pub.SetCurve(math.Curves[math.FP256BN_AMCL_MIRACL])

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
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

	pubKey, privKey, err := generateKeyPairRandom()
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
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou)),
		},
		{
			Idx: 2,
			FR:  bbs12381g2pub.FrFromOKM([]byte(role)),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid)),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh)),
		},
	}, messagesCount, B, privKeyBytes)
	assert.NoError(t, err)

	sigBytes, err := aries.UnblindSign(sig_, r, curve)
	assert.NoError(t, err)

	sig, err := bbs12381g2pub.ParseSignature(sigBytes)
	assert.NoError(t, err)

	messagesFr := []*bbs12381g2pub.SignatureMessage{
		{
			Idx: 0,
			FR:  sc.Uid_sk,
		},
		{
			Idx: 1,
			FR:  bbs12381g2pub.FrFromOKM([]byte(ou)),
		},
		{
			Idx: 2,
			FR:  bbs12381g2pub.FrFromOKM([]byte(role)),
		},
		{
			Idx: 3,
			FR:  bbs12381g2pub.FrFromOKM([]byte(eid)),
		},
		{
			Idx: 4,
			FR:  bbs12381g2pub.FrFromOKM([]byte(rh)),
		},
	}

	err = sig.Verify(messagesFr, pkwg)
	assert.NoError(t, err)

	/*********************************************************************/
	/*********************************************************************/

	pok_, err := bbs12381g2pub.NewPoKOfSignature(sig, messagesFr, []int{1, 2}, pkwg)
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

	pok_, err = bbs12381g2pub.NewPoKOfSignatureExt(sig, messagesFr[1:], []int{0, 1}, pkwg, B, r, C)
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
	pokVC2, secrets2 := newModifiedVC2Signature(d, r3, pkwg, sPrime.Minus(r), messagesFr[1:], revealedMessages)

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
) (*bbs12381g2pub.ProverCommittedG1, []*math.Zr) {

	messagesCount := len(messages)
	committing2 := bbs12381g2pub.NewProverCommittingG1()
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
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

	seed, err := hex.DecodeString("62189E8BFAC71BA9894ACEC9FCE45FE7")
	assert.NoError(t, err)

	r := sc.PRF(seed, sc.PRF_K1)

	rExpected, err := hex.DecodeString("87e904087f9c5e975a0334534db8d5ed1ba4d75df1ba61349817ce0469168488")
	assert.NoError(t, err)
	assert.Equal(t, rExpected, r.Bytes())
}

/*

CARD CONFIGURATION:

80230000c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002
80240000c304f474278832b9840a14b158b2c322bf668d8a85b4830a5277799f828b7f1672d56d5d973a48b09f95f600a8deb560c5c84e3414411d816437a5da6ad395cd466504b8d4256d91a065f1a17ed5a7a166e55e299aee8e4dad370df5fa84c4d447b138dda55ee816f2b9fc9223c14fa814be007514ecbade7f70e6f97f666f5a0471c604fd3cfacec96d76af0506fb44237c2b5f8b2536e73c8b571c4451d0f9c96aae66cf5554a92a84d23e6f2cbca4c9ab1ac21d4399dfc33af983d62c454d8cc05082
80250000202e8f42b0b247ddbca1a7296b098114cb83b76d00c53d98fad980f40769c2c761
8026000020b05f96d5582f87fc8584fa7eb11d4018012e59adf945cd8034ebcb4ee41b0586
80270000204669650c993c43ef45742c3aa8aeb842358abd275e6a945d680d40474f5f16c7

802900004084535c86a4bcb7b6931d36550483442726ea652482be9c538e998c24d4b9c179aa19147a8d3a7954e435253415b739dac70a8a9f2451969e1d4b723313c84f3b
803000002082955154973956baf250d9ad7e070264cee0a1c735eafb617a143104dd36939b
*/

func TestVerifyFromCard(t *testing.T) {
	sc, _ := getSmartcardFromFile("/home/aso/tmp/sc/IssuerPublicKey", "/home/aso/tmp/sc/SignerConfig", t)
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

	_, tau0 := sc.NymEid()

	fmt.Println(hex.EncodeToString(tau0.Bytes()))

	proof, err := hex.DecodeString("323B171209E4E81D636786D0F71383E3044F154CA1AB2DD3DA28BC4BF86FAFC30C23CDFBF1B9769AF064DC85500D291F4E11FCCA18174F8B49242F9464781A63184DB5D0FA94B500E92482D11490DFB3AA042761230A5D36DD0CB6D838D3A48778FDEBD1B7342F9D0405E6FA60393AF6CDD8685FA812D7273F66BE8CAC680CB8FB3545B45CC2A1CE81B480E5CDA729A03E4B447074A3E896C13493B96BF54B55F0E715581673E9FC8CC9FF3353C42A3DCF4DF89E8159C2329C8CD9D2C92D596F802A4D7CFF46724FABCDD7E9C0B41D16D9A49000")
	assert.NoError(t, err)

	nonce, err := hex.DecodeString("82955154973956baf250d9ad7e070264cee0a1c735eafb617a143104dd36939b")
	assert.NoError(t, err)

	tau, err := hex.DecodeString("84535c86a4bcb7b6931d36550483442726ea652482be9c538e998c24d4b9c179aa19147a8d3a7954e435253415b739dac70a8a9f2451969e1d4b723313c84f3b")
	assert.NoError(t, err)

	err = sc.NymVerify(proof, tau0, append(append([]byte{}, tau...), nonce...))
	assert.NoError(t, err)
}

func TestSmartcard(t *testing.T) {
	sc, curve := getSmartcard(t)
	defer func() {
		// reset the curve to the one other tests use
		bbs12381g2pub.SetCurve(math.Curves[math.BLS12_381_BBS])
	}()

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
