/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
)

// Smartcard is an implementation of an idemix joint signature where one of
// the attributes is only known to a smartcard. This structure plays a dual
// role:
//  1. emulation of the smartcard to be able to test verification without
//     external hardware. (`PRF`, `NymEid`, `NymSign` methods). These
//     functions are never used in production.
//  2. implementation of the verification of signatures produced by a
//     real smartcard (`NymVerify` method). This function is used in production.
type Smartcard struct {
	H0, H1, H2     *math.G1
	Uid_sk, EID    *math.Zr
	PRF_K0, PRF_K1 cipher.Block
	Curve          *math.Curve
	Rng            io.Reader

	ctr int16
}

func (sc *Smartcard) PRF(input []byte, K cipher.Block) *math.Zr {
	bytes := make([]byte, sc.Curve.ScalarByteSize)

	PRF := cipher.NewCBCEncrypter(K, make([]byte, K.BlockSize())) //nolint:gosec // deterministic PRF construction, not encryption; zero IV is intentional
	PRF.CryptBlocks(bytes, input)
	PRF.CryptBlocks(bytes[sc.PRF_K1.BlockSize():], input)

	return sc.Curve.NewZrFromBytes(bytes)
}

func (sc *Smartcard) getNymEid() (*math.Zr, *math.G1) {
	// set PRNG_input from counter
	PRNG_input := make([]byte, 16)
	PRNG_input[0] = byte(sc.ctr & 0xff)
	PRNG_input[1] = byte((sc.ctr >> 8) & 0xff)

	// sample random s
	s := sc.PRF(PRNG_input, sc.PRF_K0)

	// tau0 = h0^s h2^id
	tau0 := sc.H0.Mul2(s, sc.H2, sc.EID)

	return s, tau0
}

func (sc *Smartcard) NymEid() (*math.Zr, *math.G1) {
	// increment counter
	sc.ctr++

	return sc.getNymEid()
}

func (sc *Smartcard) NymSign(msg []byte) ([]byte, error) {
	// set PRNG_input from random
	PRNG_input := make([]byte, 16)
	_, err := rand.Read(PRNG_input)
	if err != nil {
		return nil, fmt.Errorf("rand.Read returned error [%w]", err)
	}

	// sample random r1
	r1 := sc.PRF(PRNG_input, sc.PRF_K1)

	// B = h0^r1 h1^uid
	B := sc.H0.Mul2(r1, sc.H1, sc.Uid_sk)

	x_tilde, r_tilde := sc.Curve.NewRandomZr(sc.Rng), sc.Curve.NewRandomZr(sc.Rng)

	// B_ = h0^r~ h1^x~
	B_ := sc.H0.Mul2(r_tilde, sc.H1, x_tilde)

	_, tau0 := sc.getNymEid()

	var challengeBytes []byte
	challengeBytes = append(challengeBytes, sc.H0.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, sc.H1.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, sc.H2.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, B.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, B_.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, tau0.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, msg...)

	h := sha256.Sum256(challengeBytes)

	c := sc.Curve.NewZrFromBytes(h[:])

	/*
		expected return:
			PRNG_input 	(16)
			B			(65)
			B_			(65)
			x_hat		(32)
			r_hat		(32)
	*/

	resp := make([]byte, 0)
	resp = append(resp, PRNG_input...)
	resp = append(resp, B.Bytes()...)
	resp = append(resp, B_.Bytes()...)
	resp = append(resp, x_tilde.Plus(c.Mul(sc.Uid_sk)).Bytes()...)
	resp = append(resp, r_tilde.Plus(c.Mul(r1)).Bytes()...)

	return resp, nil
}

// smartcardEidIndex is the index in the issuer public key generators (H) of the
// enrollment ID base used by the smartcard (H[0] is the user secret key base).
const smartcardEidIndex = 3

func (sc *Smartcard) NymVerify(proofBytes []byte, nymEid *math.G1, msg []byte) error {
	if sc.Curve == nil || sc.H0 == nil || sc.H1 == nil || sc.H2 == nil {
		return errors.New("invalid smartcard verifier: missing parameters")
	}

	if nymEid == nil {
		return errors.New("invalid nym eid: nil")
	}

	expectedLen := 16 + 2*sc.Curve.G1ByteSize + 2*sc.Curve.ScalarByteSize
	// proofs produced by physical cards carry the trailing APDU status word
	// 0x9000 (success), which is the only trailer accepted.
	switch len(proofBytes) {
	case expectedLen:
	case expectedLen + 2:
		if proofBytes[expectedLen] != 0x90 || proofBytes[expectedLen+1] != 0x00 {
			return fmt.Errorf("invalid proof: unexpected status word %x", proofBytes[expectedLen:])
		}
	default:
		return fmt.Errorf("invalid proof length %d, expected %d or %d", len(proofBytes), expectedLen, expectedLen+2)
	}

	offset := 16

	B, err := sc.Curve.NewG1FromBytes(proofBytes[offset : offset+sc.Curve.G1ByteSize])
	if err != nil {
		return fmt.Errorf("could not parse B, err %w", err)
	}
	offset += sc.Curve.G1ByteSize

	B_, err := sc.Curve.NewG1FromBytes(proofBytes[offset : offset+sc.Curve.G1ByteSize])
	if err != nil {
		return fmt.Errorf("could not parse B_, err %w", err)
	}
	offset += sc.Curve.G1ByteSize

	x_hat, err := sc.Curve.NewZrFromBytesCanonical(proofBytes[offset : offset+sc.Curve.ScalarByteSize])
	if err != nil {
		return fmt.Errorf("could not parse x_hat, err %w", err)
	}
	offset += sc.Curve.ScalarByteSize

	r_hat, err := sc.Curve.NewZrFromBytesCanonical(proofBytes[offset : offset+sc.Curve.ScalarByteSize])
	if err != nil {
		return fmt.Errorf("could not parse r_hat, err %w", err)
	}

	var challengeBytes []byte
	challengeBytes = append(challengeBytes, sc.H0.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, sc.H1.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, sc.H2.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, B.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, B_.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, nymEid.Bytes()[1:]...)
	challengeBytes = append(challengeBytes, msg...)

	h := sha256.Sum256(challengeBytes)

	c := sc.Curve.NewZrFromBytes(h[:])

	lhs := sc.H0.Mul2(r_hat, sc.H1, x_hat)
	rhs := B_.Mul2(sc.Curve.NewZrFromInt(1), B, c)

	if lhs.Equals(rhs) {
		return nil
	}

	return errors.New("invalid proof")
}

type SmartcardIdemixBackend struct {
	Curve *math.Curve
}

// Sign creates a new idemix pseudonym signature
func (s *SmartcardIdemixBackend) Sign(isc any, ipk types.IssuerPublicKey, digest []byte) ([]byte, *math.G1, *math.Zr, error) {
	sc, ok := isc.(*Smartcard)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid interface conversion for %T to *Smartcard", isc)
	}

	sig, err := sc.NymSign(digest)
	if err != nil {
		return nil, nil, nil, err
	}

	seed := sig[0:16]

	rNym := sc.PRF(seed, sc.PRF_K1)
	nym, err := sc.Curve.NewG1FromBytes(sig[16 : 16+sc.Curve.G1ByteSize])
	if err != nil {
		return nil, nil, nil, err
	}

	return sig, nym, rNym, err
}

// Verify verifies an idemix NymSignature
func (s *SmartcardIdemixBackend) Verify(ipk types.IssuerPublicKey, Nym *math.G1, signature, digest []byte) error {
	key, ok := ipk.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	if key.PKwG == nil || key.PKwG.H0 == nil || len(key.PKwG.H) <= smartcardEidIndex {
		return fmt.Errorf("invalid issuer public key: smartcard verification requires at least %d generators", smartcardEidIndex+1)
	}

	sc := &Smartcard{}

	sc.H0 = key.PKwG.H0
	sc.H1 = key.PKwG.H[0]
	sc.H2 = key.PKwG.H[smartcardEidIndex]
	sc.Curve = s.Curve

	return sc.NymVerify(signature, Nym, digest)
}
