/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"errors"
	"fmt"
	"io"

	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"google.golang.org/protobuf/proto"
)

const nymSigLabel = "nym-sig"

type NymSigner struct {
	Curve              *math.Curve
	Rng                io.Reader
	UserSecretKeyIndex int
}

// Sign creates a new idemix pseudonym signature
func (s *NymSigner) Sign(
	sk *math.Zr,
	Nym *math.G1,
	RNym *math.Zr,
	key types.IssuerPublicKey,
	digest []byte,
) ([]byte, error) {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	Nonce := s.Curve.NewRandomZr(s.Rng)

	commit := bbs.NewBBSLib(s.Curve).NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[s.UserSecretKeyIndex])
	commitNym := commit.Finish()

	challengeBytes := []byte(nymSigLabel)
	challengeBytes = append(challengeBytes, Nym.Bytes()...)
	challengeBytes = append(challengeBytes, commitNym.ToBytes()...)
	challengeBytes = append(challengeBytes, digest...)

	proofChallenge := bbs.FrFromOKM(challengeBytes, s.Curve)

	challengeBytes = proofChallenge.Bytes()
	challengeBytes = append(challengeBytes, Nonce.Bytes()...)
	proofChallenge = bbs.FrFromOKM(challengeBytes, s.Curve)

	proof := commitNym.GenerateProof(proofChallenge, []*math.Zr{RNym, sk})

	sig := &NymSignature{
		MainSignature: proof.ToBytes(),
		Nonce:         Nonce.Bytes(),
	}

	return proto.Marshal(sig)
}

// Verify verifies an idemix NymSignature
func (s *NymSigner) Verify(
	key types.IssuerPublicKey,
	Nym *math.G1,
	sigBytes, digest []byte,
	skIndex int,
) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	if Nym == nil {
		return errors.New("invalid nym: nil")
	}

	if ipk.PKwG == nil || ipk.PKwG.H0 == nil {
		return errors.New("invalid issuer public key: missing generators")
	}

	if skIndex < 0 || skIndex >= len(ipk.PKwG.H) {
		return fmt.Errorf("invalid sk index %d, expected in [0, %d)", skIndex, len(ipk.PKwG.H))
	}

	sig := &NymSignature{}
	err := proto.Unmarshal(sigBytes, sig)
	if err != nil {
		return fmt.Errorf("error unmarshalling signature: [%w]", err)
	}

	nymProof, err := bbs.NewBBSLib(s.Curve).ParseProofG1(sig.MainSignature)
	if err != nil {
		return fmt.Errorf("parse nym proof: %w", err)
	}

	if len(nymProof.Responses) < 2 {
		return fmt.Errorf("invalid nym proof: expected at least 2 responses, got %d", len(nymProof.Responses))
	}

	challengeBytes := []byte(nymSigLabel)
	challengeBytes = append(challengeBytes, Nym.Bytes()...)
	challengeBytes = append(challengeBytes, ipk.PKwG.H0.Bytes()...)
	challengeBytes = append(challengeBytes, ipk.PKwG.H[skIndex].Bytes()...)
	challengeBytes = append(challengeBytes, nymProof.Commitment.Bytes()...)
	challengeBytes = append(challengeBytes, digest...)

	proofChallenge := bbs.FrFromOKM(challengeBytes, s.Curve)

	challengeBytes = proofChallenge.Bytes()
	challengeBytes = append(challengeBytes, sig.Nonce...)
	proofChallenge = bbs.FrFromOKM(challengeBytes, s.Curve)

	return nymProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[skIndex]}, Nym, proofChallenge)
}
