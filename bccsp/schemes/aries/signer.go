/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/IBM/idemix/bccsp/handlers"
	bccsp "github.com/IBM/idemix/bccsp/schemes"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// UserSecretKeyIndexInNymBlinding is the index of the blinding factor of `sk` in the Nym commitment
const UserSecretKeyIndexInNymBlinding = 1

// UserSecretKeyIndexInVC2 is the index of the blinding factor of `sk` in the second term of the BBS PoK
const UserSecretKeyIndexInVC2 = 2

type Signer struct {
	Curve *math.Curve
}

func (s *Signer) getPoKOfSignature(
	credBytes []byte,
	attributes []bccsp.IdemixAttribute,
	sk *math.Zr,
	ipk *bbs12381g2pub.PublicKeyWithGenerators,
) (*bbs12381g2pub.PoKOfSignature, error) {
	credential := &Credential{}
	err := proto.Unmarshal(credBytes, credential)
	if err != nil {
		return nil, fmt.Errorf("proto.Unmarshal failed [%w]", err)
	}

	signature, err := bbs12381g2pub.ParseSignature(credential.Cred)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}

	messagesFr := credential.toSignatureMessage(sk, s.Curve)

	return bbs12381g2pub.NewPoKOfSignature(signature, messagesFr, revealedAttributesIndex(attributes), ipk)
}

func (s *Signer) getChallenge(
	pokSignature *bbs12381g2pub.PoKOfSignature,
	Nym *math.G1,
	msg []byte,
) *math.Zr {
	// hash the main proof
	challengeBytes := pokSignature.ToBytes()

	// hash the Nym commitment
	challengeBytes = append(challengeBytes, Nym.Bytes()...)

	// hash the nonce
	proofNonce := bbs12381g2pub.ParseProofNonce(msg)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)

	return bbs12381g2pub.FrFromOKM(challengeBytes)
}

func (s *Signer) packageProof(
	attributes []bccsp.IdemixAttribute,
	Nym *math.G1,
	proof *bbs12381g2pub.PoKOfSignatureProof,
	proofNym *bbs12381g2pub.ProofG1,
) ([]byte, error) {
	payload := bbs12381g2pub.NewPoKPayload(len(attributes)+1, revealedAttributesIndex(attributes))

	payloadBytes, err := payload.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("derive proof: paylod to bytes: %w", err)
	}

	signatureProofBytes := append(payloadBytes, proof.ToBytes()...)

	sig := &Signature{
		MainSignature: signatureProofBytes,
		NymCommit:     Nym.Bytes(),
		NymProof:      proofNym.ToBytes(),
	}

	return proto.Marshal(sig)
}

// Sign creates a new idemix signature
func (s *Signer) Sign(
	credBytes []byte,
	sk *math.Zr,
	Nym *math.G1,
	RNym *math.Zr,
	key handlers.IssuerPublicKey,
	attributes []bccsp.IdemixAttribute,
	msg []byte,
	rhIndex, eidIndex int,
	cri []byte,
	sigType bccsp.SignatureType,
	metadata *bccsp.IdemixSignerMetadata,
) ([]byte, *bccsp.IdemixSignerMetadata, error) {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	// TODO:
	// 1) revocation
	_ = cri
	// 2) rhIndex
	_ = rhIndex
	// 3) eidIndex
	_ = eidIndex
	// 4) sigType
	_ = sigType
	// 5) metadata
	_ = metadata

	/////////////////////////////////
	// Extract main PoK (1st move) //
	/////////////////////////////////

	pokSignature, err := s.getPoKOfSignature(credBytes, attributes, sk, ipk.PKwG)
	if err != nil {
		return nil, nil, err
	}

	//////////////////
	// Handling Nym //
	//////////////////

	// Nym is h_0^{RNym} \cdot h_1^{sk}
	commit := bbs12381g2pub.NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[UserSecretKeyIndex])
	// we force the same blinding factor used in PokVC2 to prove equality.
	// 1) commit.BlindingFactors[1] is the blinding factor for the sk in the Nym
	//    h_0^{RNym} \cdot h_1^{sk}
	// 2) pokSignature.PokVC2.BlindingFactors[2] is the blinding factor for the sk in
	//    D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
	//    index 0 is for D, index 1 is for s~ and index 2 is for the first message (which is the sk)
	commit.BlindingFactors[UserSecretKeyIndexInNymBlinding] = pokSignature.PokVC2.BlindingFactors[2]
	commitNym := commit.Finish()

	///////////////////////
	// Get the challenge //
	///////////////////////

	proofChallenge := s.getChallenge(pokSignature, Nym, msg)

	////////////////////////
	// Generate responses //
	////////////////////////

	// 1) main
	proof := pokSignature.GenerateProof(proofChallenge)
	// 2) Nym
	proofNym := commitNym.GenerateProof(proofChallenge, []*math.Zr{RNym, sk})

	///////////////////
	// Package proof //
	///////////////////

	sigBytes, err := s.packageProof(attributes, Nym, proof, proofNym)
	if err != nil {
		return nil, nil, err
	}

	return sigBytes, nil, nil
}

// Verify verifies an idemix signature.
func (s *Signer) Verify(
	key handlers.IssuerPublicKey,
	signature, msg []byte,
	attributes []bccsp.IdemixAttribute,
	rhIndex, eidIndex int,
	revocationPublicKey *ecdsa.PublicKey,
	epoch int,
	verType bccsp.VerificationType,
	meta *bccsp.IdemixSignerMetadata,
) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	// TODO:
	// 1) revocation
	_ = revocationPublicKey
	_ = epoch
	// 2) rhIndex
	_ = rhIndex
	// 3) eidIndex
	_ = eidIndex
	// 4) verType
	_ = verType
	// 5) meta
	_ = meta

	sig := &Signature{}
	err := proto.Unmarshal(signature, sig)
	if err != nil {
		return fmt.Errorf("proto.Unmarshal error: %w", err)
	}

	messages := attributesToSignatureMessage(nil, attributes, s.Curve)

	payload, err := bbs12381g2pub.ParsePoKPayload(sig.MainSignature)
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	signatureProof, err := bbs12381g2pub.ParseSignatureProof(sig.MainSignature[payload.LenInBytes():])
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	if len(payload.Revealed) > len(messages) {
		return fmt.Errorf("payload revealed bigger from messages")
	}

	revealedMessages := make(map[int]*bbs12381g2pub.SignatureMessage)
	for i := range payload.Revealed {
		revealedMessages[payload.Revealed[i]] = messages[i]
	}

	challengeBytes := signatureProof.GetBytesForChallenge(revealedMessages, ipk.PKwG)
	challengeBytes = append(challengeBytes, sig.NymCommit...)

	proofNonce := bbs12381g2pub.ParseProofNonce(msg)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := bbs12381g2pub.FrFromOKM(challengeBytes)

	nymCommit, err := s.Curve.NewG1FromBytes(sig.NymCommit)
	if err != nil {
		return fmt.Errorf("parse nym commit: %w", err)
	}

	nymProof, err := bbs12381g2pub.ParseProofG1(sig.NymProof)
	if err != nil {
		return fmt.Errorf("parse nym proof: %w", err)
	}

	// verify that `sk` in the Nym is the same as the one in the signature
	if !nymProof.Responses[UserSecretKeyIndexInNymBlinding].Equals(signatureProof.ProofVC2.Responses[2]) {
		return fmt.Errorf("failed equality proof")
	}

	// verify the proof of knowledge of the Nym
	err = nymProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[UserSecretKeyIndex]}, nymCommit, proofChallenge)
	if err != nil {
		return fmt.Errorf("verify nym proof: %w", err)
	}

	// verify the proof of knowledge of the signature
	return signatureProof.Verify(proofChallenge, ipk.PKwG, revealedMessages, messages)
}

// AuditNymEid permits the auditing of the nym eid generated by a signer
func (s *Signer) AuditNymEid(
	ipk handlers.IssuerPublicKey,
	eidIndex int,
	signature []byte,
	enrollmentID string,
	RNymEid *math.Zr,
	verType bccsp.AuditVerificationType,
) error {
	return nil
}

// AuditNymRh permits the auditing of the nym rh generated by a signer
func (s *Signer) AuditNymRh(
	ipk handlers.IssuerPublicKey,
	rhIndex int,
	signature []byte,
	revocationHandle string,
	RNymRh *math.Zr,
	verType bccsp.AuditVerificationType,
) error {
	return nil
}
