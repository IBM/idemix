/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"crypto/ecdsa"
	"fmt"
	"io"

	"github.com/IBM/idemix/bccsp/handlers"
	bccsp "github.com/IBM/idemix/bccsp/schemes"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// AttributeIndexInNym is the index of the blinding factor of the attribute in a Nym commitment
const AttributeIndexInNym = 1

// IndexOffsetVC2Attributes is the index of the attributes in VC2
const IndexOffsetVC2Attributes = 2

const signLabel = "sign"
const signWithEidNymLabel = "signWithEidNym"
const signWithEidNymRhNymLabel = "signWithEidNymRhNym" // When the revocation handle is present the enrollment id must also be present

type Signer struct {
	Curve *math.Curve
	Rng   io.Reader
}

func (s *Signer) getPoKOfSignature(
	credBytes []byte,
	attributes []bccsp.IdemixAttribute,
	sk *math.Zr,
	ipk *bbs12381g2pub.PublicKeyWithGenerators,
) (*bbs12381g2pub.PoKOfSignature, []*bbs12381g2pub.SignatureMessage, error) {
	credential := &Credential{}
	err := proto.Unmarshal(credBytes, credential)
	if err != nil {
		return nil, nil, fmt.Errorf("proto.Unmarshal failed [%w]", err)
	}

	signature, err := bbs12381g2pub.ParseSignature(credential.Cred)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signature: %w", err)
	}

	messagesFr := credential.toSignatureMessage(sk, s.Curve)

	pokOS, err := bbs12381g2pub.NewPoKOfSignature(signature, messagesFr, revealedAttributesIndex(attributes), ipk)
	if err != nil {
		return nil, nil, fmt.Errorf("bbs12381g2pub.NewPoKOfSignature error: %w", err)
	}

	return pokOS, messagesFr, nil
}

func (s *Signer) getChallenge(
	pokSignature *bbs12381g2pub.PoKOfSignature,
	Nym *math.G1,
	commitNym *math.G1,
	NymEid *math.G1,
	commitNymEid *bbs12381g2pub.ProverCommittedG1,
	msg []byte,
	sigType bccsp.SignatureType,
) *math.Zr {

	// hash the signature type first
	var challengeBytes []byte
	switch sigType {
	case bccsp.Standard:
		challengeBytes = []byte(signLabel)
	case bccsp.EidNym:
		challengeBytes = []byte(signWithEidNymLabel)
	case bccsp.EidNymRhNym:
		challengeBytes = []byte(signWithEidNymRhNymLabel)
	default:
		panic("programming error")
	}

	// hash the main proof
	challengeBytes = append(challengeBytes, pokSignature.ToBytes()...)

	// hash the Nym and t-value
	challengeBytes = append(challengeBytes, Nym.Bytes()...)
	challengeBytes = append(challengeBytes, commitNym.Bytes()...)

	// hash the NymEid and t-value
	if sigType == bccsp.EidNym || sigType == bccsp.EidNymRhNym {
		challengeBytes = append(challengeBytes, NymEid.Bytes()...)
		challengeBytes = append(challengeBytes, commitNymEid.Commitment.Bytes()...)
	}

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
	NymEid *math.G1,
	proofNymEid *bbs12381g2pub.ProofG1,
) ([]byte, error) {
	payload := bbs12381g2pub.NewPoKPayload(len(attributes)+1, revealedAttributesIndex(attributes))

	payloadBytes, err := payload.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("derive proof: paylod to bytes: %w", err)
	}

	signatureProofBytes := append(payloadBytes, proof.ToBytes()...)

	sig := &Signature{
		MainSignature: signatureProofBytes,
		Nym:           Nym.Bytes(),
		NymProof:      proofNym.ToBytes(),
	}

	if NymEid != nil {
		sig.NymEid = NymEid.Bytes()
		sig.NymEidProof = proofNymEid.ToBytes()
	}

	return proto.Marshal(sig)
}

func (s *Signer) getCommitNym(
	ipk *IssuerPublicKey,
	pokSignature *bbs12381g2pub.PoKOfSignature,
) *bbs12381g2pub.ProverCommittedG1 {

	// Nym is H0^{RNym} \cdot H[0]^{sk}

	commit := bbs12381g2pub.NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[UserSecretKeyIndex])
	// we force the same blinding factor used in PokVC2 to prove equality.
	// 1) commit.BlindingFactors[1] is the blinding factor for the sk in the Nym
	//    H0^{RNym} \cdot H[0]^{sk}
	// 2) pokSignature.PokVC2.BlindingFactors[2] is the blinding factor for the sk in
	//    D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
	//    index 0 is for D, index 1 is for s~ and index 2 is for the first message (which is the sk)
	commit.BlindingFactors[AttributeIndexInNym] = pokSignature.PokVC2.BlindingFactors[IndexOffsetVC2Attributes+UserSecretKeyIndex]

	return commit.Finish()
}

func (s *Signer) getCommitNymEid(
	ipk *IssuerPublicKey,
	pokSignature *bbs12381g2pub.PoKOfSignature,
	eid *math.Zr,
	idxInBases int,
	sigType bccsp.SignatureType,
	metadata *bccsp.IdemixSignerMetadata,
) (*bbs12381g2pub.ProverCommittedG1, *math.Zr, *math.G1, error) {

	if sigType == bccsp.Standard {
		return nil, nil, nil, nil
	}

	var NymEid *math.G1
	var RNymEid *math.Zr
	cb := bbs12381g2pub.NewCommitmentBuilder(2)
	if metadata != nil && metadata.EidNymAuditData != nil {
		if !eid.Equals(metadata.EidNymAuditData.Attr) {
			return nil, nil, nil, fmt.Errorf("eid supplied in metadata differs from signed")
		}

		RNymEid = metadata.EidNymAuditData.Rand

		cb.Add(ipk.PKwG.H0, RNymEid)
		cb.Add(ipk.PKwG.H[idxInBases], metadata.EidNymAuditData.Attr)
		NymEid = cb.Build()

		if !metadata.EidNymAuditData.Nym.Equals(NymEid) {
			return nil, nil, nil, fmt.Errorf("NymEid supplied in metadata cannot be recomputed")
		}
	} else {
		RNymEid = s.Curve.NewRandomZr(s.Rng)

		cb.Add(ipk.PKwG.H0, RNymEid)
		cb.Add(ipk.PKwG.H[idxInBases], eid)
		NymEid = cb.Build()
	}

	eidIndexInCommitment, err := s.indexOfAttributeInCommitment(pokSignature.PokVC2, idxInBases, ipk.PKwG)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error determining index for NymEid: %w", err)
	}

	commit := bbs12381g2pub.NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[idxInBases])
	// we force the same blinding factor used in PokVC2 to prove equality.
	commit.BlindingFactors[AttributeIndexInNym] = pokSignature.PokVC2.BlindingFactors[eidIndexInCommitment]

	return commit.Finish(), RNymEid, NymEid, nil
}

func (s *Signer) indexOfAttributeInCommitment(
	c *bbs12381g2pub.ProverCommittedG1,
	indexInPk int,
	ipk *bbs12381g2pub.PublicKeyWithGenerators,
) (int, error) {
	// this is the base used in the public key for the attribute; no +1 since we assume that the caller has already catered for that
	base := ipk.H[indexInPk]

	for i, h_i := range c.Bases {
		if base.Equals(h_i) {
			return i, nil
		}
	}

	return -1, fmt.Errorf("attribute not found")
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
	// 4) metadata
	_ = metadata

	//////////////////////////////////
	// Generate main PoK (1st move) //
	//////////////////////////////////

	pokSignature, messagesFr, err := s.getPoKOfSignature(credBytes, attributes, sk, ipk.PKwG)
	if err != nil {
		return nil, nil, err
	}

	//////////////////
	// Handling Nym //
	//////////////////

	commitNym := s.getCommitNym(ipk, pokSignature)

	///////////////////
	// Handle NymEID //
	///////////////////

	// increment the index to cater for the first hidden index for `sk`
	eidIndex++

	commitNymEid, RNymEid, NymEid, err := s.getCommitNymEid(ipk, pokSignature, messagesFr[eidIndex].FR, eidIndex, sigType, metadata)
	if err != nil {
		return nil, nil, err
	}

	///////////////////////
	// Get the challenge //
	///////////////////////

	proofChallenge := s.getChallenge(pokSignature, Nym, commitNym.Commitment, NymEid, commitNymEid, msg, sigType)

	////////////////////////
	// Generate responses //
	////////////////////////

	// 1) main
	proof := pokSignature.GenerateProof(proofChallenge)
	// 2) Nym
	proofNym := commitNym.GenerateProof(proofChallenge, []*math.Zr{RNym, sk})
	// 3) NymEid
	var proofNymEid *bbs12381g2pub.ProofG1
	if commitNymEid != nil {
		proofNymEid = commitNymEid.GenerateProof(proofChallenge, []*math.Zr{RNymEid, messagesFr[eidIndex].FR})
	}

	///////////////////
	// Package proof //
	///////////////////

	sigBytes, err := s.packageProof(attributes, Nym, proof, proofNym, NymEid, proofNymEid)
	if err != nil {
		return nil, nil, err
	}

	// TODO: return metadata with various Nyms

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

	verifyRHNym := (verType == bccsp.BestEffort && sig.NymRh != nil) || verType == bccsp.ExpectEidNymRhNym
	verifyEIDNym := (verType == bccsp.BestEffort && sig.NymEid != nil) || verType == bccsp.ExpectEidNym || verType == bccsp.ExpectEidNymRhNym || verifyRHNym

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

	Nym, err := s.Curve.NewG1FromBytes(sig.Nym)
	if err != nil {
		return fmt.Errorf("parse nym commit: %w", err)
	}

	nymProof, err := bbs12381g2pub.ParseProofG1(sig.NymProof)
	if err != nil {
		return fmt.Errorf("parse nym proof: %w", err)
	}

	var nymEidProof *bbs12381g2pub.ProofG1
	var NymEid *math.G1
	if verifyEIDNym {
		nymEidProof, err = bbs12381g2pub.ParseProofG1(sig.NymEidProof)
		if err != nil {
			return fmt.Errorf("parse nym proof: %w", err)
		}

		NymEid, err = s.Curve.NewG1FromBytes(sig.NymEid)
		if err != nil {
			return fmt.Errorf("parse nym commit: %w", err)
		}
	}

	////////////////////////
	// Hash the challenge //
	////////////////////////

	// hash the signature type first
	var challengeBytes []byte
	if verifyRHNym {
		challengeBytes = []byte(signWithEidNymRhNymLabel)
	} else if verifyEIDNym {
		challengeBytes = []byte(signWithEidNymLabel)
	} else {
		challengeBytes = []byte(signLabel)
	}

	challengeBytes = append(challengeBytes, signatureProof.GetBytesForChallenge(revealedMessages, ipk.PKwG)...)

	challengeBytes = append(challengeBytes, sig.Nym...)
	challengeBytes = append(challengeBytes, nymProof.Commitment.Bytes()...)

	if verifyEIDNym {
		challengeBytes = append(challengeBytes, sig.NymEid...)
		challengeBytes = append(challengeBytes, nymEidProof.Commitment.Bytes()...)
	}

	proofNonce := bbs12381g2pub.ParseProofNonce(msg)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := bbs12381g2pub.FrFromOKM(challengeBytes)

	//////////////////////
	// Verify responses //
	//////////////////////

	// TODO: verify the supplied Nyms (check what we have to do)

	// verify that `sk` in the Nym is the same as the one in the signature
	if !nymProof.Responses[AttributeIndexInNym].Equals(signatureProof.ProofVC2.Responses[IndexOffsetVC2Attributes+UserSecretKeyIndex]) {
		return fmt.Errorf("failed equality proof")
	}

	// verify the proof of knowledge of the Nym
	err = nymProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[UserSecretKeyIndex]}, Nym, proofChallenge)
	if err != nil {
		return fmt.Errorf("verify nym proof: %w", err)
	}

	if verifyEIDNym {
		// TODO: verify that eid in the NymEid is the same as the one in the signature
		// TODO: I need to know the offset into signatureProof.ProofVC2.Responses

		// verify the proof of knowledge of the Nym
		err = nymEidProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[eidIndex+1]}, NymEid, proofChallenge)
		if err != nil {
			return fmt.Errorf("verify nym eid proof: %w", err)
		}
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
