/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package aries

import (
	"crypto/ecdsa"
	"fmt"
	"io"

	"github.com/IBM/idemix/bccsp/types"
	math "github.com/IBM/mathlib"
	"github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/golang/protobuf/proto"
)

// AttributeIndexInNym is the index of the blinding factor of the attribute in a Nym commitment
const AttributeIndexInNym = 1

// IndexOffsetVC2Attributes is the index of the attributes in VC2
const IndexOffsetVC2Attributes = 2

const signLabel = "sign"
const signWithEidNymLabel = "signWithEidNym"
const signWithEidNymRhNymLabel = "signWithEidNymRhNym" // When the revocation handle is present the enrollment id must also be present
const signWithSmartcardLabel = "signWithSmartcard"

type Signer struct {
	Curve *math.Curve
	Rng   io.Reader
}

func (s *Signer) getPoKOfSignature(
	credential *Credential,
	attributes []types.IdemixAttribute,
	sk *math.Zr,
	ipk *bbs12381g2pub.PublicKeyWithGenerators,
	sigtype types.SignatureType,
	Nym *math.G1,
	RNym *math.Zr,
) (*bbs12381g2pub.PoKOfSignature, []*bbs12381g2pub.SignatureMessage, error) {
	signature, err := bbs12381g2pub.NewBBSLib(s.Curve).ParseSignature(credential.Cred)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signature: %w", err)
	}

	messagesFr := credential.toSignatureMessage(sk, s.Curve)

	var pokOS *bbs12381g2pub.PoKOfSignature
	if sigtype == types.Smartcard {
		C := Nym.Copy()
		C.Sub(ipk.H0.Mul(RNym))
		messagesFrNoSk := append(append([]*bbs12381g2pub.SignatureMessage{}, messagesFr[:credential.SkPos]...), messagesFr[credential.SkPos+1:]...)
		pokOS, err = bbs12381g2pub.NewBBSLib(s.Curve).NewPoKOfSignatureExt(signature, messagesFrNoSk, revealedAttributesIndexNoSk(attributes), ipk, Nym, RNym, C)
	} else {
		pokOS, err = bbs12381g2pub.NewBBSLib(s.Curve).NewPoKOfSignatureExt(signature, messagesFr, revealedAttributesIndex(attributes), ipk, nil, nil, nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("bbs12381g2pub.NewPoKOfSignature error: %w", err)
	}

	return pokOS, messagesFr, nil
}

func (s *Signer) getChallengeHash(
	pokSignature *bbs12381g2pub.PoKOfSignature,
	Nym *math.G1,
	commitNym *bbs12381g2pub.ProverCommittedG1,
	eid *attributeCommitment,
	rh *attributeCommitment,
	msg []byte,
	sigType types.SignatureType,
) (*math.Zr, *math.Zr) {

	// hash the signature type first
	var challengeBytes []byte
	switch sigType {
	case types.Standard:
		challengeBytes = []byte(signLabel)
	case types.EidNym:
		challengeBytes = []byte(signWithEidNymLabel)
	case types.EidNymRhNym:
		challengeBytes = []byte(signWithEidNymRhNymLabel)
	case types.Smartcard:
		challengeBytes = []byte(signWithSmartcardLabel)
	default:
		panic("programming error")
	}

	// hash the main proof
	challengeBytes = append(challengeBytes, pokSignature.ToBytes()...)

	// hash the Nym and t-value
	challengeBytes = append(challengeBytes, Nym.Bytes()...)
	if sigType != types.Smartcard {
		challengeBytes = append(challengeBytes, commitNym.Commitment.Bytes()...)
	}

	// hash the NymEid and t-value
	if sigType == types.EidNym || sigType == types.EidNymRhNym || sigType == types.Smartcard {
		challengeBytes = append(challengeBytes, eid.comm.Bytes()...)
		challengeBytes = append(challengeBytes, eid.proof.Commitment.Bytes()...)
	}

	// hash the NymEid and t-value
	if sigType == types.EidNymRhNym {
		challengeBytes = append(challengeBytes, rh.comm.Bytes()...)
		challengeBytes = append(challengeBytes, rh.proof.Commitment.Bytes()...)
	}

	// hash the nonce
	proofNonce := bbs12381g2pub.ParseProofNonce(msg, s.Curve)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)

	c := bbs12381g2pub.FrFromOKM(challengeBytes, s.Curve)

	Nonce := s.Curve.NewRandomZr(s.Rng)

	challengeBytes = c.Bytes()
	challengeBytes = append(challengeBytes, Nonce.Bytes()...)

	return bbs12381g2pub.FrFromOKM(challengeBytes, s.Curve), Nonce
}

func (s *Signer) packageProof(
	attributes []types.IdemixAttribute,
	Nym *math.G1,
	proof *bbs12381g2pub.PoKOfSignatureProof,
	proofNym *bbs12381g2pub.ProofG1,
	nymEid *attributeCommitment,
	proofNymEid *bbs12381g2pub.ProofG1,
	rhNym *attributeCommitment,
	proofRhNym *bbs12381g2pub.ProofG1,
	cri *CredentialRevocationInformation,
	nonce *math.Zr,
) ([]byte, error) {
	payload := bbs12381g2pub.NewPoKPayload(len(attributes)+1, revealedAttributesIndex(attributes))

	payloadBytes, err := payload.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("derive proof: paylod to bytes: %w", err)
	}

	signatureProofBytes := append(payloadBytes, proof.ToBytes()...)

	sig := &Signature{
		MainSignature:     signatureProofBytes,
		Nonce:             nonce.Bytes(),
		Nym:               Nym.Bytes(),
		RevocationEpochPk: cri.EpochPk,
		RevocationPkSig:   cri.EpochPkSig,
		Epoch:             cri.Epoch,
		NonRevocationProof: &NonRevocationProof{
			RevocationAlg: cri.RevocationAlg,
		},
	}

	if proofNym != nil {
		sig.NymProof = proofNym.ToBytes()
	}

	if nymEid != nil {
		sig.NymEid = nymEid.comm.Bytes()
		sig.NymEidProof = proofNymEid.ToBytes()
		sig.NymEidIdx = int32(nymEid.index)
	}

	if rhNym != nil {
		sig.NymRh = rhNym.comm.Bytes()
		sig.NymRhProof = proofRhNym.ToBytes()
		sig.NymRhIdx = int32(rhNym.index)
	}

	return proto.Marshal(sig)
}

func (s *Signer) getCommitNym(
	ipk *IssuerPublicKey,
	pokSignature *bbs12381g2pub.PoKOfSignature,
	sigType types.SignatureType,
	userSecretKeyIndex int,
) *bbs12381g2pub.ProverCommittedG1 {

	if sigType == types.Smartcard {
		return nil
	}

	// Nym is H0^{RNym} \cdot H[0]^{sk}

	commit := bbs12381g2pub.NewBBSLib(s.Curve).NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[userSecretKeyIndex])
	// we force the same blinding factor used in PokVC2 to prove equality.
	// 1) commit.BlindingFactors[1] is the blinding factor for the sk in the Nym
	//    H0^{RNym} \cdot H[0]^{sk}
	// 2) pokSignature.PokVC2.BlindingFactors[2] is the blinding factor for the sk in
	//    D * (-r3~) + Q_1 * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
	//    index 0 is for D, index 1 is for s~ and index 2 is for the first message (which is the sk)
	commit.BlindingFactors[AttributeIndexInNym] = pokSignature.PokVC2.BlindingFactors[IndexOffsetVC2Attributes+userSecretKeyIndex]

	return commit.Finish()
}

type attributeCommitment struct {
	index int
	proof *bbs12381g2pub.ProverCommittedG1
	comm  *math.G1
	r     *math.Zr
}

func safeRhNymAuditDataAccess(metadata *types.IdemixSignerMetadata) *types.AttrNymAuditData {
	if metadata == nil {
		return nil
	}

	return metadata.RhNymAuditData
}

func rhAttrCommitmentEnabled(sigType types.SignatureType) bool {
	return sigType == types.EidNymRhNym
}

func safeNymEidAuditDataAccess(metadata *types.IdemixSignerMetadata) *types.AttrNymAuditData {
	if metadata == nil {
		return nil
	}

	return metadata.EidNymAuditData
}

func nymEidAttrCommitmentEnabled(sigType types.SignatureType) bool {
	return sigType != types.Standard
}

func (s *Signer) getAttributeCommitment(
	ipk *IssuerPublicKey,
	pokSignature *bbs12381g2pub.PoKOfSignature,
	attr *math.Zr,
	idxInBases int,
	enabled bool,
	auditData *types.AttrNymAuditData,
) (*attributeCommitment, error) {

	if !enabled {
		return nil, nil
	}

	var Nym *math.G1
	var R *math.Zr

	cb := bbs12381g2pub.NewCommitmentBuilder(2)

	if auditData != nil {
		if !attr.Equals(auditData.Attr) {
			return nil, fmt.Errorf("attribute supplied in metadata differs from signed")
		}

		R = auditData.Rand

		cb.Add(ipk.PKwG.H0, R)
		cb.Add(ipk.PKwG.H[idxInBases], auditData.Attr)
		Nym = cb.Build()

		if !auditData.Nym.Equals(Nym) {
			return nil, fmt.Errorf("nym supplied in metadata cannot be recomputed")
		}
	} else {
		R = s.Curve.NewRandomZr(s.Rng)

		cb.Add(ipk.PKwG.H0, R)
		cb.Add(ipk.PKwG.H[idxInBases], attr)
		Nym = cb.Build()
	}

	attrIndexInCommitment, err := s.indexOfAttributeInCommitment(pokSignature.PokVC2, idxInBases, ipk.PKwG)
	if err != nil {
		return nil, fmt.Errorf("error determining index for attribute: %w", err)
	}

	commit := bbs12381g2pub.NewBBSLib(s.Curve).NewProverCommittingG1()
	commit.Commit(ipk.PKwG.H0)
	commit.Commit(ipk.PKwG.H[idxInBases])

	// we force the same blinding factor used in PokVC2 to prove equality.
	commit.BlindingFactors[AttributeIndexInNym] = pokSignature.PokVC2.BlindingFactors[attrIndexInCommitment]

	return &attributeCommitment{
		index: attrIndexInCommitment,
		proof: commit.Finish(),
		comm:  Nym,
		r:     R,
	}, nil
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
	key types.IssuerPublicKey,
	attributes []types.IdemixAttribute,
	msg []byte,
	rhIndex, eidIndex int,
	criRaw []byte,
	sigType types.SignatureType,
	metadata *types.IdemixSignerMetadata,
) ([]byte, *types.IdemixSignerMetadata, error) {

	///////////////
	// arg check //
	///////////////

	if (sigType == types.EidNym || sigType == types.Smartcard) &&
		attributes[eidIndex].Type != types.IdemixHiddenAttribute {
		return nil, nil, fmt.Errorf("cannot create idemix signature: disclosure of enrollment ID requested for EidNym signature")
	}

	if (sigType == types.EidNymRhNym || sigType == types.Smartcard) &&
		(attributes[eidIndex].Type != types.IdemixHiddenAttribute ||
			attributes[rhIndex].Type != types.IdemixHiddenAttribute) {
		return nil, nil, fmt.Errorf("cannot create idemix signature: disclosure of enrollment ID or RH requested for EidNymRhNym signature")
	}

	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	///////////////////////
	// handle revocation //
	///////////////////////

	cri := &CredentialRevocationInformation{}
	err := proto.Unmarshal(criRaw, cri)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmarshalling credential revocation information [%w]", err)
	}

	// if we add any other revocation algorithm, we need to change the challenge hash
	if cri.RevocationAlg != int32(types.AlgNoRevocation) {
		return nil, nil, fmt.Errorf("Unsupported revocation algorithm")
	}

	//////////////////////////////////
	// Generate main PoK (1st move) //
	//////////////////////////////////

	credential := &Credential{}
	err = proto.Unmarshal(credBytes, credential)
	if err != nil {
		return nil, nil, fmt.Errorf("proto.Unmarshal failed [%w]", err)
	}

	pokSignature, messagesFr, err := s.getPoKOfSignature(credential, attributes, sk, ipk.PKwG, sigType, Nym, RNym)
	if err != nil {
		return nil, nil, err
	}

	//////////////////
	// Handling Nym //
	//////////////////

	commitNym := s.getCommitNym(ipk, pokSignature, sigType, int(credential.SkPos))

	///////////////////
	// Handle NymEID //
	///////////////////

	// increment the index to cater for the index for `sk`
	if eidIndex > int(credential.SkPos) {
		eidIndex++
	}

	nymEid, err := s.getAttributeCommitment(ipk, pokSignature, messagesFr[eidIndex].FR, eidIndex, nymEidAttrCommitmentEnabled(sigType), safeNymEidAuditDataAccess(metadata))
	if err != nil {
		return nil, nil, err
	}

	///////////////////
	// Handle RhNym //
	///////////////////

	// increment the index to cater for the index for `sk`
	if rhIndex > int(credential.SkPos) {
		rhIndex++
	}

	rhNym, err := s.getAttributeCommitment(ipk, pokSignature, messagesFr[rhIndex].FR, rhIndex, rhAttrCommitmentEnabled(sigType), safeRhNymAuditDataAccess(metadata))
	if err != nil {
		return nil, nil, err
	}

	///////////////////////
	// Get the challenge //
	///////////////////////

	proofChallenge, Nonce := s.getChallengeHash(pokSignature, Nym, commitNym, nymEid, rhNym, msg, sigType)

	////////////////////////
	// Generate responses //
	////////////////////////

	// 1) main
	proof := pokSignature.GenerateProof(proofChallenge)
	// 2) Nym
	var proofNym *bbs12381g2pub.ProofG1
	if commitNym != nil {
		proofNym = commitNym.GenerateProof(proofChallenge, []*math.Zr{RNym, sk})
	}
	// 3) NymEid
	var proofNymEid *bbs12381g2pub.ProofG1
	if nymEid != nil {
		proofNymEid = nymEid.proof.GenerateProof(proofChallenge, []*math.Zr{nymEid.r, messagesFr[eidIndex].FR})
	}
	// 4) RhNym
	var proofRhNym *bbs12381g2pub.ProofG1
	if rhNym != nil {
		proofRhNym = rhNym.proof.GenerateProof(proofChallenge, []*math.Zr{rhNym.r, messagesFr[rhIndex].FR})
	}

	///////////////////
	// Package proof //
	///////////////////

	sigBytes, err := s.packageProof(attributes, Nym, proof, proofNym, nymEid, proofNymEid, rhNym, proofRhNym, cri, Nonce)
	if err != nil {
		return nil, nil, err
	}

	var m *types.IdemixSignerMetadata
	if sigType == types.EidNym || sigType == types.Smartcard {
		m = &types.IdemixSignerMetadata{
			EidNymAuditData: &types.AttrNymAuditData{
				Nym:  nymEid.comm,
				Rand: nymEid.r,
				Attr: messagesFr[eidIndex].FR,
			},
		}
	}

	if sigType == types.EidNymRhNym {
		m = &types.IdemixSignerMetadata{
			EidNymAuditData: &types.AttrNymAuditData{
				Nym:  nymEid.comm,
				Rand: nymEid.r,
				Attr: messagesFr[eidIndex].FR,
			},
			RhNymAuditData: &types.AttrNymAuditData{
				Nym:  rhNym.comm,
				Rand: rhNym.r,
				Attr: messagesFr[rhIndex].FR,
			},
		}
	}

	return sigBytes, m, nil
}

// Verify verifies an idemix signature.
func (s *Signer) Verify(
	key types.IssuerPublicKey,
	signature, msg []byte,
	attributes []types.IdemixAttribute,
	rhIndex, eidIndex, skIndex int,
	_ *ecdsa.PublicKey,
	_ int,
	verType types.VerificationType,
	meta *types.IdemixSignerMetadata,
) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	lib := bbs12381g2pub.NewBBSLib(s.Curve)

	sig := &Signature{}
	err := proto.Unmarshal(signature, sig)
	if err != nil {
		return fmt.Errorf("proto.Unmarshal error: %w", err)
	}

	if sig.NonRevocationProof.RevocationAlg != int32(types.AlgNoRevocation) {
		return fmt.Errorf("unsupported revocation algorithm")
	}

	if verType == types.ExpectEidNym &&
		(len(sig.NymEid) == 0 || len(sig.NymEidProof) == 0) {
		return fmt.Errorf("no EidNym provided but ExpectEidNym required")
	}

	if verType == types.ExpectEidNymRhNym {
		if len(sig.NymEid) == 0 || len(sig.NymEidProof) == 0 {
			return fmt.Errorf("no EidNym provided but ExpectEidNymRhNym required")
		}
		if len(sig.NymRh) == 0 || len(sig.NymRhProof) == 0 {
			return fmt.Errorf("no RhNym provided but ExpectEidNymRhNym required")
		}
	}

	if verType == types.ExpectStandard {
		if len(sig.NymRh) != 0 || len(sig.NymRhProof) != 0 {
			return fmt.Errorf("RhNym available but ExpectStandard required")
		}
		if len(sig.NymEid) != 0 || len(sig.NymEidProof) != 0 {
			return fmt.Errorf("EidNym available but ExpectStandard required")
		}
	}

	verifyRHNym := (verType == types.BestEffort && sig.NymRh != nil) || verType == types.ExpectEidNymRhNym
	verifyEIDNym := (verType == types.BestEffort && sig.NymEid != nil) || verType == types.ExpectEidNym || verType == types.ExpectEidNymRhNym || verType == types.ExpectSmartcard || verifyRHNym

	messages := attributesToSignatureMessage(attributes, s.Curve, skIndex)

	payload, err := bbs12381g2pub.ParsePoKPayload(sig.MainSignature)
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	signatureProof, err := lib.ParseSignatureProof(sig.MainSignature[payload.LenInBytes():])
	if err != nil {
		return fmt.Errorf("parse signature proof: %w", err)
	}

	if len(payload.Revealed) > len(messages) {
		return fmt.Errorf("payload revealed bigger from messages")
	}

	Nym, err := s.Curve.NewG1FromBytes(sig.Nym)
	if err != nil {
		return fmt.Errorf("parse nym commit: %w", err)
	}

	var nymProof *bbs12381g2pub.ProofG1
	if verType != types.ExpectSmartcard {
		nymProof, err = lib.ParseProofG1(sig.NymProof)
		if err != nil {
			return fmt.Errorf("parse nym proof: %w", err)
		}
	}

	var nymEidProof *bbs12381g2pub.ProofG1
	var NymEid *math.G1
	if verifyEIDNym {
		nymEidProof, err = lib.ParseProofG1(sig.NymEidProof)
		if err != nil {
			return fmt.Errorf("parse nym proof: %w", err)
		}

		NymEid, err = s.Curve.NewG1FromBytes(sig.NymEid)
		if err != nil {
			return fmt.Errorf("parse nym commit: %w", err)
		}
	}

	var rhNymProof *bbs12381g2pub.ProofG1
	var RhNym *math.G1
	if verifyRHNym {
		rhNymProof, err = lib.ParseProofG1(sig.NymRhProof)
		if err != nil {
			return fmt.Errorf("parse rh proof: %w", err)
		}

		RhNym, err = s.Curve.NewG1FromBytes(sig.NymRh)
		if err != nil {
			return fmt.Errorf("parse rh commit: %w", err)
		}
	}

	////////////////////////
	// Hash the challenge //
	////////////////////////

	// hash the signature type first
	var challengeBytes []byte
	if verType == types.ExpectSmartcard {
		challengeBytes = []byte(signWithSmartcardLabel)
	} else if verifyRHNym {
		challengeBytes = []byte(signWithEidNymRhNymLabel)
	} else if verifyEIDNym {
		challengeBytes = []byte(signWithEidNymLabel)
	} else {
		challengeBytes = []byte(signLabel)
	}

	revealedMessages := make(map[int]*bbs12381g2pub.SignatureMessage)
	for i := range payload.Revealed {
		revealedMessages[payload.Revealed[i]] = messages[i]
	}

	if verType == types.ExpectSmartcard {
		// we add this so that GetBytesForChallenge thinks we disclose attr 0 and doesn't add its base to the ZKP chall
		// we will remove it later
		revealedMessages[0] = &bbs12381g2pub.SignatureMessage{}
	}
	challengeBytes = append(challengeBytes, signatureProof.GetBytesForChallenge(revealedMessages, ipk.PKwG)...)
	if verType == types.ExpectSmartcard {
		delete(revealedMessages, 0)
	}

	challengeBytes = append(challengeBytes, sig.Nym...)
	if verType != types.ExpectSmartcard {
		challengeBytes = append(challengeBytes, nymProof.Commitment.Bytes()...)
	}

	if verifyEIDNym {
		challengeBytes = append(challengeBytes, sig.NymEid...)
		challengeBytes = append(challengeBytes, nymEidProof.Commitment.Bytes()...)
	}

	if verifyRHNym {
		challengeBytes = append(challengeBytes, sig.NymRh...)
		challengeBytes = append(challengeBytes, rhNymProof.Commitment.Bytes()...)
	}

	proofNonce := bbs12381g2pub.ParseProofNonce(msg, s.Curve)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := bbs12381g2pub.FrFromOKM(challengeBytes, s.Curve)

	challengeBytes = proofChallenge.Bytes()
	challengeBytes = append(challengeBytes, sig.Nonce...)
	proofChallenge = bbs12381g2pub.FrFromOKM(challengeBytes, s.Curve)

	//////////////////////
	// Verify responses //
	//////////////////////

	// increment the index to cater for the index for `sk`
	if eidIndex > skIndex {
		eidIndex++
	}

	// increment the index to cater for the index for `sk`
	if rhIndex > skIndex {
		rhIndex++
	}

	// audit eid nym if data provided and verification requested
	if (verifyEIDNym || verifyRHNym) && meta != nil {
		if meta.EidNymAuditData != nil {
			ne := ipk.PKwG.H[eidIndex].Mul2(
				meta.EidNymAuditData.Attr,
				ipk.PKwG.H0, meta.EidNymAuditData.Rand)

			if !ne.Equals(NymEid) {
				return fmt.Errorf("signature invalid: nym eid validation failed, does not match regenerated nym eid")
			}

			if meta.EidNymAuditData.Nym != nil && !NymEid.Equals(meta.EidNymAuditData.Nym) {
				return fmt.Errorf("signature invalid: nym eid validation failed, does not match metadata")
			}
		}

		if len(meta.EidNym) != 0 {
			NymEID_, err := s.Curve.NewG1FromBytes(meta.EidNym)
			if err != nil {
				return fmt.Errorf("signature invalid: nym eid validation failed, failed to unmarshal meta nym eid")
			}
			if !NymEID_.Equals(NymEid) {
				return fmt.Errorf("signature invalid: nym eid validation failed, signature nym eid does not match metadata")
			}
		}
	}

	// audit rh nym if data provided and verification requested
	if verifyRHNym && meta != nil {
		if meta.RhNymAuditData != nil {
			rn := ipk.PKwG.H[rhIndex].Mul2(
				meta.RhNymAuditData.Attr,
				ipk.PKwG.H0, meta.RhNymAuditData.Rand,
			)

			if !rn.Equals(RhNym) {
				return fmt.Errorf("signature invalid: nym rh validation failed, does not match regenerated nym rh")
			}

			if meta.RhNymAuditData.Nym != nil && !RhNym.Equals(meta.RhNymAuditData.Nym) {
				return fmt.Errorf("signature invalid: nym rh validation failed, does not match metadata")
			}
		}

		if len(meta.RhNym) != 0 {
			RhNym_, err := s.Curve.NewG1FromBytes(meta.RhNym)
			if err != nil {
				return fmt.Errorf("signature invalid: rh nym validation failed, failed to unmarshal meta rh nym")
			}
			if !RhNym_.Equals(RhNym) {
				return fmt.Errorf("signature invalid: rh nym validation failed, signature rh nym does not match metadata")
			}
		}
	}

	if verType != types.ExpectSmartcard {
		// verify that `sk` in the Nym is the same as the one in the signature
		if !nymProof.Responses[AttributeIndexInNym].Equals(signatureProof.ProofVC2.Responses[IndexOffsetVC2Attributes+skIndex]) {
			return fmt.Errorf("failed equality proof for sk")
		}

		// verify the proof of knowledge of the Nym
		err = nymProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[skIndex]}, Nym, proofChallenge)
		if err != nil {
			return fmt.Errorf("verify nym proof: %w", err)
		}
	}

	if verifyEIDNym {
		// verify that eid in the NymEid is the same as the one in the signature
		if !nymEidProof.Responses[AttributeIndexInNym].Equals(signatureProof.ProofVC2.Responses[sig.NymEidIdx]) {
			return fmt.Errorf("failed equality proof for eid")
		}

		// verify the proof of knowledge of the Nym
		err = nymEidProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[eidIndex]}, NymEid, proofChallenge)
		if err != nil {
			return fmt.Errorf("verify nym eid proof: %w", err)
		}
	}

	if verifyRHNym {
		// verify that rh in the RhNym is the same as the one in the signature
		if !rhNymProof.Responses[AttributeIndexInNym].Equals(signatureProof.ProofVC2.Responses[sig.NymRhIdx]) {
			return fmt.Errorf("failed equality proof for rh")
		}

		// verify the proof of knowledge of the Rh
		err = rhNymProof.Verify([]*math.G1{ipk.PKwG.H0, ipk.PKwG.H[rhIndex]}, RhNym, proofChallenge)
		if err != nil {
			return fmt.Errorf("verify nym eid proof: %w", err)
		}
	}

	// verify the proof of knowledge of the signature
	if verType != types.ExpectSmartcard {
		return signatureProof.Verify(proofChallenge, ipk.PKwG, revealedMessages, messages)
	} else {
		return signatureProof.VerifyExt(proofChallenge, ipk.PKwG, revealedMessages, messages, Nym)
	}
}

// AuditNymEid permits the auditing of the nym eid generated by a signer
func (s *Signer) AuditNymEid(
	key types.IssuerPublicKey,
	eidIndex int,
	signature []byte,
	enrollmentID string,
	RNymEid *math.Zr,
	verType types.AuditVerificationType,
) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	var NymEid *math.G1
	switch verType {
	case types.AuditExpectSignature:
		sig := &Signature{}
		err := proto.Unmarshal(signature, sig)
		if err != nil {
			return fmt.Errorf("proto.Unmarshal error: %w", err)
		}

		NymEid, err = s.Curve.NewG1FromBytes(sig.NymEid)
		if err != nil {
			return fmt.Errorf("parse nym commit: %w", err)
		}
	case types.AuditExpectEidNymRhNym:
		fallthrough
	case types.AuditExpectEidNym:
		var err error
		NymEid, err = s.Curve.NewG1FromBytes(signature)
		if err != nil {
			return fmt.Errorf("parse nym commit: %w", err)
		}
	default:
		return fmt.Errorf("invalid audit type [%d]", verType)
	}

	eidAttr := bbs12381g2pub.FrFromOKM([]byte(enrollmentID), s.Curve)

	ne := ipk.PKwG.H[eidIndex+1].Mul2(eidAttr, ipk.PKwG.H0, RNymEid)

	if !ne.Equals(NymEid) {
		return fmt.Errorf("eid nym does not match")
	}

	return nil
}

// AuditNymRh permits the auditing of the nym rh generated by a signer
func (s *Signer) AuditNymRh(
	key types.IssuerPublicKey,
	rhIndex int,
	signature []byte,
	revocationHandle string,
	RNymRh *math.Zr,
	verType types.AuditVerificationType,
) error {
	ipk, ok := key.(*IssuerPublicKey)
	if !ok {
		return fmt.Errorf("invalid issuer public key, expected *IssuerPublicKey, got [%T]", ipk)
	}

	var RhNym *math.G1
	switch verType {
	case types.AuditExpectSignature:
		sig := &Signature{}
		err := proto.Unmarshal(signature, sig)
		if err != nil {
			return fmt.Errorf("proto.Unmarshal error: %w", err)
		}

		RhNym, err = s.Curve.NewG1FromBytes(sig.NymRh)
		if err != nil {
			return fmt.Errorf("parse rh commit: %w", err)
		}
	case types.AuditExpectEidNymRhNym:
		var err error
		RhNym, err = s.Curve.NewG1FromBytes(signature)
		if err != nil {
			return fmt.Errorf("parse nym commit: %w", err)
		}
	default:
		return fmt.Errorf("invalid audit type [%d]", verType)
	}

	rhAttr := bbs12381g2pub.FrFromOKM([]byte(revocationHandle), s.Curve)

	nr := ipk.PKwG.H[rhIndex+1].Mul2(rhAttr, ipk.PKwG.H0, RNymRh)

	if !nr.Equals(RhNym) {
		return fmt.Errorf("rh nym does not match")
	}

	return nil
}
