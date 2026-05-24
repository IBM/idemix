/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/IBM/idemix/bbs"
)

// curve used for all benchmarks: BLS12-381 with BBS-specific hash-to-curve (GURVY backend).
var benchCurve = ml.Curves[ml.BLS12_381_BBS_GURVY]

// ─── helpers ──────────────────────────────────────────────────────────

// benchMessages generates n distinct test messages.
func benchMessages(n int) [][]byte {
	msgs := make([][]byte, n)
	for i := range msgs {
		msgs[i] = []byte(fmt.Sprintf("bench-message-%d", i))
	}
	return msgs
}

// benchKeyPair returns a fresh key pair for the benchmark curve.
func benchKeyPair() (*bbs.PublicKey, *bbs.PrivateKey) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	lib := bbs.NewBBSLib(benchCurve)
	pub, priv, err := lib.GenerateKeyPair(sha256.New, seed)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// benchRevealedIndexes returns a slice of revealed indexes selecting roughly
// half the messages, spread evenly.
func benchRevealedIndexes(msgCount int) []int {
	if msgCount == 1 {
		return []int{0}
	}
	var idxs []int
	for i := 0; i < msgCount; i += 2 {
		idxs = append(idxs, i)
	}
	return idxs
}

// messageCounts defines the parameterized sizes we benchmark with.
var messageCounts = []int{1, 5, 10, 20}

// ─── End-to-End Operation Benchmarks ──────────────────────────────────

// BenchmarkSign measures BBS+ signing over varying message counts.
func BenchmarkSign(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			_, priv := benchKeyPair()
			privKeyBytes, err := priv.Marshal()
			if err != nil {
				b.Fatal(err)
			}
			msgs := benchMessages(n)
			scheme := bbs.New(benchCurve)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := scheme.Sign(msgs, privKeyBytes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerify measures BBS+ signature verification over varying message counts.
func BenchmarkVerify(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			pub, priv := benchKeyPair()
			privKeyBytes, _ := priv.Marshal()
			pubKeyBytes, _ := pub.Marshal()
			msgs := benchMessages(n)
			scheme := bbs.New(benchCurve)

			sigBytes, err := scheme.Sign(msgs, privKeyBytes)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := scheme.Verify(msgs, sigBytes, pubKeyBytes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDeriveProof measures selective-disclosure proof generation.
func BenchmarkDeriveProof(b *testing.B) {
	for _, n := range messageCounts {
		revealed := benchRevealedIndexes(n)
		b.Run(fmt.Sprintf("msgs=%d/revealed=%d", n, len(revealed)), func(b *testing.B) {
			pub, priv := benchKeyPair()
			privKeyBytes, _ := priv.Marshal()
			pubKeyBytes, _ := pub.Marshal()
			msgs := benchMessages(n)
			scheme := bbs.New(benchCurve)
			nonce := []byte("benchmark-nonce")

			sigBytes, err := scheme.Sign(msgs, privKeyBytes)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := scheme.DeriveProof(msgs, sigBytes, nonce, pubKeyBytes, revealed)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerifyProof measures selective-disclosure proof verification.
func BenchmarkVerifyProof(b *testing.B) {
	for _, n := range messageCounts {
		revealed := benchRevealedIndexes(n)
		b.Run(fmt.Sprintf("msgs=%d/revealed=%d", n, len(revealed)), func(b *testing.B) {
			pub, priv := benchKeyPair()
			privKeyBytes, _ := priv.Marshal()
			pubKeyBytes, _ := pub.Marshal()
			msgs := benchMessages(n)
			scheme := bbs.New(benchCurve)
			nonce := []byte("benchmark-nonce")

			sigBytes, err := scheme.Sign(msgs, privKeyBytes)
			if err != nil {
				b.Fatal(err)
			}

			revealedMsgs := make([][]byte, len(revealed))
			for i, idx := range revealed {
				revealedMsgs[i] = msgs[idx]
			}

			// Pre-generate multiple proofs to avoid verifying the same parsed
			// proof object repeatedly (internal append in getChallengeContribution
			// can corrupt Responses on re-verification of same parsed proof).
			const proofPoolSize = 64
			proofPool := make([][]byte, proofPoolSize)
			for j := 0; j < proofPoolSize; j++ {
				proofPool[j], err = scheme.DeriveProof(msgs, sigBytes, nonce, pubKeyBytes, revealed)
				if err != nil {
					b.Fatal(err)
				}
			}

			// Sanity check: verify the first proof before benchmarking
			hash1 := fmt.Sprintf("%x", sha256.Sum256(proofPool[0]))
			if err := scheme.VerifyProof(revealedMsgs, proofPool[0], nonce, pubKeyBytes); err != nil {
				b.Fatal("sanity check failed:", err)
			}
			hash2 := fmt.Sprintf("%x", sha256.Sum256(proofPool[0]))
			if hash1 != hash2 {
				b.Fatalf("proofPool[0] MUTATED! %s != %s", hash1, hash2)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := scheme.VerifyProof(revealedMsgs, proofPool[i%proofPoolSize], nonce, pubKeyBytes)
				if err != nil {
					b.Fatalf("failed at i=%d: %v", i, err)
				}
			}
		})
	}
}

// BenchmarkSignWithKey measures signing using a pre-parsed key (skips unmarshal).
func BenchmarkSignWithKey(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			_, priv := benchKeyPair()
			msgs := benchMessages(n)
			scheme := bbs.New(benchCurve)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := scheme.SignWithKey(msgs, priv)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ─── Component-Level Benchmarks ───────────────────────────────────────

// BenchmarkToPublicKeyWithGenerators measures the cost of deriving generators
// from a public key. This is called on every BBS+ operation.
func BenchmarkToPublicKeyWithGenerators(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			pub, _ := benchKeyPair()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := pub.ToPublicKeyWithGenerators(n)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkComputeB measures the multi-scalar multiplication in ComputeB,
// which is called during both signing and verification.
func BenchmarkComputeB(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			pub, _ := benchKeyPair()
			msgs := benchMessages(n)
			messagesFr := bbs.MessagesToFr(msgs, benchCurve)

			pubKeyWithGens, err := pub.ToPublicKeyWithGenerators(n)
			if err != nil {
				b.Fatal(err)
			}

			s := benchCurve.NewRandomZr(rand.Reader)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = bbs.ComputeB(s, messagesFr, pubKeyWithGens, benchCurve)
			}
		})
	}
}

// BenchmarkFrFromOKM measures the scalar derivation from arbitrary-length input,
// called for every message in sign/verify/proof flows.
func BenchmarkFrFromOKM(b *testing.B) {
	msg := []byte("benchmark-message-for-okm")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bbs.FrFromOKM(msg, benchCurve)
	}
}

// BenchmarkMessagesToFr measures batch message-to-scalar conversion.
func BenchmarkMessagesToFr(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("msgs=%d", n), func(b *testing.B) {
			msgs := benchMessages(n)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = bbs.MessagesToFr(msgs, benchCurve)
			}
		})
	}
}

// BenchmarkNewCommitmentBuilder measures the commitment building used in
// sumOfG1Products — the core multi-scalar multiplication bottleneck.
func BenchmarkNewCommitmentBuilder(b *testing.B) {
	for _, n := range messageCounts {
		b.Run(fmt.Sprintf("bases=%d", n), func(b *testing.B) {
			pub, _ := benchKeyPair()
			pubKeyWithGens, err := pub.ToPublicKeyWithGenerators(n)
			if err != nil {
				b.Fatal(err)
			}

			// Pre-generate random scalars
			scalars := make([]*ml.Zr, n)
			for i := range scalars {
				scalars[i] = benchCurve.NewRandomZr(rand.Reader)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cb := bbs.NewCommitmentBuilder(n)
				for j := 0; j < n; j++ {
					cb.Add(pubKeyWithGens.H[j], scalars[j])
				}
				_ = cb.Build()
			}
		})
	}
}

// ─── Signature Parsing & Serialization Benchmarks ─────────────────────

// BenchmarkParseSignature measures signature deserialization.
func BenchmarkParseSignature(b *testing.B) {
	_, priv := benchKeyPair()
	privKeyBytes, _ := priv.Marshal()
	msgs := benchMessages(5)
	scheme := bbs.New(benchCurve)
	sigBytes, err := scheme.Sign(msgs, privKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	lib := bbs.NewBBSLib(benchCurve)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lib.ParseSignature(sigBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignatureToBytes measures signature serialization.
func BenchmarkSignatureToBytes(b *testing.B) {
	_, priv := benchKeyPair()
	privKeyBytes, _ := priv.Marshal()
	msgs := benchMessages(5)
	scheme := bbs.New(benchCurve)
	sigBytes, err := scheme.Sign(msgs, privKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	lib := bbs.NewBBSLib(benchCurve)
	sig, err := lib.ParseSignature(sigBytes)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sig.ToBytes()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Key Operation Benchmarks ─────────────────────────────────────────

// BenchmarkGenerateKeyPair measures key pair generation.
func BenchmarkGenerateKeyPair(b *testing.B) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		b.Fatal(err)
	}
	lib := bbs.NewBBSLib(benchCurve)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := lib.GenerateKeyPair(sha256.New, seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPublicKeyMarshal measures public key serialization.
func BenchmarkPublicKeyMarshal(b *testing.B) {
	pub, _ := benchKeyPair()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pub.Marshal()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUnmarshalPublicKey measures public key deserialization.
func BenchmarkUnmarshalPublicKey(b *testing.B) {
	pub, _ := benchKeyPair()
	pubKeyBytes, _ := pub.Marshal()
	lib := bbs.NewBBSLib(benchCurve)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lib.UnmarshalPublicKey(pubKeyBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Proof Serialization / Parsing Benchmarks ─────────────────────────

// BenchmarkParseSignatureProof measures proof deserialization.
func BenchmarkParseSignatureProof(b *testing.B) {
	pub, priv := benchKeyPair()
	privKeyBytes, _ := priv.Marshal()
	pubKeyBytes, _ := pub.Marshal()
	msgs := benchMessages(10)
	scheme := bbs.New(benchCurve)
	nonce := []byte("benchmark-nonce")
	revealed := benchRevealedIndexes(10)

	sigBytes, err := scheme.Sign(msgs, privKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	proofBytes, err := scheme.DeriveProof(msgs, sigBytes, nonce, pubKeyBytes, revealed)
	if err != nil {
		b.Fatal(err)
	}

	// Strip the payload header to get just the signature proof portion
	payload, err := bbs.ParsePoKPayload(proofBytes)
	if err != nil {
		b.Fatal(err)
	}
	sigProofBytes := proofBytes[payload.LenInBytes():]
	lib := bbs.NewBBSLib(benchCurve)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lib.ParseSignatureProof(sigProofBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ─── Pairing Benchmark ───────────────────────────────────────────────

// BenchmarkPairing measures the cost of a single pairing evaluation,
// which is the most expensive primitive and dominates Verify/VerifyProof.
func BenchmarkPairing(b *testing.B) {
	a := benchCurve.NewRandomZr(rand.Reader)
	p := benchCurve.GenG1.Mul(a)
	q := benchCurve.GenG2.Mul(a)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gt := benchCurve.Pairing(q, p)
		_ = benchCurve.FExp(gt)
	}
}

// BenchmarkPairing2 measures the cost of a double pairing (Pairing2 + FExp),
// which is used in signature and proof verification.
func BenchmarkPairing2(b *testing.B) {
	a := benchCurve.NewRandomZr(rand.Reader)
	p1 := benchCurve.GenG1.Mul(a)
	q1 := benchCurve.GenG2.Mul(a)
	c := benchCurve.NewRandomZr(rand.Reader)
	p2 := benchCurve.GenG1.Mul(c)
	q2 := benchCurve.GenG2.Mul(c)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gt := benchCurve.Pairing2(q1, p1, q2, p2)
		_ = benchCurve.FExp(gt)
	}
}

// ─── Scalar Multiplication Benchmark ─────────────────────────────────

// BenchmarkG1ScalarMul measures a single G1 scalar multiplication,
// which is the building block of sumOfG1Products.
func BenchmarkG1ScalarMul(b *testing.B) {
	s := benchCurve.NewRandomZr(rand.Reader)
	p := benchCurve.GenG1.Mul(benchCurve.NewRandomZr(rand.Reader))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Mul(s)
	}
}

// BenchmarkG1Add measures a single G1 point addition.
func BenchmarkG1Add(b *testing.B) {
	p := benchCurve.GenG1.Mul(benchCurve.NewRandomZr(rand.Reader))
	q := benchCurve.GenG1.Mul(benchCurve.NewRandomZr(rand.Reader))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := p.Copy()
		r.Add(q)
	}
}

// BenchmarkHashToG1 measures the cost of hash-to-curve, which is used
// for generator derivation in ToPublicKeyWithGenerators.
func BenchmarkHashToG1(b *testing.B) {
	data := []byte("benchmark-data-for-hash-to-g1-operation-with-some-length")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")
		_ = benchCurve.HashToG1WithDomain(data, dst)
	}
}
