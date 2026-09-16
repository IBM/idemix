/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"testing"

	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// innerIdemixIDBytes unwraps the outer SerializedIdentity produced by
// identity.Serialize() (and consumed by MSP.DeserializeIdentity) and returns
// the inner SerializedIdemixIdentity bytes that MSP.DeserializeSigningIdentity
// actually expects as its raw argument.
func innerIdemixIDBytes(t *testing.T, serializedIdentity []byte) []byte {
	t.Helper()

	sID := &m.SerializedIdentity{}
	require.NoError(t, proto.Unmarshal(serializedIdentity, sID))

	return sID.GetIdBytes()
}

// TestDeserializeSigningIdentity exercises MSP.DeserializeSigningIdentity against
// the round trip already established by GetDefaultSigningIdentity, Serialize and
// DeserializeIdentity: reconstructing a signing identity from the raw bytes of a
// serialized identity should produce something that signs, verifies and validates
// exactly like the original. This requires the MSP to be backed by a persistent
// keystore.KVS (setupCurveWithKeyStore): DeserializeSigningIdentity recovers the
// nym secret key via BCCSP.GetKey, which only finds keys that were actually
// stored - see TestDeserializeSigningIdentityRequiresPersistentKeyStore for what
// happens without one.
func TestDeserializeSigningIdentity(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithKeyStore(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		serializedID, err := id1.Serialize()
		require.NoError(t, err)

		reconstructed, err := msp1.DeserializeSigningIdentity(innerIdemixIDBytes(t, serializedID))
		require.NoError(t, err)
		require.NotNil(t, reconstructed)

		// The reconstructed identity must be independently valid and satisfy the
		// same association proof checks as the original.
		require.NoError(t, reconstructed.Validate())
		require.NoError(t, msp1.Validate(reconstructed))

		// It must be able to sign, and the resulting signatures must verify
		// against both the reconstructed identity and the original one, since
		// they wrap the very same pseudonym.
		msg := []byte("TestDeserializeSigningIdentity message")
		sig, err := reconstructed.Sign(msg)
		require.NoError(t, err)
		require.NoError(t, reconstructed.Verify(msg, sig))
		require.NoError(t, id1.Verify(msg, sig))

		sigFromOriginal, err := id1.Sign(msg)
		require.NoError(t, err)
		require.NoError(t, reconstructed.Verify(msg, sigFromOriginal))

		// Its identifying attributes must match the ones of the identity that
		// DeserializeIdentity would build from the very same serialized bytes.
		plainID, err := msp1.DeserializeIdentity(serializedID)
		require.NoError(t, err)
		require.Equal(t, plainID.GetIdentifier(), reconstructed.GetIdentifier())
		require.Equal(t, plainID.GetMSPIdentifier(), reconstructed.GetMSPIdentifier())
		require.Equal(t, plainID.GetOrganizationalUnits(), reconstructed.GetOrganizationalUnits())

		// GetPublicVersion must expose the same public identity that Serialize
		// would reproduce byte-for-byte.
		reconstructedSigningID, ok := reconstructed.(*signingIdentity)
		require.True(t, ok)
		pubBytes, err := reconstructedSigningID.GetPublicVersion().(Identity).Serialize()
		require.NoError(t, err)
		require.Equal(t, serializedID, pubBytes)

		require.Equal(t, msp1.signer.enrollmentId, reconstructedSigningID.enrollmentId)
	})
}

// TestDeserializeSigningIdentityRequiresPersistentKeyStore documents that
// DeserializeSigningIdentity cannot recover any nym - not even one belonging to
// the MSP's own default signer - when the MSP was set up without a persistent
// keystore.KVS (e.g. via setupCurve/NewIdemixMsp, which fall back to the
// non-persistent keystore.Dummy): the nym secret key derived during Setup is
// then never stored, so BCCSP.GetKey always fails to find it later.
func TestDeserializeSigningIdentityRequiresPersistentKeyStore(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurve(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		serializedID, err := id1.Serialize()
		require.NoError(t, err)

		_, err = msp1.DeserializeSigningIdentity(innerIdemixIDBytes(t, serializedID))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot find nym secret key")
	})
}

func TestDeserializeSigningIdentityBadInput(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithKeyStore(t, sc, "MSP1OU1")
		require.NoError(t, err)

		_, err = msp1.DeserializeSigningIdentity([]byte("barf"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not deserialize a SerializedIdemixIdentity")
	})
}

// TestDeserializeSigningIdentityRejectsOuterEnvelope documents that, unlike
// DeserializeIdentity, DeserializeSigningIdentity does not accept the outer
// SerializedIdentity envelope produced by identity.Serialize(): it must be
// given the inner SerializedIdemixIdentity bytes directly.
func TestDeserializeSigningIdentityRejectsOuterEnvelope(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithKeyStore(t, sc, "MSP1OU1")
		require.NoError(t, err)

		id1, err := getDefaultSigner(t, msp1)
		require.NoError(t, err)

		serializedID, err := id1.Serialize()
		require.NoError(t, err)

		// Passing the outer envelope (mspid + inner bytes) instead of just the
		// inner bytes must not silently succeed.
		_, err = msp1.DeserializeSigningIdentity(serializedID)
		require.Error(t, err)
	})
}

// TestDeserializeSigningIdentityCrossMSP shows that DeserializeSigningIdentity,
// unlike DeserializeIdentity, does not check the identity's MSP membership by
// itself: a well-formed identity belonging to a different MSP instance is
// rejected only because its nym secret key is not present in this MSP's own
// keystore, not because of an explicit MSP-id mismatch check. Both MSPs are
// backed by their own persistent keystore.KVS, so msp2's own round trip
// (checked implicitly by getDefaultSigner/id2.Validate) is known to work; the
// point here is that its result is still rejected by msp1.
func TestDeserializeSigningIdentityCrossMSP(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		msp1, err := setupCurveWithKeyStore(t, sc, "MSP1OU1")
		require.NoError(t, err)
		msp2, err := setupCurveWithKeyStore(t, sc, "MSP2OU1")
		require.NoError(t, err)

		id2, err := getDefaultSigner(t, msp2)
		require.NoError(t, err)

		serializedID2, err := id2.Serialize()
		require.NoError(t, err)

		// Sanity check: msp2 can reconstruct its own signing identity.
		_, err = msp2.DeserializeSigningIdentity(innerIdemixIDBytes(t, serializedID2))
		require.NoError(t, err)

		_, err = msp1.DeserializeSigningIdentity(innerIdemixIDBytes(t, serializedID2))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot find nym secret key")
	})
}

// TestDeserializeSigningIdentityNoDefaultSigner documents current behavior of
// DeserializeSigningIdentity on a verification-only MSP (one set up without
// signer key material, e.g. via setupCurveVerifier). Such an MSP never derives
// any nym key on its own csp, so DeserializeSigningIdentity fails on the "find
// the nym secret key" step for any identity - including one belonging to its
// own MSP id - before it ever reaches the unconditional msp.signer.Cred /
// msp.signer.UserKey / msp.signer.enrollmentId access that would otherwise
// nil-pointer-dereference given msp.signer == nil here.
func TestDeserializeSigningIdentityNoDefaultSigner(t *testing.T) {
	forEachSchemeCurve(t, func(t *testing.T, sc schemeCurve) {
		signerMsp, err := setupCurveWithKeyStore(t, sc, "MSP1OU1")
		require.NoError(t, err)
		id1, err := getDefaultSigner(t, signerMsp)
		require.NoError(t, err)
		serializedID, err := id1.Serialize()
		require.NoError(t, err)

		verMsp, err := setupCurveVerifier(t, sc, "MSP1OU1")
		require.NoError(t, err)
		require.Nil(t, verMsp.signer)

		_, err = verMsp.DeserializeSigningIdentity(innerIdemixIDBytes(t, serializedID))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot find nym secret key")
	})
}
