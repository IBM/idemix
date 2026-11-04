/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

// Drop-in compatibility with the idemix v0.3.1 API (used by fabric-x-common).

// Aliases for the v0.3.1 type names.
type (
	Idemixmsp             = MSP
	Idemixidentity        = identity
	IdemixSigningIdentity = signingIdentity
)

// NewIdemixMsp is like NewMSP but returns the Provider interface.
// Setup auto-detects the scheme (dlog or Aries/BBS+).
func NewIdemixMsp(version MSPVersion) (Provider, error) {
	return NewIdemixMspWithLogger(version, nil)
}

// NewIdemixMspWithLogger is like NewMSPWithLogger but returns the Provider interface.
func NewIdemixMspWithLogger(version MSPVersion, logger Logger) (Provider, error) {
	return NewMSPWithLogger(version, logger)
}

// NewIdemixMspAries is equivalent to NewIdemixMsp: the scheme is auto-detected at Setup.
//
// Deprecated: use NewIdemixMsp.
func NewIdemixMspAries(version MSPVersion) (Provider, error) {
	return NewIdemixMsp(version)
}

// NewIdemixMspAriesWithLogger is equivalent to NewIdemixMspWithLogger.
//
// Deprecated: use NewIdemixMspWithLogger.
func NewIdemixMspAriesWithLogger(version MSPVersion, logger Logger) (Provider, error) {
	return NewIdemixMspWithLogger(version, logger)
}

// DeserializeIdentityInternal deserializes the inner SerializedIdemixIdentity bytes.
func (msp *MSP) DeserializeIdentityInternal(serializedID []byte) (Identity, error) {
	id, err := msp.deserializeIdentityInternal(serializedID)
	if err != nil {
		return nil, err
	}

	return id, nil
}
