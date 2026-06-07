/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"github.com/pkg/errors"
)

func setupWithTypeAndVersion(configPath string, ID string, version MSPVersion, mspType ProviderType) (MSP, error) {
	var msp MSP
	var err error
	switch mspType {
	case IDEMIX:
		msp, err = NewIdemixMsp(version)
	case IDEMIX_ARIES:
		msp, err = NewIdemixMspAries(version)
	default:
		panic("programming error")
	}
	if err != nil {
		return nil, err
	}

	conf, err := GetIdemixMspConfigWithType(configPath, ID, mspType)
	if err != nil {
		return nil, errors.Wrap(err, "Getting MSP config failed")
	}

	err = msp.Setup(conf)
	if err != nil {
		return nil, errors.Wrap(err, "Setting up MSP failed")
	}
	return msp, nil
}

func getDefaultSigner(msp MSP) (SigningIdentity, error) {
	id, err := msp.GetDefaultSigningIdentity()
	if err != nil {
		return nil, errors.Wrap(err, "Getting default signing identity failed")
	}

	err = id.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "Default signing identity invalid")
	}

	err = msp.Validate(id)
	if err != nil {
		return nil, errors.Wrap(err, "Default signing identity invalid")
	}

	return id, nil
}
