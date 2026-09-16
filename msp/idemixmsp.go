/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	idemix "github.com/IBM/idemix/bccsp"
	"github.com/IBM/idemix/bccsp/keystore"
	idemixcrypto "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	bccsp "github.com/IBM/idemix/bccsp/types"
	im "github.com/IBM/idemix/msp/config"
	math "github.com/IBM/mathlib"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

const (
	// AttributeIndexOU contains the index of the OU attribute in the idemix credential attributes
	AttributeIndexOU = iota

	// AttributeIndexRole contains the index of the Role attribute in the idemix credential attributes
	AttributeIndexRole

	// AttributeIndexEnrollmentId contains the index of the Enrollment ID attribute in the idemix credential attributes
	AttributeIndexEnrollmentId

	// AttributeIndexRevocationHandle contains the index of the Revocation Handle attribute in the idemix credential attributes
	AttributeIndexRevocationHandle
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

type MSPVersion int

const (
	MSPv1_0 = iota
	MSPv1_1
	MSPv1_3
	MSPv1_4_3
)

// index of the revocation handle attribute in the credential
const rhIndex = 3
const eidIndex = 2

// Curve ID string constants matching the values written by idemixgen into IdemixMSPConfig.CurveId.
const (
	curveIDFP256BN_AMCL        = "FP256BN_AMCL"
	curveIDBN254               = "BN254"
	curveIDFP256BN_AMCL_MIRACL = "FP256BN_AMCL_MIRACL"
	curveIDBLS12_377_GURVY     = "BLS12_377_GURVY"
	curveIDBLS12_381_GURVY     = "BLS12_381_GURVY"
	curveIDBLS12_381           = "BLS12_381"
	curveIDBLS12_381_BBS       = "BLS12_381_BBS"
	curveIDBLS12_381_BBS_GURVY = "BLS12_381_BBS_GURVY"
)

// curveAndTranslator maps a curve_id string (as stored in IdemixMSPConfig) to the corresponding
// math.Curve and dlog Translator. Returns an error for unknown curve IDs.
func curveAndTranslator(curveID string) (*math.Curve, idemixcrypto.Translator, error) {
	switch curveID {
	case curveIDFP256BN_AMCL:
		c := math.Curves[math.FP256BN_AMCL]

		return c, &amcl.Fp256bn{C: c}, nil
	case curveIDBN254:
		c := math.Curves[math.BN254]

		return c, &amcl.Gurvy{C: c}, nil
	case curveIDFP256BN_AMCL_MIRACL:
		c := math.Curves[math.FP256BN_AMCL_MIRACL]

		return c, &amcl.Fp256bnMiracl{C: c}, nil
	case curveIDBLS12_377_GURVY:
		c := math.Curves[math.BLS12_377_GURVY]

		return c, &amcl.Gurvy{C: c}, nil
	case curveIDBLS12_381_GURVY:
		c := math.Curves[math.BLS12_381_GURVY]

		return c, &amcl.Gurvy{C: c}, nil
	case curveIDBLS12_381:
		c := math.Curves[math.BLS12_381]

		return c, &amcl.Gurvy{C: c}, nil
	case curveIDBLS12_381_BBS:
		c := math.Curves[math.BLS12_381_BBS]

		return c, &amcl.Gurvy{C: c}, nil
	case curveIDBLS12_381_BBS_GURVY:
		c := math.Curves[math.BLS12_381_BBS_GURVY]

		return c, &amcl.Gurvy{C: c}, nil
	default:
		return nil, nil, fmt.Errorf("unknown curve id %q", curveID)
	}
}

// cspConstructor matches the shared signature of idemix.New and idemix.NewAries.
type cspConstructor func(keyStore bccsp.KeyStore, curve *math.Curve, translator idemixcrypto.Translator, exportable bool) (bccsp.BCCSP, error)

type msp struct {
	csp          bccsp.BCCSP
	version      MSPVersion
	ipk          bccsp.Key
	signer       *signingIdentity
	name         string
	revocationPK bccsp.Key
	epoch        int
	logger       Logger
	exportable   bool
	conf         *im.IdemixMSPConfig
}

// NewIdemixMsp creates a new instance of msp. Setup auto-detects the underlying
// cryptographic scheme (dlog or Aries/BBS+) from the key material in the config: it first
// attempts to load the config using the dlog scheme and, if that fails, retries using the
// Aries/BBS+ scheme. Any curve supported by curveAndTranslator is accepted by either scheme;
// the curve is determined at Setup time from IdemixMSPConfig.CurveId (default: FP256BN_AMCL
// for dlog, BLS12_381_BBS for Aries).
func NewIdemixMsp(version MSPVersion) (MSP, error) {
	return NewIdemixMspWithLogger(version, newDefaultLogger("idemix"))
}

// NewIdemixMspWithLogger creates a new instance of idemixmsp with a custom logger. See
// NewIdemixMsp for the scheme auto-detection and curve-selection behavior of Setup.
// If logger is nil, the default logger is used.
func NewIdemixMspWithLogger(version MSPVersion, logger Logger) (MSP, error) {
	if logger == nil {
		logger = newDefaultLogger("idemix")
	}
	logger.Debugf("Creating Idemix-based MSP instance")
	msp := msp{logger: logger, version: version, exportable: true}

	return &msp, nil
}

func (msp *msp) Setup(conf1 *m.MSPConfig) error {
	msp.logger.Debugf("Setting up Idemix-based MSP instance")

	if conf1 == nil {
		return errors.New("setup error: nil conf reference")
	}

	var conf im.IdemixMSPConfig
	err := proto.Unmarshal(conf1.Config, &conf)
	if err != nil {
		return fmt.Errorf("failed unmarshalling idemix msp config: %w", err)
	}

	msp.name = conf.Name
	msp.conf = &conf
	msp.logger.Debugf("Setting up Idemix MSP instance %s", msp.name)

	if conf1.Type != int32(IDEMIX) {
		return fmt.Errorf("setup error: unsupported config type %d, expected IDEMIX", conf1.Type)
	}

	// Auto-detect the underlying cryptographic scheme (dlog or Aries/BBS+) from the key
	// material: attempt the dlog scheme first and, if that fails, retry with Aries/BBS+.
	// Any curve supported by curveAndTranslator is accepted by either scheme.
	newDlogCSP := func(keyStore bccsp.KeyStore, curve *math.Curve, translator idemixcrypto.Translator, exportable bool) (bccsp.BCCSP, error) {
		return idemix.New(keyStore, curve, translator, exportable)
	}
	newAriesCSP := func(keyStore bccsp.KeyStore, curve *math.Curve, translator idemixcrypto.Translator, exportable bool) (bccsp.BCCSP, error) {
		return idemix.NewAries(keyStore, curve, translator, exportable)
	}

	dlogErr := msp.setupWithScheme(newDlogCSP, curveIDFP256BN_AMCL, &conf)
	if dlogErr == nil {
		msp.logger.Debugf("Idemix MSP instance %s set up using the dlog scheme", msp.name)

		return nil
	}

	msp.logger.Debugf("dlog scheme setup failed for Idemix MSP instance %s, retrying with Aries/BBS+: %v", msp.name, dlogErr)
	msp.resetCryptoMaterial()

	ariesErr := msp.setupWithScheme(newAriesCSP, curveIDBLS12_381_BBS, &conf)
	if ariesErr == nil {
		msp.logger.Debugf("Idemix MSP instance %s set up using the Aries/BBS+ scheme", msp.name)

		return nil
	}

	msp.resetCryptoMaterial()

	return fmt.Errorf("setup error: %w", errors.Join(dlogErr, ariesErr))
}

// resetCryptoMaterial clears the fields written by setupWithScheme, so a failed attempt does
// not leave partial state visible to a subsequent attempt or to callers.
func (msp *msp) resetCryptoMaterial() {
	msp.csp = nil
	msp.ipk = nil
	msp.revocationPK = nil
	msp.signer = nil
}

// setupWithScheme builds msp's BCCSP using newCSP and the curve named by conf.CurveId
// (defaultCurveID when unset), then imports the issuer public key, revocation public key,
// and - if present - the default signer's credential material.
func (msp *msp) setupWithScheme(newCSP cspConstructor, defaultCurveID string, conf *im.IdemixMSPConfig) error {
	curveID := conf.CurveId
	if curveID == "" {
		curveID = defaultCurveID
	}

	curve, tr, err := curveAndTranslator(curveID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	csp, err := newCSP(&keystore.Dummy{}, curve, tr, msp.exportable)
	if err != nil {
		return fmt.Errorf("failed to create BCCSP: %w", err)
	}
	msp.csp = csp

	// Import Issuer Public Key
	IssuerPublicKey, err := msp.csp.KeyImport(
		conf.Ipk,
		&bccsp.IdemixIssuerPublicKeyImportOpts{
			Temporary: true,
			AttributeNames: []string{
				AttributeNameOU,
				AttributeNameRole,
				AttributeNameEnrollmentId,
				AttributeNameRevocationHandle,
			},
		})
	if err != nil {
		var importErr *bccsp.IdemixIssuerPublicKeyImporterError
		ok := errors.As(err, &importErr)
		if !ok {
			// Not every scheme wraps its errors in *bccsp.IdemixIssuerPublicKeyImporterError
			// (e.g. the Aries importer does not) - treat this as an unmarshalling failure
			// rather than panicking on attacker-controlled config bytes.
			return fmt.Errorf("failed to unmarshal ipk from idemix msp config: %w", err)
		}
		switch importErr.Type {
		case bccsp.IdemixIssuerPublicKeyImporterUnmarshallingError:
			return fmt.Errorf("failed to unmarshal ipk from idemix msp config: %w", err)
		case bccsp.IdemixIssuerPublicKeyImporterHashError:
			return fmt.Errorf("setting the hash of the issuer public key failed: %w", err)
		case bccsp.IdemixIssuerPublicKeyImporterValidationError:
			return fmt.Errorf("cannot setup idemix msp with invalid public key: %w", err)
		case bccsp.IdemixIssuerPublicKeyImporterNumAttributesError:
			fallthrough
		case bccsp.IdemixIssuerPublicKeyImporterAttributeNameError:
			return errors.New("issuer public key must have attributes OU, Role, EnrollmentId, and RevocationHandle")
		default:
			return fmt.Errorf("unexpected condition, issuer public key import error not valid, got [%d]", importErr.Type)
		}
	}
	msp.ipk = IssuerPublicKey

	// Import revocation public key
	RevocationPublicKey, err := msp.csp.KeyImport(
		conf.RevocationPk,
		&bccsp.IdemixRevocationPublicKeyImportOpts{Temporary: true},
	)
	if err != nil {
		return fmt.Errorf("failed to import revocation public key: %w", err)
	}
	msp.revocationPK = RevocationPublicKey

	if conf.Signer == nil {
		// No credential in config, so we don't setup a default signer
		msp.logger.Debug("idemix msp setup as verification only msp (no key material found)")

		return nil
	}

	// A credential is present in the config, so we setup a default signer

	// Import User secret key
	UserKey, err := msp.csp.KeyImport(conf.Signer.Sk, &bccsp.IdemixUserSecretKeyImportOpts{Temporary: true})
	if err != nil {
		return fmt.Errorf("failed importing signer secret key: %w", err)
	}

	// Derive NymPublicKey
	NymKey, err := msp.csp.KeyDeriv(UserKey, &bccsp.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: IssuerPublicKey})
	if err != nil {
		return fmt.Errorf("failed deriving nym: %w", err)
	}
	NymPublicKey, err := NymKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed getting public nym key: %w", err)
	}

	role := &m.MSPRole{
		MspIdentifier: msp.name,
		Role:          m.MSPRole_MEMBER,
	}
	if CheckRole(int(conf.Signer.Role), ADMIN) {
		role.Role = m.MSPRole_ADMIN
	}

	ou := &m.OrganizationUnit{
		MspIdentifier:                msp.name,
		OrganizationalUnitIdentifier: conf.Signer.OrganizationalUnitIdentifier,
		CertifiersIdentifier:         IssuerPublicKey.SKI(),
	}

	enrollmentId := conf.Signer.EnrollmentId

	// Verify credential
	valid, err := msp.csp.Verify(
		UserKey,
		conf.Signer.Cred,
		nil,
		&bccsp.IdemixCredentialSignerOpts{
			IssuerPK: IssuerPublicKey,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte(conf.Signer.OrganizationalUnitIdentifier)},
				{Type: bccsp.IdemixIntAttribute, Value: getIdemixRoleFromMSPRole(role)},
				{Type: bccsp.IdemixBytesAttribute, Value: []byte(enrollmentId)},
				{Type: bccsp.IdemixHiddenAttribute},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("credential is not cryptographically valid: %w", err)
	}
	if !valid {
		return errors.New("credential is not cryptographically valid")
	}

	// Create the cryptographic evidence that this identity is valid
	proof, err := msp.csp.Sign(
		UserKey,
		nil,
		&bccsp.IdemixSignerOpts{
			Credential: conf.Signer.Cred,
			Nym:        NymKey,
			IssuerPK:   IssuerPublicKey,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute},
				{Type: bccsp.IdemixIntAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:  rhIndex,
			EidIndex: eidIndex,
			CRI:      conf.Signer.CredentialRevocationInformation,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to setup cryptographic proof of identity: %w", err)
	}

	// Set up default signer
	msp.signer = NewSigningIdentity(
		NewIdemixIdentity(msp, NymPublicKey, role, ou, proof),
		conf.Signer.Cred,
		UserKey,
		NymKey,
		enrollmentId,
	)

	return nil
}

// GetVersion returns the version of this MSP
func (msp *msp) GetVersion() MSPVersion {
	return msp.version
}

func (msp *msp) GetType() ProviderType {
	return IDEMIX
}

func (msp *msp) GetIdentifier() (string, error) {
	return msp.name, nil
}

func (msp *msp) GetDefaultSigningIdentity() (SigningIdentity, error) {
	msp.logger.Debugf("Obtaining default idemix signing identity")

	if msp.signer == nil {
		return nil, errors.New("no default signer setup")
	}

	return msp.signer, nil
}

func (msp *msp) DeserializeIdentity(serializedID []byte) (Identity, error) {
	sID := &m.SerializedIdentity{}
	err := proto.Unmarshal(serializedID, sID)
	if err != nil {
		return nil, fmt.Errorf("could not deserialize a SerializedIdentity: %w", err)
	}

	if sID.Mspid != msp.name {
		return nil, fmt.Errorf("expected MSP ID %s, received %s", msp.name, sID.Mspid)
	}

	return msp.DeserializeIdentityInternal(sID.GetIdBytes())
}

func (msp *msp) DeserializeIdentityInternal(serializedID []byte) (Identity, error) {
	msp.logger.Debug("idemixmsp: deserializing identity")
	serialized := new(im.SerializedIdemixIdentity)
	err := proto.Unmarshal(serializedID, serialized)
	if err != nil {
		return nil, fmt.Errorf("could not deserialize a SerializedIdemixIdentity: %w", err)
	}
	if serialized.NymX == nil || serialized.NymY == nil {
		return nil, errors.New("unable to deserialize idemix identity: pseudonym is invalid")
	}

	// Import NymPublicKey
	var rawNymPublicKey []byte
	rawNymPublicKey = append(rawNymPublicKey, serialized.NymX...)
	rawNymPublicKey = append(rawNymPublicKey, serialized.NymY...)
	NymPublicKey, err := msp.csp.KeyImport(
		rawNymPublicKey,
		&bccsp.IdemixNymPublicKeyImportOpts{Temporary: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to import nym public key: %w", err)
	}

	// OU
	ou := &m.OrganizationUnit{}
	err = proto.Unmarshal(serialized.Ou, ou)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the OU of the identity: %w", err)
	}

	// Role
	role := &m.MSPRole{}
	err = proto.Unmarshal(serialized.Role, role)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the role of the identity: %w", err)
	}

	return NewIdemixIdentity(msp, NymPublicKey, role, ou, serialized.Proof), nil
}

func (msp *msp) Validate(id Identity) error {
	temp, err := asIdentity(id)
	if err != nil {
		return err
	}

	msp.logger.Debugf("Validating identity %+v", temp)
	if temp.GetMSPIdentifier() != msp.name {
		return errors.New("the supplied identity does not belong to this msp")
	}

	return temp.Validate()
}

func (msp *msp) SatisfiesPrincipal(id Identity, principal *m.MSPPrincipal) error {
	if err := msp.Validate(id); err != nil {
		return fmt.Errorf("identity is not valid with respect to this MSP: %w", err)
	}

	temp, err := asIdentity(id)
	if err != nil {
		return err
	}

	return temp.satisfiesPrincipalValidated(principal)
}

// IsWellFormed checks if the given identity can be deserialized into its provider-specific .
// In this MSP implementation, an identity is considered well formed if it contains a
// marshaled SerializedIdemixIdentity protobuf message.
func (msp *msp) IsWellFormed(identity *m.SerializedIdentity) error {
	sId := new(im.SerializedIdemixIdentity)
	err := proto.Unmarshal(identity.IdBytes, sId)
	if err != nil {
		return fmt.Errorf("not an idemix identity: %w", err)
	}

	return nil
}

func (msp *msp) GetTLSRootCerts() [][]byte {
	// TODO
	return nil
}

func (msp *msp) GetTLSIntermediateCerts() [][]byte {
	// TODO
	return nil
}

func (msp *msp) Pseudonym() (SigningIdentity, []byte, error) {
	// Derive NymPublicKey
	nymKey, err := msp.csp.KeyDeriv(
		msp.signer.UserKey,
		&bccsp.IdemixNymKeyDerivationOpts{
			Temporary: true,
			IssuerPK:  msp.ipk,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed deriving nym: %w", err)
	}
	NymPublicKey, err := nymKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting public nym key: %w", err)
	}

	role := &m.MSPRole{
		MspIdentifier: msp.name,
		Role:          m.MSPRole_MEMBER,
	}
	if CheckRole(int(msp.conf.Signer.Role), ADMIN) {
		role.Role = m.MSPRole_ADMIN
	}

	ou := &m.OrganizationUnit{
		MspIdentifier:                msp.name,
		OrganizationalUnitIdentifier: msp.conf.Signer.OrganizationalUnitIdentifier,
		CertifiersIdentifier:         msp.ipk.SKI(),
	}

	enrollmentID := msp.conf.Signer.EnrollmentId

	// Create the cryptographic evidence that this identity is valid
	sigOpts := &bccsp.IdemixSignerOpts{
		Credential: msp.conf.Signer.Cred,
		Nym:        nymKey,
		IssuerPK:   msp.ipk,
		Attributes: []bccsp.IdemixAttribute{
			{Type: bccsp.IdemixBytesAttribute},
			{Type: bccsp.IdemixIntAttribute},
			{Type: bccsp.IdemixHiddenAttribute},
			{Type: bccsp.IdemixHiddenAttribute},
		},
		RhIndex:  rhIndex,
		EidIndex: eidIndex,
		CRI:      msp.conf.Signer.CredentialRevocationInformation,
		SigType:  bccsp.Standard,
	}
	proof, err := msp.csp.Sign(
		msp.signer.UserKey,
		nil,
		sigOpts,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed signing identity: %w", err)
	}

	// Set up default signer
	id := NewIdemixIdentity(msp, NymPublicKey, role, ou, proof)

	return NewSigningIdentity(id, msp.signer.Cred, msp.signer.UserKey, nymKey, enrollmentID), nil, nil
}

func (msp *msp) EnrollmentID() string {
	return msp.conf.Signer.EnrollmentId
}

type identity struct {
	NymPublicKey bccsp.Key
	id           *IdentityIdentifier
	Role         *m.MSPRole
	OU           *m.OrganizationUnit
	// associationProof contains cryptographic proof that this identity
	// belongs to the MSP identified by mspIdentifier, i.e., it proves that
	// the pseudonym is constructed from a secret key on which the CA issued
	// a credential.
	associationProof []byte
	msp              *msp
}

// asIdentity extracts the underlying *identity from an Identity, whether it wraps a
// plain identity or a signingIdentity.
func asIdentity(id Identity) (*identity, error) {
	switch t := id.(type) {
	case *identity:
		return t, nil
	case *signingIdentity:
		return t.identity, nil
	default:
		return nil, fmt.Errorf("identity type %T is not recognized", t)
	}
}

func NewIdemixIdentity(
	msp *msp,
	NymPublicKey bccsp.Key,
	role *m.MSPRole,
	ou *m.OrganizationUnit,
	proof []byte,
) *identity {
	id := &identity{}
	id.msp = msp
	id.NymPublicKey = NymPublicKey
	id.Role = role
	id.OU = ou
	id.associationProof = proof

	raw, err := NymPublicKey.Bytes()
	if err != nil {
		panic(fmt.Sprintf("unexpected condition, failed marshalling nym public key [%s]", err))
	}
	id.id = &IdentityIdentifier{
		Mspid: msp.name,
		Id:    bytes.NewBuffer(raw).String(),
	}

	return id
}

func (id *identity) Anonymous() bool {
	return true
}

func (id *identity) ExpiresAt() time.Time {
	// Idemix MSP currently does not use expiration dates or revocation,
	// so we return the zero time to indicate this.
	return time.Time{}
}

func (id *identity) GetIdentifier() *IdentityIdentifier {
	return id.id
}

func (id *identity) GetMSPIdentifier() string {
	return id.msp.name
}

func (id *identity) GetOrganizationalUnits() []*OUIdentifier {
	// we use the (serialized) public key of this MSP as the CertifiersIdentifier
	certifiersIdentifier, err := id.msp.ipk.Bytes()
	if err != nil {
		id.msp.logger.Errorf("failed to marshal ipk in GetOrganizationalUnits: %s", err)

		return nil
	}

	return []*OUIdentifier{{certifiersIdentifier, id.OU.OrganizationalUnitIdentifier}}
}

func (id *identity) Validate() error {
	return id.verifyProof()
}

func (id *identity) Verify(msg []byte, sig []byte) error {
	if id.msp.logger.IsEnabledFor(zapcore.DebugLevel) {
		id.msp.logger.Debugf("Verify Idemix sig: msg = %s", hex.Dump(msg))
		id.msp.logger.Debugf("Verify Idemix sig: sig = %s", hex.Dump(sig))
	}

	_, err := id.msp.csp.Verify(
		id.NymPublicKey,
		sig,
		msg,
		&bccsp.IdemixNymSignerOpts{
			IssuerPK: id.msp.ipk,
		},
	)

	return err
}

func (id *identity) SatisfiesPrincipal(principal *m.MSPPrincipal) error {
	if err := id.Validate(); err != nil {
		return fmt.Errorf("identity is not valid with respect to this MSP: %w", err)
	}

	return id.satisfiesPrincipalValidated(principal)
}

// satisfiesPrincipalValidated performs all the tasks of SatisfiesPrincipal except the identity validation,
// such that combined principals will not cause multiple expensive identity validations.
func (id *identity) satisfiesPrincipalValidated(principal *m.MSPPrincipal) error {
	switch principal.PrincipalClassification {
	// in this case, we have to check whether the
	// identity has a role in the msp - member or admin
	case m.MSPPrincipal_ROLE:
		// Principal contains the msp role
		mspRole := &m.MSPRole{}
		err := proto.Unmarshal(principal.Principal, mspRole)
		if err != nil {
			return fmt.Errorf("could not unmarshal MSPRole from principal: %w", err)
		}

		// at first, we check whether the MSP
		// identifier is the same as that of the identity
		if mspRole.MspIdentifier != id.msp.name {
			return fmt.Errorf("the identity is a member of a different MSP (expected %s, got %s)", mspRole.MspIdentifier, id.GetMSPIdentifier())
		}

		// now we validate the different msp roles
		switch mspRole.Role {
		case m.MSPRole_MEMBER:
			// in the case of member, we simply check
			// whether this identity is valid for the MSP
			id.msp.logger.Debugf("Checking if identity satisfies MEMBER role for %s", id.msp.name)

			return nil
		case m.MSPRole_ADMIN:
			id.msp.logger.Debugf("Checking if identity satisfies ADMIN role for %s", id.msp.name)
			if id.Role.Role != m.MSPRole_ADMIN {
				return errors.New("user is not an admin")
			}

			return nil
		case m.MSPRole_PEER:
			if id.msp.version >= MSPv1_3 {
				return errors.New("idemixmsp only supports client use, so it cannot satisfy an MSPRole PEER principal")
			}

			fallthrough
		case m.MSPRole_CLIENT:
			if id.msp.version >= MSPv1_3 {
				return nil // any valid idemixmsp member must be a client
			}

			fallthrough
		default:
			return fmt.Errorf("invalid MSP role type %d", int32(mspRole.Role))
		}
		// in this case we have to serialize this instance
		// and compare it byte-by-byte with Principal
	case m.MSPPrincipal_IDENTITY:
		id.msp.logger.Debugf("Checking if identity satisfies IDENTITY principal")
		idBytes, err := id.Serialize()
		if err != nil {
			return fmt.Errorf("could not serialize this identity instance: %w", err)
		}

		rv := bytes.Compare(idBytes, principal.Principal)
		if rv == 0 {
			return nil
		}

		return errors.New("the identities do not match")

	case m.MSPPrincipal_ORGANIZATION_UNIT:
		ou := &m.OrganizationUnit{}
		err := proto.Unmarshal(principal.Principal, ou)
		if err != nil {
			return fmt.Errorf("could not unmarshal OU from principal: %w", err)
		}

		id.msp.logger.Debugf("Checking if identity is part of OU \"%s\" of mspid \"%s\"", ou.OrganizationalUnitIdentifier, ou.MspIdentifier)

		// at first, we check whether the MSP
		// identifier is the same as that of the identity
		if ou.MspIdentifier != id.msp.name {
			return fmt.Errorf("the identity is a member of a different MSP (expected %s, got %s)", ou.MspIdentifier, id.GetMSPIdentifier())
		}

		if ou.OrganizationalUnitIdentifier != id.OU.OrganizationalUnitIdentifier {
			return errors.New("user is not part of the desired organizational unit")
		}

		return nil
	case m.MSPPrincipal_COMBINED:
		if id.msp.version <= MSPv1_1 {
			return errors.New("combined MSP Principals are unsupported in MSPv1_1")
		}

		// Principal is a combination of multiple principals.
		principals := &m.CombinedPrincipal{}
		err := proto.Unmarshal(principal.Principal, principals)
		if err != nil {
			return fmt.Errorf("could not unmarshal CombinedPrincipal from principal: %w", err)
		}
		// Return an error if there are no principals in the combined principal.
		if len(principals.Principals) == 0 {
			return errors.New("no principals in CombinedPrincipal")
		}
		// Recursively call satisfiesPrincipalValidated for all combined principals.
		// There is no limit for the levels of nesting for the combined principals.
		for _, cp := range principals.Principals {
			err = id.satisfiesPrincipalValidated(cp)
			if err != nil {
				return err
			}
		}
		// The identity satisfies all the principals
		return nil
	case m.MSPPrincipal_ANONYMITY:
		if id.msp.version <= MSPv1_1 {
			return errors.New("anonymity MSP Principals are unsupported in MSPv1_1")
		}

		anon := &m.MSPIdentityAnonymity{}
		err := proto.Unmarshal(principal.Principal, anon)
		if err != nil {
			return fmt.Errorf("could not unmarshal MSPIdentityAnonymity from principal: %w", err)
		}
		switch anon.AnonymityType {
		case m.MSPIdentityAnonymity_ANONYMOUS:
			return nil
		case m.MSPIdentityAnonymity_NOMINAL:
			return errors.New("principal is nominal, but idemix MSP is anonymous")
		default:
			return fmt.Errorf("unknown principal anonymity type: %d", anon.AnonymityType)
		}
	default:
		return fmt.Errorf("invalid principal type %d", int32(principal.PrincipalClassification))
	}
}

func (id *identity) Serialize() ([]byte, error) {
	serialized := &im.SerializedIdemixIdentity{}

	raw, err := id.NymPublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("could not serialize nym of identity %s: %w", id.id, err)
	}
	// This is an assumption on how the underlying idemix implementation work.
	// TODO: change this in future version
	serialized.NymX = raw[:len(raw)/2]
	serialized.NymY = raw[len(raw)/2:]
	ouBytes, err := proto.Marshal(id.OU)
	if err != nil {
		return nil, fmt.Errorf("could not marshal OU of identity %s: %w", id.id, err)
	}

	roleBytes, err := proto.Marshal(id.Role)
	if err != nil {
		return nil, fmt.Errorf("could not marshal role of identity %s: %w", id.id, err)
	}

	serialized.Ou = ouBytes
	serialized.Role = roleBytes
	serialized.Proof = id.associationProof

	idemixIDBytes, err := proto.Marshal(serialized)
	if err != nil {
		return nil, err
	}

	sID := &m.SerializedIdentity{Mspid: id.GetMSPIdentifier(), IdBytes: idemixIDBytes}
	idBytes, err := proto.Marshal(sID)
	if err != nil {
		return nil, fmt.Errorf("could not marshal a SerializedIdentity structure for identity %s: %w", id.id, err)
	}

	return idBytes, nil
}

func (id *identity) verifyProof() error {
	// Verify signature
	valid, err := id.msp.csp.Verify(
		id.msp.ipk,
		id.associationProof,
		nil,
		&bccsp.IdemixSignerOpts{
			RevocationPublicKey: id.msp.revocationPK,
			Attributes: []bccsp.IdemixAttribute{
				{Type: bccsp.IdemixBytesAttribute, Value: []byte(id.OU.OrganizationalUnitIdentifier)},
				{Type: bccsp.IdemixIntAttribute, Value: getIdemixRoleFromMSPRole(id.Role)},
				{Type: bccsp.IdemixHiddenAttribute},
				{Type: bccsp.IdemixHiddenAttribute},
			},
			RhIndex:  rhIndex,
			EidIndex: eidIndex,
			Epoch:    id.msp.epoch,
			Nym:      id.NymPublicKey,
		},
	)
	if err == nil && !valid {
		panic("unexpected condition, an error should be returned for an invalid signature")
	}

	return err
}

type signingIdentity struct {
	*identity
	Cred         []byte
	UserKey      bccsp.Key
	NymKey       bccsp.Key
	enrollmentId string
}

func NewSigningIdentity(
	identity *identity,
	cred []byte,
	userKey bccsp.Key,
	nymKey bccsp.Key,
	enrollmentId string,
) *signingIdentity {
	return &signingIdentity{identity: identity, Cred: cred, UserKey: userKey, NymKey: nymKey, enrollmentId: enrollmentId}
}

func (id *signingIdentity) Sign(msg []byte) ([]byte, error) {
	id.msp.logger.Debugf("Idemix identity %s is signing", id.GetIdentifier())

	sig, err := id.msp.csp.Sign(
		id.UserKey,
		msg,
		&bccsp.IdemixNymSignerOpts{
			Nym:      id.NymKey,
			IssuerPK: id.msp.ipk,
		},
	)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (id *signingIdentity) GetPublicVersion() Identity {
	return id.identity
}
