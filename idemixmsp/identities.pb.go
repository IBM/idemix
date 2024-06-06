// Code generated by protoc-gen-go. DO NOT EDIT.
// source: idemixmsp/identities.proto

package idemixmsp

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// This struct represents an Idemix Identity
// to be used to serialize it and deserialize it.
// The IdemixMSP will first serialize an idemix identity to bytes using
// this proto, and then uses these bytes as id_bytes in SerializedIdentity
type SerializedIdemixIdentity struct {
	// nym_x is the X-component of the pseudonym elliptic curve point.
	// It is a []byte representation of an amcl.BIG
	// The pseudonym can be seen as a public key of the identity, it is used to verify signatures.
	NymX []byte `protobuf:"bytes,1,opt,name=nym_x,json=nymX,proto3" json:"nym_x,omitempty"`
	// nym_y is the Y-component of the pseudonym elliptic curve point.
	// It is a []byte representation of an amcl.BIG
	// The pseudonym can be seen as a public key of the identity, it is used to verify signatures.
	NymY []byte `protobuf:"bytes,2,opt,name=nym_y,json=nymY,proto3" json:"nym_y,omitempty"`
	// ou contains the organizational unit of the idemix identity
	Ou []byte `protobuf:"bytes,3,opt,name=ou,proto3" json:"ou,omitempty"`
	// role contains the role of this identity (e.g., ADMIN or MEMBER)
	Role []byte `protobuf:"bytes,4,opt,name=role,proto3" json:"role,omitempty"`
	// proof contains the cryptographic evidence that this identity is valid
	Proof []byte `protobuf:"bytes,5,opt,name=proof,proto3" json:"proof,omitempty"`
	// schema contains the version of the schema used by this credential
	Schema               string   `protobuf:"bytes,6,opt,name=schema,proto3" json:"schema,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SerializedIdemixIdentity) Reset()         { *m = SerializedIdemixIdentity{} }
func (m *SerializedIdemixIdentity) String() string { return proto.CompactTextString(m) }
func (*SerializedIdemixIdentity) ProtoMessage()    {}
func (*SerializedIdemixIdentity) Descriptor() ([]byte, []int) {
	return fileDescriptor_cb8a4544fc71d2d8, []int{0}
}

func (m *SerializedIdemixIdentity) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SerializedIdemixIdentity.Unmarshal(m, b)
}
func (m *SerializedIdemixIdentity) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SerializedIdemixIdentity.Marshal(b, m, deterministic)
}
func (m *SerializedIdemixIdentity) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SerializedIdemixIdentity.Merge(m, src)
}
func (m *SerializedIdemixIdentity) XXX_Size() int {
	return xxx_messageInfo_SerializedIdemixIdentity.Size(m)
}
func (m *SerializedIdemixIdentity) XXX_DiscardUnknown() {
	xxx_messageInfo_SerializedIdemixIdentity.DiscardUnknown(m)
}

var xxx_messageInfo_SerializedIdemixIdentity proto.InternalMessageInfo

func (m *SerializedIdemixIdentity) GetNymX() []byte {
	if m != nil {
		return m.NymX
	}
	return nil
}

func (m *SerializedIdemixIdentity) GetNymY() []byte {
	if m != nil {
		return m.NymY
	}
	return nil
}

func (m *SerializedIdemixIdentity) GetOu() []byte {
	if m != nil {
		return m.Ou
	}
	return nil
}

func (m *SerializedIdemixIdentity) GetRole() []byte {
	if m != nil {
		return m.Role
	}
	return nil
}

func (m *SerializedIdemixIdentity) GetProof() []byte {
	if m != nil {
		return m.Proof
	}
	return nil
}

func (m *SerializedIdemixIdentity) GetSchema() string {
	if m != nil {
		return m.Schema
	}
	return ""
}

func init() {
	proto.RegisterType((*SerializedIdemixIdentity)(nil), "idemixmsp.SerializedIdemixIdentity")
}

func init() { proto.RegisterFile("idemixmsp/identities.proto", fileDescriptor_cb8a4544fc71d2d8) }

var fileDescriptor_cb8a4544fc71d2d8 = []byte{
	// 251 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0xca, 0x4c, 0x49, 0xcd,
	0xcd, 0xac, 0xc8, 0x2d, 0x2e, 0xd0, 0xcf, 0x4c, 0x49, 0xcd, 0x2b, 0xc9, 0x2c, 0xc9, 0x4c, 0x2d,
	0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0xcb, 0x29, 0x4d, 0x63, 0xe4, 0x92, 0x08,
	0x4e, 0x2d, 0xca, 0x4c, 0xcc, 0xc9, 0xac, 0x4a, 0x4d, 0xf1, 0x04, 0x8b, 0x7b, 0x42, 0xd4, 0x57,
	0x0a, 0x09, 0x73, 0xb1, 0xe6, 0x55, 0xe6, 0xc6, 0x57, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0xf0, 0x04,
	0xb1, 0xe4, 0x55, 0xe6, 0x46, 0xc0, 0x04, 0x2b, 0x25, 0x98, 0xe0, 0x82, 0x91, 0x42, 0x7c, 0x5c,
	0x4c, 0xf9, 0xa5, 0x12, 0xcc, 0x60, 0x11, 0xa6, 0xfc, 0x52, 0x21, 0x21, 0x2e, 0x96, 0xa2, 0xfc,
	0x9c, 0x54, 0x09, 0x16, 0x88, 0x1a, 0x10, 0x5b, 0x48, 0x84, 0x8b, 0xb5, 0xa0, 0x28, 0x3f, 0x3f,
	0x4d, 0x82, 0x15, 0x2c, 0x08, 0xe1, 0x08, 0x89, 0x71, 0xb1, 0x15, 0x27, 0x67, 0xa4, 0xe6, 0x26,
	0x4a, 0xb0, 0x29, 0x30, 0x6a, 0x70, 0x06, 0x41, 0x79, 0x4e, 0xad, 0x8c, 0x5c, 0xbc, 0xc9, 0xf9,
	0xb9, 0x7a, 0x70, 0xa7, 0x3a, 0xf1, 0x7b, 0xc2, 0xfd, 0x11, 0x00, 0xf2, 0x46, 0x00, 0x63, 0x94,
	0x7c, 0x7a, 0x66, 0x49, 0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0xbe, 0xa7, 0x93, 0xaf, 0x3e,
	0x44, 0xb1, 0x3e, 0x5c, 0xcf, 0x22, 0x26, 0x66, 0xcf, 0x88, 0x88, 0x55, 0x4c, 0x9c, 0x9e, 0x30,
	0x91, 0x53, 0x48, 0xec, 0x47, 0x4c, 0xa2, 0x70, 0x76, 0x8c, 0x7b, 0x80, 0x93, 0x6f, 0x6a, 0x49,
	0x62, 0x4a, 0x62, 0x49, 0xe2, 0x2b, 0x24, 0x35, 0x49, 0x6c, 0xe0, 0x20, 0x33, 0x06, 0x04, 0x00,
	0x00, 0xff, 0xff, 0xe1, 0xc8, 0xcf, 0x4f, 0x50, 0x01, 0x00, 0x00,
}
