// Code generated by protoc-gen-go. DO NOT EDIT.
// source: bccsp/schemes/aries/cred.proto

package aries

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

// Credential specifies a credential object
type Credential struct {
	Cred                 []byte   `protobuf:"bytes,1,opt,name=cred,proto3" json:"cred,omitempty"`
	Attrs                [][]byte `protobuf:"bytes,2,rep,name=attrs,proto3" json:"attrs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Credential) Reset()         { *m = Credential{} }
func (m *Credential) String() string { return proto.CompactTextString(m) }
func (*Credential) ProtoMessage()    {}
func (*Credential) Descriptor() ([]byte, []int) {
	return fileDescriptor_57701eac61520cf0, []int{0}
}

func (m *Credential) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Credential.Unmarshal(m, b)
}
func (m *Credential) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Credential.Marshal(b, m, deterministic)
}
func (m *Credential) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Credential.Merge(m, src)
}
func (m *Credential) XXX_Size() int {
	return xxx_messageInfo_Credential.Size(m)
}
func (m *Credential) XXX_DiscardUnknown() {
	xxx_messageInfo_Credential.DiscardUnknown(m)
}

var xxx_messageInfo_Credential proto.InternalMessageInfo

func (m *Credential) GetCred() []byte {
	if m != nil {
		return m.Cred
	}
	return nil
}

func (m *Credential) GetAttrs() [][]byte {
	if m != nil {
		return m.Attrs
	}
	return nil
}

func init() {
	proto.RegisterType((*Credential)(nil), "aries.Credential")
}

func init() { proto.RegisterFile("bccsp/schemes/aries/cred.proto", fileDescriptor_57701eac61520cf0) }

var fileDescriptor_57701eac61520cf0 = []byte{
	// 192 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x4b, 0x4a, 0x4e, 0x2e,
	0x2e, 0xd0, 0x2f, 0x4e, 0xce, 0x48, 0xcd, 0x4d, 0x2d, 0xd6, 0x4f, 0x2c, 0xca, 0x4c, 0x2d, 0xd6,
	0x4f, 0x2e, 0x4a, 0x4d, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x05, 0x8b, 0x28, 0x99,
	0x71, 0x71, 0x39, 0x17, 0xa5, 0xa6, 0xa4, 0xe6, 0x95, 0x64, 0x26, 0xe6, 0x08, 0x09, 0x71, 0xb1,
	0x80, 0x94, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0xf0, 0x04, 0x81, 0xd9, 0x42, 0x22, 0x5c, 0xac, 0x89,
	0x25, 0x25, 0x45, 0xc5, 0x12, 0x4c, 0x0a, 0xcc, 0x1a, 0x3c, 0x41, 0x10, 0x8e, 0x53, 0x29, 0x17,
	0x67, 0x72, 0x7e, 0xae, 0x1e, 0xd8, 0x10, 0x27, 0x4e, 0x90, 0x11, 0x01, 0x20, 0x63, 0x03, 0x18,
	0xa3, 0x34, 0xd3, 0x33, 0x4b, 0x32, 0x4a, 0x93, 0xf4, 0x92, 0xf3, 0x73, 0xf5, 0x3d, 0x9d, 0x7c,
	0xf5, 0x33, 0x53, 0x52, 0x73, 0x33, 0x2b, 0xf4, 0xb1, 0x38, 0x67, 0x11, 0x13, 0xb3, 0x63, 0x44,
	0xc4, 0x2a, 0x26, 0x56, 0x47, 0x10, 0xef, 0x14, 0x94, 0x7e, 0xc4, 0x24, 0x08, 0xa6, 0x63, 0xdc,
	0x03, 0x9c, 0x7c, 0x53, 0x4b, 0x12, 0x53, 0x12, 0x4b, 0x12, 0x5f, 0x41, 0xe5, 0x92, 0xd8, 0xc0,
	0x8e, 0x37, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xe4, 0x8f, 0x45, 0x50, 0xde, 0x00, 0x00, 0x00,
}
