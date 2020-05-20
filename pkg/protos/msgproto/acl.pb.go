// Code generated by protoc-gen-go. DO NOT EDIT.
// source: acl.proto

package msgproto

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

type AccessControlList struct {
	Type                 MsgType    `protobuf:"varint,1,opt,name=type,proto3,enum=msgproto.MsgType" json:"type,omitempty"`
	Id                   string     `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Command              ACLCommand `protobuf:"varint,3,opt,name=command,proto3,enum=msgproto.ACLCommand" json:"command,omitempty"`
	Payload              []byte     `protobuf:"bytes,4,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *AccessControlList) Reset()         { *m = AccessControlList{} }
func (m *AccessControlList) String() string { return proto.CompactTextString(m) }
func (*AccessControlList) ProtoMessage()    {}
func (*AccessControlList) Descriptor() ([]byte, []int) {
	return fileDescriptor_a452f070aeef01eb, []int{0}
}

func (m *AccessControlList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AccessControlList.Unmarshal(m, b)
}
func (m *AccessControlList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AccessControlList.Marshal(b, m, deterministic)
}
func (m *AccessControlList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessControlList.Merge(m, src)
}
func (m *AccessControlList) XXX_Size() int {
	return xxx_messageInfo_AccessControlList.Size(m)
}
func (m *AccessControlList) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessControlList.DiscardUnknown(m)
}

var xxx_messageInfo_AccessControlList proto.InternalMessageInfo

func (m *AccessControlList) GetType() MsgType {
	if m != nil {
		return m.Type
	}
	return MsgType_MSG
}

func (m *AccessControlList) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *AccessControlList) GetCommand() ACLCommand {
	if m != nil {
		return m.Command
	}
	return ACLCommand_LIST
}

func (m *AccessControlList) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func init() {
	proto.RegisterType((*AccessControlList)(nil), "msgproto.AccessControlList")
}

func init() { proto.RegisterFile("acl.proto", fileDescriptor_a452f070aeef01eb) }

var fileDescriptor_a452f070aeef01eb = []byte{
	// 201 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x8e, 0x41, 0x8a, 0xc3, 0x20,
	0x14, 0x86, 0x31, 0x13, 0x26, 0x13, 0x99, 0x09, 0x13, 0x19, 0x18, 0x27, 0xab, 0x30, 0x50, 0xc8,
	0xca, 0x45, 0x7b, 0x82, 0x34, 0xdb, 0x74, 0x23, 0xbd, 0x80, 0x55, 0x1b, 0x04, 0x8d, 0x12, 0xdd,
	0xe4, 0x1e, 0x3d, 0x70, 0xa9, 0x36, 0x74, 0xf7, 0xbf, 0xf7, 0xbd, 0xef, 0xe7, 0xc1, 0x92, 0x71,
	0x4d, 0xdc, 0x62, 0x83, 0x45, 0x1f, 0xc6, 0x4f, 0x31, 0x35, 0x5f, 0xc6, 0x4f, 0x61, 0x75, 0x32,
	0x81, 0xe6, 0x9b, 0x71, 0xcd, 0xad, 0x31, 0x6c, 0x16, 0x69, 0xf3, 0x7f, 0x03, 0xb0, 0xee, 0x39,
	0x97, 0xde, 0x0f, 0x76, 0x0e, 0x8b, 0xd5, 0xa3, 0xf2, 0x01, 0xed, 0x60, 0xfe, 0xb0, 0x30, 0x68,
	0x41, 0x57, 0xed, 0x6b, 0xb2, 0xf5, 0x91, 0x93, 0x9f, 0xce, 0xab, 0x93, 0x34, 0x62, 0x54, 0xc1,
	0x4c, 0x09, 0x9c, 0xb5, 0xa0, 0x2b, 0x69, 0xa6, 0x04, 0x22, 0xb0, 0x78, 0xb6, 0xe3, 0xb7, 0x68,
	0xfe, 0xbc, 0xcc, 0x7e, 0x18, 0x87, 0xc4, 0xe8, 0x76, 0x84, 0x30, 0x2c, 0x1c, 0x5b, 0xb5, 0x65,
	0x02, 0xe7, 0x2d, 0xe8, 0x3e, 0xe9, 0x36, 0x1e, 0xff, 0xe0, 0xef, 0x2c, 0x03, 0xf1, 0x52, 0x5f,
	0x95, 0x20, 0xcc, 0xb9, 0xf4, 0x2e, 0xb7, 0xfa, 0xf2, 0x1e, 0xd3, 0xe1, 0x1e, 0x00, 0x00, 0xff,
	0xff, 0x61, 0x33, 0x2e, 0xee, 0xf0, 0x00, 0x00, 0x00,
}