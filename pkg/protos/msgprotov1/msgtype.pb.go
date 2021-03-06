// Copyright 2020 Self Group Ltd. All Rights Reserved.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.6.1
// source: msgtype.proto

package msgprotov1

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type MsgType int32

const (
	MsgType_MSG  MsgType = 0
	MsgType_ACK  MsgType = 1
	MsgType_ERR  MsgType = 2
	MsgType_AUTH MsgType = 3
	MsgType_ACL  MsgType = 4
)

// Enum value maps for MsgType.
var (
	MsgType_name = map[int32]string{
		0: "MSG",
		1: "ACK",
		2: "ERR",
		3: "AUTH",
		4: "ACL",
	}
	MsgType_value = map[string]int32{
		"MSG":  0,
		"ACK":  1,
		"ERR":  2,
		"AUTH": 3,
		"ACL":  4,
	}
)

func (x MsgType) Enum() *MsgType {
	p := new(MsgType)
	*p = x
	return p
}

func (x MsgType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MsgType) Descriptor() protoreflect.EnumDescriptor {
	return file_msgtype_proto_enumTypes[0].Descriptor()
}

func (MsgType) Type() protoreflect.EnumType {
	return &file_msgtype_proto_enumTypes[0]
}

func (x MsgType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MsgType.Descriptor instead.
func (MsgType) EnumDescriptor() ([]byte, []int) {
	return file_msgtype_proto_rawDescGZIP(), []int{0}
}

var File_msgtype_proto protoreflect.FileDescriptor

var file_msgtype_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x73, 0x67, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x08, 0x6d, 0x73, 0x67, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x37, 0x0a, 0x07, 0x4d, 0x73, 0x67,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x07, 0x0a, 0x03, 0x4d, 0x53, 0x47, 0x10, 0x00, 0x12, 0x07, 0x0a,
	0x03, 0x41, 0x43, 0x4b, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x45, 0x52, 0x52, 0x10, 0x02, 0x12,
	0x08, 0x0a, 0x04, 0x41, 0x55, 0x54, 0x48, 0x10, 0x03, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x43, 0x4c,
	0x10, 0x04, 0x42, 0x19, 0x0a, 0x17, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x65, 0x6c, 0x66, 0x69, 0x64,
	0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_msgtype_proto_rawDescOnce sync.Once
	file_msgtype_proto_rawDescData = file_msgtype_proto_rawDesc
)

func file_msgtype_proto_rawDescGZIP() []byte {
	file_msgtype_proto_rawDescOnce.Do(func() {
		file_msgtype_proto_rawDescData = protoimpl.X.CompressGZIP(file_msgtype_proto_rawDescData)
	})
	return file_msgtype_proto_rawDescData
}

var file_msgtype_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_msgtype_proto_goTypes = []interface{}{
	(MsgType)(0), // 0: msgproto.MsgType
}
var file_msgtype_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_msgtype_proto_init() }
func file_msgtype_proto_init() {
	if File_msgtype_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_msgtype_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_msgtype_proto_goTypes,
		DependencyIndexes: file_msgtype_proto_depIdxs,
		EnumInfos:         file_msgtype_proto_enumTypes,
	}.Build()
	File_msgtype_proto = out.File
	file_msgtype_proto_rawDesc = nil
	file_msgtype_proto_goTypes = nil
	file_msgtype_proto_depIdxs = nil
}
