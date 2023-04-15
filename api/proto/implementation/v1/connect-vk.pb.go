// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: v1/connect-vk.proto

package v1

import (
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

type ConnectVkRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id    string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Code  string `protobuf:"bytes,2,opt,name=code,proto3" json:"code,omitempty"`
	State string `protobuf:"bytes,3,opt,name=state,proto3" json:"state,omitempty"`
}

func (x *ConnectVkRequest) Reset() {
	*x = ConnectVkRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_connect_vk_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectVkRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectVkRequest) ProtoMessage() {}

func (x *ConnectVkRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_connect_vk_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectVkRequest.ProtoReflect.Descriptor instead.
func (*ConnectVkRequest) Descriptor() ([]byte, []int) {
	return file_v1_connect_vk_proto_rawDescGZIP(), []int{0}
}

func (x *ConnectVkRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ConnectVkRequest) GetCode() string {
	if x != nil {
		return x.Code
	}
	return ""
}

func (x *ConnectVkRequest) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

type ConnectVkResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *ConnectVkResponse) Reset() {
	*x = ConnectVkResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_connect_vk_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectVkResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectVkResponse) ProtoMessage() {}

func (x *ConnectVkResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_connect_vk_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectVkResponse.ProtoReflect.Descriptor instead.
func (*ConnectVkResponse) Descriptor() ([]byte, []int) {
	return file_v1_connect_vk_proto_rawDescGZIP(), []int{1}
}

func (x *ConnectVkResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_v1_connect_vk_proto protoreflect.FileDescriptor

var file_v1_connect_vk_proto_rawDesc = []byte{
	0x0a, 0x13, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2d, 0x76, 0x6b, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x76, 0x31, 0x22, 0x4c, 0x0a, 0x10, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x56, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x63, 0x6f, 0x64,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x22, 0x2d, 0x0a, 0x11, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x56, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6d, 0x65, 0x70, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x6c, 0x69, 0x65,
	0x2f, 0x63, 0x68, 0x65, 0x66, 0x62, 0x6f, 0x6f, 0x6b, 0x2d, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e,
	0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_connect_vk_proto_rawDescOnce sync.Once
	file_v1_connect_vk_proto_rawDescData = file_v1_connect_vk_proto_rawDesc
)

func file_v1_connect_vk_proto_rawDescGZIP() []byte {
	file_v1_connect_vk_proto_rawDescOnce.Do(func() {
		file_v1_connect_vk_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_connect_vk_proto_rawDescData)
	})
	return file_v1_connect_vk_proto_rawDescData
}

var file_v1_connect_vk_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_v1_connect_vk_proto_goTypes = []interface{}{
	(*ConnectVkRequest)(nil),  // 0: v1.ConnectVkRequest
	(*ConnectVkResponse)(nil), // 1: v1.ConnectVkResponse
}
var file_v1_connect_vk_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_v1_connect_vk_proto_init() }
func file_v1_connect_vk_proto_init() {
	if File_v1_connect_vk_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1_connect_vk_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectVkRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_v1_connect_vk_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectVkResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_v1_connect_vk_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1_connect_vk_proto_goTypes,
		DependencyIndexes: file_v1_connect_vk_proto_depIdxs,
		MessageInfos:      file_v1_connect_vk_proto_msgTypes,
	}.Build()
	File_v1_connect_vk_proto = out.File
	file_v1_connect_vk_proto_rawDesc = nil
	file_v1_connect_vk_proto_goTypes = nil
	file_v1_connect_vk_proto_depIdxs = nil
}
