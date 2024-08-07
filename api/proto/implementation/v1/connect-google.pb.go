// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.27.0
// source: v1/connect-google.proto

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

type ConnectGoogleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Code        string `protobuf:"bytes,2,opt,name=code,proto3" json:"code,omitempty"`
	State       string `protobuf:"bytes,3,opt,name=state,proto3" json:"state,omitempty"`
	RedirectUrl string `protobuf:"bytes,4,opt,name=redirectUrl,proto3" json:"redirectUrl,omitempty"`
}

func (x *ConnectGoogleRequest) Reset() {
	*x = ConnectGoogleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_connect_google_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectGoogleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectGoogleRequest) ProtoMessage() {}

func (x *ConnectGoogleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1_connect_google_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectGoogleRequest.ProtoReflect.Descriptor instead.
func (*ConnectGoogleRequest) Descriptor() ([]byte, []int) {
	return file_v1_connect_google_proto_rawDescGZIP(), []int{0}
}

func (x *ConnectGoogleRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ConnectGoogleRequest) GetCode() string {
	if x != nil {
		return x.Code
	}
	return ""
}

func (x *ConnectGoogleRequest) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *ConnectGoogleRequest) GetRedirectUrl() string {
	if x != nil {
		return x.RedirectUrl
	}
	return ""
}

type ConnectGoogleResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *ConnectGoogleResponse) Reset() {
	*x = ConnectGoogleResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_connect_google_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectGoogleResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectGoogleResponse) ProtoMessage() {}

func (x *ConnectGoogleResponse) ProtoReflect() protoreflect.Message {
	mi := &file_v1_connect_google_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectGoogleResponse.ProtoReflect.Descriptor instead.
func (*ConnectGoogleResponse) Descriptor() ([]byte, []int) {
	return file_v1_connect_google_proto_rawDescGZIP(), []int{1}
}

func (x *ConnectGoogleResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_v1_connect_google_proto protoreflect.FileDescriptor

var file_v1_connect_google_proto_rawDesc = []byte{
	0x0a, 0x17, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2d, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x76, 0x31, 0x22, 0x72, 0x0a,
	0x14, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12,
	0x20, 0x0a, 0x0b, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x55, 0x72, 0x6c, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x55, 0x72,
	0x6c, 0x22, 0x31, 0x0a, 0x15, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x47, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x6d, 0x65, 0x70, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x6c, 0x69, 0x65, 0x2f, 0x63,
	0x68, 0x65, 0x66, 0x62, 0x6f, 0x6f, 0x6b, 0x2d, 0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2d,
	0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_connect_google_proto_rawDescOnce sync.Once
	file_v1_connect_google_proto_rawDescData = file_v1_connect_google_proto_rawDesc
)

func file_v1_connect_google_proto_rawDescGZIP() []byte {
	file_v1_connect_google_proto_rawDescOnce.Do(func() {
		file_v1_connect_google_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_connect_google_proto_rawDescData)
	})
	return file_v1_connect_google_proto_rawDescData
}

var file_v1_connect_google_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_v1_connect_google_proto_goTypes = []interface{}{
	(*ConnectGoogleRequest)(nil),  // 0: v1.ConnectGoogleRequest
	(*ConnectGoogleResponse)(nil), // 1: v1.ConnectGoogleResponse
}
var file_v1_connect_google_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_v1_connect_google_proto_init() }
func file_v1_connect_google_proto_init() {
	if File_v1_connect_google_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1_connect_google_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectGoogleRequest); i {
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
		file_v1_connect_google_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectGoogleResponse); i {
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
			RawDescriptor: file_v1_connect_google_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1_connect_google_proto_goTypes,
		DependencyIndexes: file_v1_connect_google_proto_depIdxs,
		MessageInfos:      file_v1_connect_google_proto_msgTypes,
	}.Build()
	File_v1_connect_google_proto = out.File
	file_v1_connect_google_proto_rawDesc = nil
	file_v1_connect_google_proto_goTypes = nil
	file_v1_connect_google_proto_depIdxs = nil
}
