// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/config/trace/v2/service.proto

package tracev2

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
	core "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/api/v2/core"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
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

// Configuration structure.
type TraceServiceConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The upstream gRPC cluster that hosts the metrics service.
	GrpcService *core.GrpcService `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService,proto3" json:"grpc_service,omitempty"`
}

func (x *TraceServiceConfig) Reset() {
	*x = TraceServiceConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_config_trace_v2_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TraceServiceConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TraceServiceConfig) ProtoMessage() {}

func (x *TraceServiceConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_config_trace_v2_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TraceServiceConfig.ProtoReflect.Descriptor instead.
func (*TraceServiceConfig) Descriptor() ([]byte, []int) {
	return file_envoy_config_trace_v2_service_proto_rawDescGZIP(), []int{0}
}

func (x *TraceServiceConfig) GetGrpcService() *core.GrpcService {
	if x != nil {
		return x.GrpcService
	}
	return nil
}

var File_envoy_config_trace_v2_service_proto protoreflect.FileDescriptor

var file_envoy_config_trace_v2_service_proto_rawDesc = []byte{
	0x0a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x32, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x32, 0x1a, 0x24, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x61, 0x0a, 0x12, 0x54, 0x72,
	0x61, 0x63, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x4b, 0x0a, 0x0c, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x47, 0x72, 0x70, 0x63, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01,
	0x52, 0x0b, 0x67, 0x72, 0x70, 0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x83, 0x01,
	0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x01, 0x0a, 0x23, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x32, 0x42, 0x0c, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x44, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x32, 0x3b, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x76, 0x32, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_config_trace_v2_service_proto_rawDescOnce sync.Once
	file_envoy_config_trace_v2_service_proto_rawDescData = file_envoy_config_trace_v2_service_proto_rawDesc
)

func file_envoy_config_trace_v2_service_proto_rawDescGZIP() []byte {
	file_envoy_config_trace_v2_service_proto_rawDescOnce.Do(func() {
		file_envoy_config_trace_v2_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_config_trace_v2_service_proto_rawDescData)
	})
	return file_envoy_config_trace_v2_service_proto_rawDescData
}

var file_envoy_config_trace_v2_service_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_config_trace_v2_service_proto_goTypes = []interface{}{
	(*TraceServiceConfig)(nil), // 0: envoy.config.trace.v2.TraceServiceConfig
	(*core.GrpcService)(nil),   // 1: envoy.api.v2.core.GrpcService
}
var file_envoy_config_trace_v2_service_proto_depIdxs = []int32{
	1, // 0: envoy.config.trace.v2.TraceServiceConfig.grpc_service:type_name -> envoy.api.v2.core.GrpcService
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_envoy_config_trace_v2_service_proto_init() }
func file_envoy_config_trace_v2_service_proto_init() {
	if File_envoy_config_trace_v2_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_config_trace_v2_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TraceServiceConfig); i {
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
			RawDescriptor: file_envoy_config_trace_v2_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_config_trace_v2_service_proto_goTypes,
		DependencyIndexes: file_envoy_config_trace_v2_service_proto_depIdxs,
		MessageInfos:      file_envoy_config_trace_v2_service_proto_msgTypes,
	}.Build()
	File_envoy_config_trace_v2_service_proto = out.File
	file_envoy_config_trace_v2_service_proto_rawDesc = nil
	file_envoy_config_trace_v2_service_proto_goTypes = nil
	file_envoy_config_trace_v2_service_proto_depIdxs = nil
}
