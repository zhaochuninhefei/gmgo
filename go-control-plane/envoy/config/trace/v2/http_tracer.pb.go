// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/config/trace/v2/http_tracer.proto

package tracev2

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The tracing configuration specifies settings for an HTTP tracer provider used by Envoy.
//
// Envoy may support other tracers in the future, but right now the HTTP tracer is the only one
// supported.
//
// .. attention::
//
//	Use of this message type has been deprecated in favor of direct use of
//	:ref:`Tracing.Http <envoy_api_msg_config.trace.v2.Tracing.Http>`.
type Tracing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Provides configuration for the HTTP tracer.
	Http *Tracing_Http `protobuf:"bytes,1,opt,name=http,proto3" json:"http,omitempty"`
}

func (x *Tracing) Reset() {
	*x = Tracing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_config_trace_v2_http_tracer_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tracing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tracing) ProtoMessage() {}

func (x *Tracing) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_config_trace_v2_http_tracer_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tracing.ProtoReflect.Descriptor instead.
func (*Tracing) Descriptor() ([]byte, []int) {
	return file_envoy_config_trace_v2_http_tracer_proto_rawDescGZIP(), []int{0}
}

func (x *Tracing) GetHttp() *Tracing_Http {
	if x != nil {
		return x.Http
	}
	return nil
}

// Configuration for an HTTP tracer provider used by Envoy.
//
// The configuration is defined by the
// :ref:`HttpConnectionManager.Tracing <envoy_api_msg_config.filter.network.http_connection_manager.v2.HttpConnectionManager.Tracing>`
// :ref:`provider <envoy_api_field_config.filter.network.http_connection_manager.v2.HttpConnectionManager.Tracing.provider>`
// field.
type Tracing_Http struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the HTTP trace driver to instantiate. The name must match a
	// supported HTTP trace driver. Built-in trace drivers:
	//
	// - *envoy.tracers.lightstep*
	// - *envoy.tracers.zipkin*
	// - *envoy.tracers.dynamic_ot*
	// - *envoy.tracers.datadog*
	// - *envoy.tracers.opencensus*
	// - *envoy.tracers.xray*
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Trace driver specific configuration which depends on the driver being instantiated.
	// See the trace drivers for examples:
	//
	// - :ref:`LightstepConfig <envoy_api_msg_config.trace.v2.LightstepConfig>`
	// - :ref:`ZipkinConfig <envoy_api_msg_config.trace.v2.ZipkinConfig>`
	// - :ref:`DynamicOtConfig <envoy_api_msg_config.trace.v2.DynamicOtConfig>`
	// - :ref:`DatadogConfig <envoy_api_msg_config.trace.v2.DatadogConfig>`
	// - :ref:`OpenCensusConfig <envoy_api_msg_config.trace.v2.OpenCensusConfig>`
	// - :ref:`AWS X-Ray <envoy_api_msg_config.trace.v2alpha.XRayConfig>`
	//
	// Types that are assignable to ConfigType:
	//
	//	*Tracing_Http_Config
	//	*Tracing_Http_TypedConfig
	ConfigType isTracing_Http_ConfigType `protobuf_oneof:"config_type"`
}

func (x *Tracing_Http) Reset() {
	*x = Tracing_Http{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_config_trace_v2_http_tracer_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tracing_Http) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tracing_Http) ProtoMessage() {}

func (x *Tracing_Http) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_config_trace_v2_http_tracer_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tracing_Http.ProtoReflect.Descriptor instead.
func (*Tracing_Http) Descriptor() ([]byte, []int) {
	return file_envoy_config_trace_v2_http_tracer_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Tracing_Http) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *Tracing_Http) GetConfigType() isTracing_Http_ConfigType {
	if m != nil {
		return m.ConfigType
	}
	return nil
}

// Deprecated: Marked as deprecated in envoy/config/trace/v2/http_tracer.proto.
func (x *Tracing_Http) GetConfig() *structpb.Struct {
	if x, ok := x.GetConfigType().(*Tracing_Http_Config); ok {
		return x.Config
	}
	return nil
}

func (x *Tracing_Http) GetTypedConfig() *anypb.Any {
	if x, ok := x.GetConfigType().(*Tracing_Http_TypedConfig); ok {
		return x.TypedConfig
	}
	return nil
}

type isTracing_Http_ConfigType interface {
	isTracing_Http_ConfigType()
}

type Tracing_Http_Config struct {
	// Deprecated: Marked as deprecated in envoy/config/trace/v2/http_tracer.proto.
	Config *structpb.Struct `protobuf:"bytes,2,opt,name=config,proto3,oneof"`
}

type Tracing_Http_TypedConfig struct {
	TypedConfig *anypb.Any `protobuf:"bytes,3,opt,name=typed_config,json=typedConfig,proto3,oneof"`
}

func (*Tracing_Http_Config) isTracing_Http_ConfigType() {}

func (*Tracing_Http_TypedConfig) isTracing_Http_ConfigType() {}

var File_envoy_config_trace_v2_http_tracer_proto protoreflect.FileDescriptor

var file_envoy_config_trace_v2_http_tracer_proto_rawDesc = []byte{
	0x0a, 0x27, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x32, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x32,
	0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72,
	0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xe9, 0x01, 0x0a, 0x07, 0x54, 0x72, 0x61, 0x63, 0x69, 0x6e, 0x67, 0x12, 0x37, 0x0a,
	0x04, 0x68, 0x74, 0x74, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x2e, 0x76, 0x32, 0x2e, 0x54, 0x72, 0x61, 0x63, 0x69, 0x6e, 0x67, 0x2e, 0x48, 0x74, 0x74, 0x70,
	0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x1a, 0xa4, 0x01, 0x0a, 0x04, 0x48, 0x74, 0x74, 0x70, 0x12,
	0x1b, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa,
	0x42, 0x04, 0x72, 0x02, 0x20, 0x01, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x35, 0x0a, 0x06,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x02, 0x18, 0x01, 0x48, 0x00, 0x52, 0x06, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x39, 0x0a, 0x0c, 0x74, 0x79, 0x70, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x48,
	0x00, 0x52, 0x0b, 0x74, 0x79, 0x70, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x0d,
	0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x42, 0x86, 0x01,
	0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x01, 0x0a, 0x23, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x32, 0x42, 0x0f, 0x48,
	0x74, 0x74, 0x70, 0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01,
	0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x32, 0x3b, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x76, 0x32, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_config_trace_v2_http_tracer_proto_rawDescOnce sync.Once
	file_envoy_config_trace_v2_http_tracer_proto_rawDescData = file_envoy_config_trace_v2_http_tracer_proto_rawDesc
)

func file_envoy_config_trace_v2_http_tracer_proto_rawDescGZIP() []byte {
	file_envoy_config_trace_v2_http_tracer_proto_rawDescOnce.Do(func() {
		file_envoy_config_trace_v2_http_tracer_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_config_trace_v2_http_tracer_proto_rawDescData)
	})
	return file_envoy_config_trace_v2_http_tracer_proto_rawDescData
}

var file_envoy_config_trace_v2_http_tracer_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_config_trace_v2_http_tracer_proto_goTypes = []interface{}{
	(*Tracing)(nil),         // 0: envoy.config.trace.v2.Tracing
	(*Tracing_Http)(nil),    // 1: envoy.config.trace.v2.Tracing.Http
	(*structpb.Struct)(nil), // 2: google.protobuf.Struct
	(*anypb.Any)(nil),       // 3: google.protobuf.Any
}
var file_envoy_config_trace_v2_http_tracer_proto_depIdxs = []int32{
	1, // 0: envoy.config.trace.v2.Tracing.http:type_name -> envoy.config.trace.v2.Tracing.Http
	2, // 1: envoy.config.trace.v2.Tracing.Http.config:type_name -> google.protobuf.Struct
	3, // 2: envoy.config.trace.v2.Tracing.Http.typed_config:type_name -> google.protobuf.Any
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_envoy_config_trace_v2_http_tracer_proto_init() }
func file_envoy_config_trace_v2_http_tracer_proto_init() {
	if File_envoy_config_trace_v2_http_tracer_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_config_trace_v2_http_tracer_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tracing); i {
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
		file_envoy_config_trace_v2_http_tracer_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tracing_Http); i {
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
	file_envoy_config_trace_v2_http_tracer_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*Tracing_Http_Config)(nil),
		(*Tracing_Http_TypedConfig)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_config_trace_v2_http_tracer_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_config_trace_v2_http_tracer_proto_goTypes,
		DependencyIndexes: file_envoy_config_trace_v2_http_tracer_proto_depIdxs,
		MessageInfos:      file_envoy_config_trace_v2_http_tracer_proto_msgTypes,
	}.Build()
	File_envoy_config_trace_v2_http_tracer_proto = out.File
	file_envoy_config_trace_v2_http_tracer_proto_rawDesc = nil
	file_envoy_config_trace_v2_http_tracer_proto_goTypes = nil
	file_envoy_config_trace_v2_http_tracer_proto_depIdxs = nil
}
