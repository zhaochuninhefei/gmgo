// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/config/trace/v3/opencensus.proto

package tracev3

import (
	v1 "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/annotations"
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/core/v3"
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

type OpenCensusConfig_TraceContext int32

const (
	// No-op default, no trace context is utilized.
	OpenCensusConfig_NONE OpenCensusConfig_TraceContext = 0
	// W3C Trace-Context format "traceparent:" header.
	OpenCensusConfig_TRACE_CONTEXT OpenCensusConfig_TraceContext = 1
	// Binary "grpc-trace-bin:" header.
	OpenCensusConfig_GRPC_TRACE_BIN OpenCensusConfig_TraceContext = 2
	// "X-Cloud-Trace-Context:" header.
	OpenCensusConfig_CLOUD_TRACE_CONTEXT OpenCensusConfig_TraceContext = 3
	// X-B3-* headers.
	OpenCensusConfig_B3 OpenCensusConfig_TraceContext = 4
)

// Enum value maps for OpenCensusConfig_TraceContext.
var (
	OpenCensusConfig_TraceContext_name = map[int32]string{
		0: "NONE",
		1: "TRACE_CONTEXT",
		2: "GRPC_TRACE_BIN",
		3: "CLOUD_TRACE_CONTEXT",
		4: "B3",
	}
	OpenCensusConfig_TraceContext_value = map[string]int32{
		"NONE":                0,
		"TRACE_CONTEXT":       1,
		"GRPC_TRACE_BIN":      2,
		"CLOUD_TRACE_CONTEXT": 3,
		"B3":                  4,
	}
)

func (x OpenCensusConfig_TraceContext) Enum() *OpenCensusConfig_TraceContext {
	p := new(OpenCensusConfig_TraceContext)
	*p = x
	return p
}

func (x OpenCensusConfig_TraceContext) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OpenCensusConfig_TraceContext) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_config_trace_v3_opencensus_proto_enumTypes[0].Descriptor()
}

func (OpenCensusConfig_TraceContext) Type() protoreflect.EnumType {
	return &file_envoy_config_trace_v3_opencensus_proto_enumTypes[0]
}

func (x OpenCensusConfig_TraceContext) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OpenCensusConfig_TraceContext.Descriptor instead.
func (OpenCensusConfig_TraceContext) EnumDescriptor() ([]byte, []int) {
	return file_envoy_config_trace_v3_opencensus_proto_rawDescGZIP(), []int{0, 0}
}

// Configuration for the OpenCensus tracer.
// [#next-free-field: 15]
// [#extension: envoy.tracers.opencensus]
type OpenCensusConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Configures tracing, e.g. the sampler, max number of annotations, etc.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	TraceConfig *v1.TraceConfig `protobuf:"bytes,1,opt,name=trace_config,json=traceConfig,proto3" json:"trace_config,omitempty"`
	// Enables the stdout exporter if set to true. This is intended for debugging
	// purposes.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	StdoutExporterEnabled bool `protobuf:"varint,2,opt,name=stdout_exporter_enabled,json=stdoutExporterEnabled,proto3" json:"stdout_exporter_enabled,omitempty"`
	// Enables the Stackdriver exporter if set to true. The project_id must also
	// be set.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	StackdriverExporterEnabled bool `protobuf:"varint,3,opt,name=stackdriver_exporter_enabled,json=stackdriverExporterEnabled,proto3" json:"stackdriver_exporter_enabled,omitempty"`
	// The Cloud project_id to use for Stackdriver tracing.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	StackdriverProjectId string `protobuf:"bytes,4,opt,name=stackdriver_project_id,json=stackdriverProjectId,proto3" json:"stackdriver_project_id,omitempty"`
	// (optional) By default, the Stackdriver exporter will connect to production
	// Stackdriver. If stackdriver_address is non-empty, it will instead connect
	// to this address, which is in the gRPC format:
	// https://github.com/grpc/grpc/blob/master/doc/naming.md
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	StackdriverAddress string `protobuf:"bytes,10,opt,name=stackdriver_address,json=stackdriverAddress,proto3" json:"stackdriver_address,omitempty"`
	// (optional) The gRPC server that hosts Stackdriver tracing service. Only
	// Google gRPC is supported. If :ref:`target_uri <envoy_v3_api_field_config.core.v3.GrpcService.GoogleGrpc.target_uri>`
	// is not provided, the default production Stackdriver address will be used.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	StackdriverGrpcService *v3.GrpcService `protobuf:"bytes,13,opt,name=stackdriver_grpc_service,json=stackdriverGrpcService,proto3" json:"stackdriver_grpc_service,omitempty"`
	// Enables the Zipkin exporter if set to true. The url and service name must
	// also be set. This is deprecated, prefer to use Envoy's :ref:`native Zipkin
	// tracer <envoy_v3_api_msg_config.trace.v3.ZipkinConfig>`.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	ZipkinExporterEnabled bool `protobuf:"varint,5,opt,name=zipkin_exporter_enabled,json=zipkinExporterEnabled,proto3" json:"zipkin_exporter_enabled,omitempty"`
	// The URL to Zipkin, e.g. "http://127.0.0.1:9411/api/v2/spans". This is
	// deprecated, prefer to use Envoy's :ref:`native Zipkin tracer
	// <envoy_v3_api_msg_config.trace.v3.ZipkinConfig>`.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	ZipkinUrl string `protobuf:"bytes,6,opt,name=zipkin_url,json=zipkinUrl,proto3" json:"zipkin_url,omitempty"`
	// Enables the OpenCensus Agent exporter if set to true. The ocagent_address or
	// ocagent_grpc_service must also be set.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	OcagentExporterEnabled bool `protobuf:"varint,11,opt,name=ocagent_exporter_enabled,json=ocagentExporterEnabled,proto3" json:"ocagent_exporter_enabled,omitempty"`
	// The address of the OpenCensus Agent, if its exporter is enabled, in gRPC
	// format: https://github.com/grpc/grpc/blob/master/doc/naming.md
	// [#comment:TODO: deprecate this field]
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	OcagentAddress string `protobuf:"bytes,12,opt,name=ocagent_address,json=ocagentAddress,proto3" json:"ocagent_address,omitempty"`
	// (optional) The gRPC server hosted by the OpenCensus Agent. Only Google gRPC is supported.
	// This is only used if the ocagent_address is left empty.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	OcagentGrpcService *v3.GrpcService `protobuf:"bytes,14,opt,name=ocagent_grpc_service,json=ocagentGrpcService,proto3" json:"ocagent_grpc_service,omitempty"`
	// List of incoming trace context headers we will accept. First one found
	// wins.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	IncomingTraceContext []OpenCensusConfig_TraceContext `protobuf:"varint,8,rep,packed,name=incoming_trace_context,json=incomingTraceContext,proto3,enum=envoy.config.trace.v3.OpenCensusConfig_TraceContext" json:"incoming_trace_context,omitempty"`
	// List of outgoing trace context headers we will produce.
	//
	// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
	OutgoingTraceContext []OpenCensusConfig_TraceContext `protobuf:"varint,9,rep,packed,name=outgoing_trace_context,json=outgoingTraceContext,proto3,enum=envoy.config.trace.v3.OpenCensusConfig_TraceContext" json:"outgoing_trace_context,omitempty"`
}

func (x *OpenCensusConfig) Reset() {
	*x = OpenCensusConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_config_trace_v3_opencensus_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OpenCensusConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OpenCensusConfig) ProtoMessage() {}

func (x *OpenCensusConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_config_trace_v3_opencensus_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OpenCensusConfig.ProtoReflect.Descriptor instead.
func (*OpenCensusConfig) Descriptor() ([]byte, []int) {
	return file_envoy_config_trace_v3_opencensus_proto_rawDescGZIP(), []int{0}
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetTraceConfig() *v1.TraceConfig {
	if x != nil {
		return x.TraceConfig
	}
	return nil
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetStdoutExporterEnabled() bool {
	if x != nil {
		return x.StdoutExporterEnabled
	}
	return false
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetStackdriverExporterEnabled() bool {
	if x != nil {
		return x.StackdriverExporterEnabled
	}
	return false
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetStackdriverProjectId() string {
	if x != nil {
		return x.StackdriverProjectId
	}
	return ""
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetStackdriverAddress() string {
	if x != nil {
		return x.StackdriverAddress
	}
	return ""
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetStackdriverGrpcService() *v3.GrpcService {
	if x != nil {
		return x.StackdriverGrpcService
	}
	return nil
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetZipkinExporterEnabled() bool {
	if x != nil {
		return x.ZipkinExporterEnabled
	}
	return false
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetZipkinUrl() string {
	if x != nil {
		return x.ZipkinUrl
	}
	return ""
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetOcagentExporterEnabled() bool {
	if x != nil {
		return x.OcagentExporterEnabled
	}
	return false
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetOcagentAddress() string {
	if x != nil {
		return x.OcagentAddress
	}
	return ""
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetOcagentGrpcService() *v3.GrpcService {
	if x != nil {
		return x.OcagentGrpcService
	}
	return nil
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetIncomingTraceContext() []OpenCensusConfig_TraceContext {
	if x != nil {
		return x.IncomingTraceContext
	}
	return nil
}

// Deprecated: Marked as deprecated in envoy/config/trace/v3/opencensus.proto.
func (x *OpenCensusConfig) GetOutgoingTraceContext() []OpenCensusConfig_TraceContext {
	if x != nil {
		return x.OutgoingTraceContext
	}
	return nil
}

var File_envoy_config_trace_v3_opencensus_proto protoreflect.FileDescriptor

var file_envoy_config_trace_v3_opencensus_proto_rawDesc = []byte{
	0x0a, 0x26, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73,
	0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x33, 0x1a,
	0x27, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f,
	0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2c, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65,
	0x6e, 0x73, 0x75, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x64, 0x65, 0x70, 0x72, 0x65, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x6d, 0x69,
	0x67, 0x72, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70, 0x61,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc2, 0x09,
	0x0a, 0x10, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x56, 0x0a, 0x0c, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63,
	0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x0b, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x43, 0x0a, 0x17, 0x73, 0x74,
	0x64, 0x6f, 0x75, 0x74, 0x5f, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x5f, 0x65, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x42, 0x0b, 0x92, 0xc7, 0x86,
	0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x15, 0x73, 0x74, 0x64, 0x6f, 0x75, 0x74,
	0x45, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12,
	0x4d, 0x0a, 0x1c, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x5f, 0x65,
	0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x08, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30,
	0x18, 0x01, 0x52, 0x1a, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x45,
	0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x41,
	0x0a, 0x16, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x5f, 0x70, 0x72,
	0x6f, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b,
	0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x14, 0x73, 0x74, 0x61,
	0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x49,
	0x64, 0x12, 0x3c, 0x0a, 0x13, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72,
	0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b,
	0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x12, 0x73, 0x74, 0x61,
	0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12,
	0x68, 0x0a, 0x18, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x5f, 0x67,
	0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x21, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x47, 0x72, 0x70, 0x63, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18,
	0x01, 0x52, 0x16, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x47, 0x72,
	0x70, 0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x43, 0x0a, 0x17, 0x7a, 0x69, 0x70,
	0x6b, 0x69, 0x6e, 0x5f, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x5f, 0x65, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8,
	0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x15, 0x7a, 0x69, 0x70, 0x6b, 0x69, 0x6e, 0x45,
	0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x2a,
	0x0a, 0x0a, 0x7a, 0x69, 0x70, 0x6b, 0x69, 0x6e, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52,
	0x09, 0x7a, 0x69, 0x70, 0x6b, 0x69, 0x6e, 0x55, 0x72, 0x6c, 0x12, 0x45, 0x0a, 0x18, 0x6f, 0x63,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x5f, 0x65,
	0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x42, 0x0b, 0x92, 0xc7,
	0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x16, 0x6f, 0x63, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x45, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x64, 0x12, 0x34, 0x0a, 0x0f, 0x6f, 0x63, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8,
	0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x0e, 0x6f, 0x63, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x60, 0x0a, 0x14, 0x6f, 0x63, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x5f, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18,
	0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x47, 0x72, 0x70,
	0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03,
	0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x12, 0x6f, 0x63, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x47, 0x72,
	0x70, 0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x77, 0x0a, 0x16, 0x69, 0x6e, 0x63,
	0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x78, 0x74, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x34, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76,
	0x33, 0x2e, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x54, 0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x42,
	0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x14, 0x69, 0x6e,
	0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x54, 0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x78, 0x74, 0x12, 0x77, 0x0a, 0x16, 0x6f, 0x75, 0x74, 0x67, 0x6f, 0x69, 0x6e, 0x67, 0x5f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x09, 0x20, 0x03,
	0x28, 0x0e, 0x32, 0x34, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x4f, 0x70, 0x65, 0x6e, 0x43,
	0x65, 0x6e, 0x73, 0x75, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x54, 0x72, 0x61, 0x63,
	0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03,
	0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x14, 0x6f, 0x75, 0x74, 0x67, 0x6f, 0x69, 0x6e, 0x67, 0x54,
	0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x22, 0x60, 0x0a, 0x0c, 0x54,
	0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x08, 0x0a, 0x04, 0x4e,
	0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x54, 0x52, 0x41, 0x43, 0x45, 0x5f, 0x43,
	0x4f, 0x4e, 0x54, 0x45, 0x58, 0x54, 0x10, 0x01, 0x12, 0x12, 0x0a, 0x0e, 0x47, 0x52, 0x50, 0x43,
	0x5f, 0x54, 0x52, 0x41, 0x43, 0x45, 0x5f, 0x42, 0x49, 0x4e, 0x10, 0x02, 0x12, 0x17, 0x0a, 0x13,
	0x43, 0x4c, 0x4f, 0x55, 0x44, 0x5f, 0x54, 0x52, 0x41, 0x43, 0x45, 0x5f, 0x43, 0x4f, 0x4e, 0x54,
	0x45, 0x58, 0x54, 0x10, 0x03, 0x12, 0x06, 0x0a, 0x02, 0x42, 0x33, 0x10, 0x04, 0x3a, 0x2d, 0x9a,
	0xc5, 0x88, 0x1e, 0x28, 0x0a, 0x26, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x76, 0x32, 0x2e, 0x4f, 0x70, 0x65, 0x6e,
	0x43, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x4a, 0x04, 0x08, 0x07,
	0x10, 0x08, 0x42, 0xb9, 0x01, 0xf2, 0x98, 0xfe, 0x8f, 0x05, 0x2d, 0x12, 0x2b, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x72, 0x73, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73,
	0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02,
	0x0a, 0x23, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x2e, 0x76, 0x33, 0x42, 0x0f, 0x4f, 0x70, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x73, 0x75,
	0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f,
	0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x2f, 0x76, 0x33, 0x3b, 0x74, 0x72, 0x61, 0x63, 0x65, 0x76, 0x33, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_config_trace_v3_opencensus_proto_rawDescOnce sync.Once
	file_envoy_config_trace_v3_opencensus_proto_rawDescData = file_envoy_config_trace_v3_opencensus_proto_rawDesc
)

func file_envoy_config_trace_v3_opencensus_proto_rawDescGZIP() []byte {
	file_envoy_config_trace_v3_opencensus_proto_rawDescOnce.Do(func() {
		file_envoy_config_trace_v3_opencensus_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_config_trace_v3_opencensus_proto_rawDescData)
	})
	return file_envoy_config_trace_v3_opencensus_proto_rawDescData
}

var file_envoy_config_trace_v3_opencensus_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_envoy_config_trace_v3_opencensus_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_config_trace_v3_opencensus_proto_goTypes = []interface{}{
	(OpenCensusConfig_TraceContext)(0), // 0: envoy.config.trace.v3.OpenCensusConfig.TraceContext
	(*OpenCensusConfig)(nil),           // 1: envoy.config.trace.v3.OpenCensusConfig
	(*v1.TraceConfig)(nil),             // 2: opencensus.proto.trace.v1.TraceConfig
	(*v3.GrpcService)(nil),             // 3: envoy.config.core.v3.GrpcService
}
var file_envoy_config_trace_v3_opencensus_proto_depIdxs = []int32{
	2, // 0: envoy.config.trace.v3.OpenCensusConfig.trace_config:type_name -> opencensus.proto.trace.v1.TraceConfig
	3, // 1: envoy.config.trace.v3.OpenCensusConfig.stackdriver_grpc_service:type_name -> envoy.config.core.v3.GrpcService
	3, // 2: envoy.config.trace.v3.OpenCensusConfig.ocagent_grpc_service:type_name -> envoy.config.core.v3.GrpcService
	0, // 3: envoy.config.trace.v3.OpenCensusConfig.incoming_trace_context:type_name -> envoy.config.trace.v3.OpenCensusConfig.TraceContext
	0, // 4: envoy.config.trace.v3.OpenCensusConfig.outgoing_trace_context:type_name -> envoy.config.trace.v3.OpenCensusConfig.TraceContext
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_envoy_config_trace_v3_opencensus_proto_init() }
func file_envoy_config_trace_v3_opencensus_proto_init() {
	if File_envoy_config_trace_v3_opencensus_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_config_trace_v3_opencensus_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OpenCensusConfig); i {
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
			RawDescriptor: file_envoy_config_trace_v3_opencensus_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_config_trace_v3_opencensus_proto_goTypes,
		DependencyIndexes: file_envoy_config_trace_v3_opencensus_proto_depIdxs,
		EnumInfos:         file_envoy_config_trace_v3_opencensus_proto_enumTypes,
		MessageInfos:      file_envoy_config_trace_v3_opencensus_proto_msgTypes,
	}.Build()
	File_envoy_config_trace_v3_opencensus_proto = out.File
	file_envoy_config_trace_v3_opencensus_proto_rawDesc = nil
	file_envoy_config_trace_v3_opencensus_proto_goTypes = nil
	file_envoy_config_trace_v3_opencensus_proto_depIdxs = nil
}
