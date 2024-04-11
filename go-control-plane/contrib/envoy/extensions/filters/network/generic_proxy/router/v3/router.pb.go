// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: contrib/envoy/extensions/filters/network/generic_proxy/router/v3/router.proto

package routerv3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/cncf/xds/go/xds/annotations/v3"
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

type Router struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Set to true if the upstream connection should be bound to the downstream connection, false
	// otherwise.
	//
	// By default, one random upstream connection will be selected from the upstream connection pool
	// and used for every request. And after the request is finished, the upstream connection will be
	// released back to the upstream connection pool.
	//
	// If this option is true, the upstream connection will be bound to the downstream connection and
	// have same lifetime as the downstream connection. The same upstream connection will be used for
	// all requests from the same downstream connection.
	//
	// And if this options is true, one of the following requirements must be met:
	//
	//  1. The request must be handled one by one. That is, the next request can not be sent to the
	//     upstream until the previous request is finished.
	//  2. Unique request id must be provided for each request and response. The request id must be
	//     unique for each request and response pair in same connection pair. And the request id must
	//     be the same for the corresponding request and response.
	//
	// This could be useful for some protocols that require the same upstream connection to be used
	// for all requests from the same downstream connection. For example, the protocol using stateful
	// connection.
	BindUpstreamConnection bool `protobuf:"varint,1,opt,name=bind_upstream_connection,json=bindUpstreamConnection,proto3" json:"bind_upstream_connection,omitempty"`
}

func (x *Router) Reset() {
	*x = Router{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Router) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Router) ProtoMessage() {}

func (x *Router) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Router.ProtoReflect.Descriptor instead.
func (*Router) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescGZIP(), []int{0}
}

func (x *Router) GetBindUpstreamConnection() bool {
	if x != nil {
		return x.BindUpstreamConnection
	}
	return false
}

var File_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto protoreflect.FileDescriptor

var file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDesc = []byte{
	0x0a, 0x4d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f,
	0x76, 0x33, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x38, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x78, 0x64, 0x73, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x42, 0x0a, 0x06, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x72, 0x12, 0x38, 0x0a, 0x18, 0x62, 0x69, 0x6e, 0x64, 0x5f, 0x75, 0x70, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x16, 0x62, 0x69, 0x6e, 0x64, 0x55, 0x70, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0xd9, 0x01,
	0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4, 0xe1, 0x06, 0x02, 0x08, 0x01,
	0x0a, 0x46, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x72,
	0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x42, 0x0b, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x70, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67,
	0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
	0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f, 0x76, 0x33,
	0x3b, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescOnce sync.Once
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescData = file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDesc
)

func file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescGZIP() []byte {
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescOnce.Do(func() {
		file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescData = protoimpl.X.CompressGZIP(file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescData)
	})
	return file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDescData
}

var file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_goTypes = []interface{}{
	(*Router)(nil), // 0: envoy.extensions.filters.network.generic_proxy.router.v3.Router
}
var file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() {
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_init()
}
func file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_init() {
	if File_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Router); i {
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
			RawDescriptor: file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_goTypes,
		DependencyIndexes: file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_depIdxs,
		MessageInfos:      file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_msgTypes,
	}.Build()
	File_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto = out.File
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_rawDesc = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_goTypes = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_router_v3_router_proto_depIdxs = nil
}
