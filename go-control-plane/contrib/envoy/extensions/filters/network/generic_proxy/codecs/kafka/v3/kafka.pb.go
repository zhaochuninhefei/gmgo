// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: contrib/envoy/extensions/filters/network/generic_proxy/codecs/kafka/v3/kafka.proto

package kafkav3

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/xds/annotations/v3"
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

// Configuration for Kafka codec. This codec gives the generic proxy the ability to proxy
// Kafka traffic. But note any route configuration for Kafka traffic is not supported yet.
// The generic proxy can only used to generate logs or metrics for Kafka traffic but cannot
// do matching or routing.
//
// .. note::
//
//	The codec can currently only be used in the sidecar mode. And to ensure the codec works
//	properly, please make sure the following conditions are met:
//
//	1. The generic proxy must be configured with a wildcard route that matches all traffic.
//	2. The target cluster must be configured as a original destination cluster.
//	3. The :ref:`bind_upstream_connection
//	   <envoy_v3_api_field_extensions.filters.network.generic_proxy.router.v3.Router.bind_upstream_connection>`
//	   of generic proxy router must be set to true to ensure same upstream connection is used
//	   for all traffic from same downstream connection.
type KafkaCodecConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *KafkaCodecConfig) Reset() {
	*x = KafkaCodecConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KafkaCodecConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KafkaCodecConfig) ProtoMessage() {}

func (x *KafkaCodecConfig) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KafkaCodecConfig.ProtoReflect.Descriptor instead.
func (*KafkaCodecConfig) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescGZIP(), []int{0}
}

var File_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto protoreflect.FileDescriptor

var file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDesc = []byte{
	0x0a, 0x52, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2f,
	0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2f, 0x76, 0x33, 0x2f, 0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x3e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e,
	0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2e, 0x6b, 0x61, 0x66, 0x6b,
	0x61, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x78, 0x64, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x12, 0x0a, 0x10, 0x4b, 0x61, 0x66, 0x6b, 0x61, 0x43, 0x6f, 0x64,
	0x65, 0x63, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0xe3, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06,
	0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4, 0xe1, 0x06, 0x02, 0x08, 0x01, 0x0a, 0x4c, 0x69, 0x6f, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65,
	0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73,
	0x2e, 0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2e, 0x76, 0x33, 0x42, 0x0a, 0x4b, 0x61, 0x66, 0x6b, 0x61,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x75, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67,
	0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
	0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2f, 0x6b, 0x61,
	0x66, 0x6b, 0x61, 0x2f, 0x76, 0x33, 0x3b, 0x6b, 0x61, 0x66, 0x6b, 0x61, 0x76, 0x33, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescOnce sync.Once
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescData = file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDesc
)

func file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescGZIP() []byte {
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescOnce.Do(func() {
		file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescData = protoimpl.X.CompressGZIP(file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescData)
	})
	return file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDescData
}

var file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_goTypes = []interface{}{
	(*KafkaCodecConfig)(nil), // 0: envoy.extensions.filters.network.generic_proxy.codecs.kafka.v3.KafkaCodecConfig
}
var file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() {
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_init()
}
func file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_init() {
	if File_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KafkaCodecConfig); i {
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
			RawDescriptor: file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_goTypes,
		DependencyIndexes: file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_depIdxs,
		MessageInfos:      file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_msgTypes,
	}.Build()
	File_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto = out.File
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_rawDesc = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_goTypes = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_codecs_kafka_v3_kafka_proto_depIdxs = nil
}
