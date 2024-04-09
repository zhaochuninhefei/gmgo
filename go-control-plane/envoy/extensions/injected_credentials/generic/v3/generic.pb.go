// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.4
// source: envoy/extensions/injected_credentials/generic/v3/generic.proto

package genericv3

import (
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/cncf/xds/go/xds/annotations/v3"
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

// Generic extension can be used to inject HTTP Basic Auth, Bearer Token, or any arbitrary credential
// into the proxied requests.
// The credential will be injected into the specified HTTP request header.
// Example:
//
//	.. code-block:: yaml
//
//	credential:
//	  name: generic_credential
//	  typed_config:
//	    "@type": type.googleapis.com/envoy.extensions.injected_credentials.generic.v3.Generic
//	    credential:
//	      name: credential
//	      sds_config:
//	        path_config_source:
//	          path: credential.yaml
//	    header: Authorization
//
// credential.yaml for Basic Auth:
//
//	.. code-block:: yaml
//
//	resources:
//	- "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
//	  name: credential
//	  generic_secret:
//	    secret:
//	      inline_string: "Basic base64EncodedUsernamePassword"
//
// Refer to [RFC 7617: The 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617) for details.
//
// credential.yaml for Bearer Token:
//
//	.. code-block:: yaml
//	resources:
//	- "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
//	  name: credential
//	  generic_secret:
//	    secret:
//	      inline_string: "Bearer myToken"
//
// Refer to [RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) for details.
type Generic struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The SDS configuration for the credential that will be injected to the specified HTTP request header.
	// It must be a generic secret.
	Credential *v3.SdsSecretConfig `protobuf:"bytes,1,opt,name=credential,proto3" json:"credential,omitempty"`
	// The header that will be injected to the HTTP request with the provided credential.
	// If not set, filter will default to: “Authorization“
	Header string `protobuf:"bytes,2,opt,name=header,proto3" json:"header,omitempty"`
}

func (x *Generic) Reset() {
	*x = Generic{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_injected_credentials_generic_v3_generic_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Generic) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Generic) ProtoMessage() {}

func (x *Generic) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_injected_credentials_generic_v3_generic_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Generic.ProtoReflect.Descriptor instead.
func (*Generic) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescGZIP(), []int{0}
}

func (x *Generic) GetCredential() *v3.SdsSecretConfig {
	if x != nil {
		return x.Credential
	}
	return nil
}

func (x *Generic) GetHeader() string {
	if x != nil {
		return x.Header
	}
	return ""
}

var File_envoy_extensions_injected_credentials_generic_v3_generic_proto protoreflect.FileDescriptor

var file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDesc = []byte{
	0x0a, 0x3e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x63, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2f,
	0x76, 0x33, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x30, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x63, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2e,
	0x76, 0x33, 0x1a, 0x36, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73,
	0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x78, 0x64, 0x73, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x94, 0x01, 0x0a, 0x07, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x12,
	0x64, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x74, 0x6c, 0x73, 0x2e, 0x76, 0x33, 0x2e,
	0x53, 0x64, 0x73, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42,
	0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x12, 0x23, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b, 0xfa, 0x42, 0x08, 0x72, 0x06, 0xd0, 0x01, 0x01, 0xc0,
	0x01, 0x01, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x42, 0xc3, 0x01, 0xba, 0x80, 0xc8,
	0xd1, 0x06, 0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4, 0xe1, 0x06, 0x02, 0x08, 0x01, 0x0a, 0x3e, 0x69,
	0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x69, 0x6e,
	0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
	0x6c, 0x73, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2e, 0x76, 0x33, 0x42, 0x0c, 0x47,
	0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x61, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f,
	0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2f, 0x67, 0x65, 0x6e, 0x65,
	0x72, 0x69, 0x63, 0x2f, 0x76, 0x33, 0x3b, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x76, 0x33,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescOnce sync.Once
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescData = file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDesc
)

func file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescGZIP() []byte {
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescData)
	})
	return file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDescData
}

var file_envoy_extensions_injected_credentials_generic_v3_generic_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_injected_credentials_generic_v3_generic_proto_goTypes = []interface{}{
	(*Generic)(nil),            // 0: envoy.extensions.injected_credentials.generic.v3.Generic
	(*v3.SdsSecretConfig)(nil), // 1: envoy.extensions.transport_sockets.tls.v3.SdsSecretConfig
}
var file_envoy_extensions_injected_credentials_generic_v3_generic_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.injected_credentials.generic.v3.Generic.credential:type_name -> envoy.extensions.transport_sockets.tls.v3.SdsSecretConfig
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_envoy_extensions_injected_credentials_generic_v3_generic_proto_init() }
func file_envoy_extensions_injected_credentials_generic_v3_generic_proto_init() {
	if File_envoy_extensions_injected_credentials_generic_v3_generic_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_injected_credentials_generic_v3_generic_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Generic); i {
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
			RawDescriptor: file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_injected_credentials_generic_v3_generic_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_injected_credentials_generic_v3_generic_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_injected_credentials_generic_v3_generic_proto_msgTypes,
	}.Build()
	File_envoy_extensions_injected_credentials_generic_v3_generic_proto = out.File
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_rawDesc = nil
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_goTypes = nil
	file_envoy_extensions_injected_credentials_generic_v3_generic_proto_depIdxs = nil
}
