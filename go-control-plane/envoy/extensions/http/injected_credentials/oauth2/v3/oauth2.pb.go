// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/extensions/http/injected_credentials/oauth2/v3/oauth2.proto

package oauth2v3

import (
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/core/v3"
	v31 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
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

type OAuth2_AuthType int32

const (
	// The “client_id“ and “client_secret“ will be sent using HTTP Basic authentication scheme.
	OAuth2_BASIC_AUTH OAuth2_AuthType = 0
	// The “client_id“ and “client_secret“ will be sent in the URL encoded request body.
	// This type should only be used when Auth server does not support Basic authentication.
	OAuth2_URL_ENCODED_BODY OAuth2_AuthType = 1
)

// Enum value maps for OAuth2_AuthType.
var (
	OAuth2_AuthType_name = map[int32]string{
		0: "BASIC_AUTH",
		1: "URL_ENCODED_BODY",
	}
	OAuth2_AuthType_value = map[string]int32{
		"BASIC_AUTH":       0,
		"URL_ENCODED_BODY": 1,
	}
)

func (x OAuth2_AuthType) Enum() *OAuth2_AuthType {
	p := new(OAuth2_AuthType)
	*p = x
	return p
}

func (x OAuth2_AuthType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OAuth2_AuthType) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_enumTypes[0].Descriptor()
}

func (OAuth2_AuthType) Type() protoreflect.EnumType {
	return &file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_enumTypes[0]
}

func (x OAuth2_AuthType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OAuth2_AuthType.Descriptor instead.
func (OAuth2_AuthType) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescGZIP(), []int{0, 0}
}

// OAuth2 extension can be used to retrieve an OAuth2 access token from an authorization server and inject it into the
// proxied requests.
// Currently, only the Client Credentials Grant flow is supported.
// The access token will be injected into the request headers using the “Authorization“ header as a bearer token.
type OAuth2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Endpoint on the authorization server to retrieve the access token from.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-3.2) for details.
	TokenEndpoint *v3.HttpUri `protobuf:"bytes,1,opt,name=token_endpoint,json=tokenEndpoint,proto3" json:"token_endpoint,omitempty"`
	// Optional list of OAuth scopes to be claimed in the authorization request.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2) for details.
	Scopes []string `protobuf:"bytes,2,rep,name=scopes,proto3" json:"scopes,omitempty"`
	// Types that are assignable to FlowType:
	//
	//	*OAuth2_ClientCredentials_
	FlowType isOAuth2_FlowType `protobuf_oneof:"flow_type"`
}

func (x *OAuth2) Reset() {
	*x = OAuth2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OAuth2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OAuth2) ProtoMessage() {}

func (x *OAuth2) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OAuth2.ProtoReflect.Descriptor instead.
func (*OAuth2) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescGZIP(), []int{0}
}

func (x *OAuth2) GetTokenEndpoint() *v3.HttpUri {
	if x != nil {
		return x.TokenEndpoint
	}
	return nil
}

func (x *OAuth2) GetScopes() []string {
	if x != nil {
		return x.Scopes
	}
	return nil
}

func (m *OAuth2) GetFlowType() isOAuth2_FlowType {
	if m != nil {
		return m.FlowType
	}
	return nil
}

func (x *OAuth2) GetClientCredentials() *OAuth2_ClientCredentials {
	if x, ok := x.GetFlowType().(*OAuth2_ClientCredentials_); ok {
		return x.ClientCredentials
	}
	return nil
}

type isOAuth2_FlowType interface {
	isOAuth2_FlowType()
}

type OAuth2_ClientCredentials_ struct {
	// Client Credentials Grant.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) for details.
	ClientCredentials *OAuth2_ClientCredentials `protobuf:"bytes,3,opt,name=client_credentials,json=clientCredentials,proto3,oneof"`
}

func (*OAuth2_ClientCredentials_) isOAuth2_FlowType() {}

// Credentials to authenticate client to the authorization server.
// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-2.3) for details.
type OAuth2_ClientCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Client ID.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) for details.
	ClientId string `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	// Client secret.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) for details.
	ClientSecret *v31.SdsSecretConfig `protobuf:"bytes,2,opt,name=client_secret,json=clientSecret,proto3" json:"client_secret,omitempty"`
	// The method to use when sending credentials to the authorization server.
	// Refer to [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) for details.
	AuthType OAuth2_AuthType `protobuf:"varint,3,opt,name=auth_type,json=authType,proto3,enum=envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2_AuthType" json:"auth_type,omitempty"`
}

func (x *OAuth2_ClientCredentials) Reset() {
	*x = OAuth2_ClientCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OAuth2_ClientCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OAuth2_ClientCredentials) ProtoMessage() {}

func (x *OAuth2_ClientCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OAuth2_ClientCredentials.ProtoReflect.Descriptor instead.
func (*OAuth2_ClientCredentials) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescGZIP(), []int{0, 0}
}

func (x *OAuth2_ClientCredentials) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *OAuth2_ClientCredentials) GetClientSecret() *v31.SdsSecretConfig {
	if x != nil {
		return x.ClientSecret
	}
	return nil
}

func (x *OAuth2_ClientCredentials) GetAuthType() OAuth2_AuthType {
	if x != nil {
		return x.AuthType
	}
	return OAuth2_BASIC_AUTH
}

var File_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto protoreflect.FileDescriptor

var file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDesc = []byte{
	0x0a, 0x41, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64,
	0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2f, 0x6f, 0x61, 0x75,
	0x74, 0x68, 0x32, 0x2f, 0x76, 0x33, 0x2f, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x34, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x69, 0x6e, 0x6a, 0x65, 0x63,
	0x74, 0x65, 0x64, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e,
	0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x2e, 0x76, 0x33, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f,
	0x68, 0x74, 0x74, 0x70, 0x5f, 0x75, 0x72, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x36,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65,
	0x74, 0x73, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x78, 0x64, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xc0, 0x04, 0x0a, 0x06, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x12, 0x4e, 0x0a, 0x0e, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x5f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x48, 0x74, 0x74, 0x70, 0x55, 0x72,
	0x69, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0d, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x73, 0x12, 0x7f, 0x0a, 0x12, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x4e,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f,
	0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x6f, 0x61, 0x75, 0x74,
	0x68, 0x32, 0x2e, 0x76, 0x33, 0x2e, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x2e, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x48, 0x00,
	0x52, 0x11, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x73, 0x1a, 0x88, 0x02, 0x0a, 0x11, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x24, 0x0a, 0x09, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42,
	0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12,
	0x69, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x74, 0x6c, 0x73, 0x2e,
	0x76, 0x33, 0x2e, 0x53, 0x64, 0x73, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0c, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x62, 0x0a, 0x09, 0x61, 0x75,
	0x74, 0x68, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x45, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x63,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x6f, 0x61, 0x75, 0x74, 0x68,
	0x32, 0x2e, 0x76, 0x33, 0x2e, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x32, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x08, 0x61, 0x75, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x22, 0x30,
	0x0a, 0x08, 0x41, 0x75, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x0a, 0x42, 0x41,
	0x53, 0x49, 0x43, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x10, 0x00, 0x12, 0x14, 0x0a, 0x10, 0x55, 0x52,
	0x4c, 0x5f, 0x45, 0x4e, 0x43, 0x4f, 0x44, 0x45, 0x44, 0x5f, 0x42, 0x4f, 0x44, 0x59, 0x10, 0x01,
	0x42, 0x10, 0x0a, 0x09, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x12, 0x03, 0xf8,
	0x42, 0x01, 0x42, 0xc9, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4,
	0xe1, 0x06, 0x02, 0x08, 0x01, 0x0a, 0x42, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x69, 0x6e, 0x6a, 0x65, 0x63,
	0x74, 0x65, 0x64, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e,
	0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x2e, 0x76, 0x33, 0x42, 0x0b, 0x4f, 0x61, 0x75, 0x74, 0x68,
	0x32, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x64, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f,
	0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x69, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f,
	0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2f, 0x6f, 0x61, 0x75, 0x74,
	0x68, 0x32, 0x2f, 0x76, 0x33, 0x3b, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x32, 0x76, 0x33, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescOnce sync.Once
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescData = file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDesc
)

func file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescGZIP() []byte {
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescData)
	})
	return file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDescData
}

var file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_goTypes = []interface{}{
	(OAuth2_AuthType)(0),             // 0: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.AuthType
	(*OAuth2)(nil),                   // 1: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2
	(*OAuth2_ClientCredentials)(nil), // 2: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.ClientCredentials
	(*v3.HttpUri)(nil),               // 3: envoy.config.core.v3.HttpUri
	(*v31.SdsSecretConfig)(nil),      // 4: envoy.extensions.transport_sockets.tls.v3.SdsSecretConfig
}
var file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_depIdxs = []int32{
	3, // 0: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.token_endpoint:type_name -> envoy.config.core.v3.HttpUri
	2, // 1: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.client_credentials:type_name -> envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.ClientCredentials
	4, // 2: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.ClientCredentials.client_secret:type_name -> envoy.extensions.transport_sockets.tls.v3.SdsSecretConfig
	0, // 3: envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.ClientCredentials.auth_type:type_name -> envoy.extensions.http.injected_credentials.oauth2.v3.OAuth2.AuthType
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_init() }
func file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_init() {
	if File_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OAuth2); i {
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
		file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OAuth2_ClientCredentials); i {
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
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*OAuth2_ClientCredentials_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_depIdxs,
		EnumInfos:         file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_enumTypes,
		MessageInfos:      file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_msgTypes,
	}.Build()
	File_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto = out.File
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_rawDesc = nil
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_goTypes = nil
	file_envoy_extensions_http_injected_credentials_oauth2_v3_oauth2_proto_depIdxs = nil
}
