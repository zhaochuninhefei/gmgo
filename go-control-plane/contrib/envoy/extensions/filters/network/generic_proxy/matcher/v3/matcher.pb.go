// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.4
// source: contrib/envoy/extensions/filters/network/generic_proxy/matcher/v3/matcher.proto

package matcherv3

import (
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/type/matcher/v3"
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

// Used to match request service of the downstream request. Only applicable if a service provided
// by the application protocol.
// This is deprecated and should be replaced by HostMatchInput. This is kept for backward compatibility.
type ServiceMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ServiceMatchInput) Reset() {
	*x = ServiceMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServiceMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServiceMatchInput) ProtoMessage() {}

func (x *ServiceMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServiceMatchInput.ProtoReflect.Descriptor instead.
func (*ServiceMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{0}
}

// Used to match request host of the generic downstream request. Only applicable if a host provided
// by the application protocol.
// This is same with the ServiceMatchInput and this should be preferred over ServiceMatchInput.
type HostMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HostMatchInput) Reset() {
	*x = HostMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostMatchInput) ProtoMessage() {}

func (x *HostMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostMatchInput.ProtoReflect.Descriptor instead.
func (*HostMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{1}
}

// Used to match request path of the generic downstream request. Only applicable if a path provided
// by the application protocol.
type PathMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PathMatchInput) Reset() {
	*x = PathMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PathMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PathMatchInput) ProtoMessage() {}

func (x *PathMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PathMatchInput.ProtoReflect.Descriptor instead.
func (*PathMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{2}
}

// Used to match request method of the generic downstream request. Only applicable if a method provided
// by the application protocol.
type MethodMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *MethodMatchInput) Reset() {
	*x = MethodMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MethodMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MethodMatchInput) ProtoMessage() {}

func (x *MethodMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MethodMatchInput.ProtoReflect.Descriptor instead.
func (*MethodMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{3}
}

// Used to match an arbitrary property of the generic downstream request.
// These properties are populated by the codecs of application protocols.
type PropertyMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The property name to match on.
	PropertyName string `protobuf:"bytes,1,opt,name=property_name,json=propertyName,proto3" json:"property_name,omitempty"`
}

func (x *PropertyMatchInput) Reset() {
	*x = PropertyMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PropertyMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PropertyMatchInput) ProtoMessage() {}

func (x *PropertyMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PropertyMatchInput.ProtoReflect.Descriptor instead.
func (*PropertyMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{4}
}

func (x *PropertyMatchInput) GetPropertyName() string {
	if x != nil {
		return x.PropertyName
	}
	return ""
}

// Used to match an whole generic downstream request.
type RequestMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RequestMatchInput) Reset() {
	*x = RequestMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RequestMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestMatchInput) ProtoMessage() {}

func (x *RequestMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestMatchInput.ProtoReflect.Descriptor instead.
func (*RequestMatchInput) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{5}
}

// Used to match an arbitrary key-value pair for headers, trailers or properties.
type KeyValueMatchEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The key name to match on.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The key value pattern.
	StringMatch *v3.StringMatcher `protobuf:"bytes,2,opt,name=string_match,json=stringMatch,proto3" json:"string_match,omitempty"`
}

func (x *KeyValueMatchEntry) Reset() {
	*x = KeyValueMatchEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyValueMatchEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyValueMatchEntry) ProtoMessage() {}

func (x *KeyValueMatchEntry) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyValueMatchEntry.ProtoReflect.Descriptor instead.
func (*KeyValueMatchEntry) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{6}
}

func (x *KeyValueMatchEntry) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KeyValueMatchEntry) GetStringMatch() *v3.StringMatcher {
	if x != nil {
		return x.StringMatch
	}
	return nil
}

// Custom matcher to match on the generic downstream request. This is used to match
// multiple fields of the downstream request and avoid complex combinations of
// HostMatchInput, PathMatchInput, MethodMatchInput and PropertyMatchInput.
type RequestMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Optional host pattern to match on. If not specified, any host will match.
	Host *v3.StringMatcher `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	// Optional path pattern to match on. If not specified, any path will match.
	Path *v3.StringMatcher `protobuf:"bytes,2,opt,name=path,proto3" json:"path,omitempty"`
	// Optional method pattern to match on. If not specified, any method will match.
	Method *v3.StringMatcher `protobuf:"bytes,3,opt,name=method,proto3" json:"method,omitempty"`
	// Optional arbitrary properties to match on. If not specified, any properties
	// will match. The key is the property name and the value is the property value
	// to match on.
	Properties []*KeyValueMatchEntry `protobuf:"bytes,4,rep,name=properties,proto3" json:"properties,omitempty"`
}

func (x *RequestMatcher) Reset() {
	*x = RequestMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RequestMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestMatcher) ProtoMessage() {}

func (x *RequestMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestMatcher.ProtoReflect.Descriptor instead.
func (*RequestMatcher) Descriptor() ([]byte, []int) {
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP(), []int{7}
}

func (x *RequestMatcher) GetHost() *v3.StringMatcher {
	if x != nil {
		return x.Host
	}
	return nil
}

func (x *RequestMatcher) GetPath() *v3.StringMatcher {
	if x != nil {
		return x.Path
	}
	return nil
}

func (x *RequestMatcher) GetMethod() *v3.StringMatcher {
	if x != nil {
		return x.Method
	}
	return nil
}

func (x *RequestMatcher) GetProperties() []*KeyValueMatchEntry {
	if x != nil {
		return x.Properties
	}
	return nil
}

var File_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto protoreflect.FileDescriptor

var file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDesc = []byte{
	0x0a, 0x4f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x2f, 0x76, 0x33, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x39, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77,
	0x6f, 0x72, 0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a, 0x22, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1f, 0x78, 0x64, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x13, 0x0a, 0x11, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x10,
	0x0a, 0x0e, 0x48, 0x6f, 0x73, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70, 0x75, 0x74,
	0x22, 0x10, 0x0a, 0x0e, 0x50, 0x61, 0x74, 0x68, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70,
	0x75, 0x74, 0x22, 0x12, 0x0a, 0x10, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x42, 0x0a, 0x12, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72,
	0x74, 0x79, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x12, 0x2c, 0x0a, 0x0d,
	0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x0c, 0x70, 0x72,
	0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x13, 0x0a, 0x11, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22,
	0x84, 0x01, 0x0a, 0x12, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x1b, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x51, 0x0a, 0x0c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76,
	0x33, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x42,
	0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0b, 0x73, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x22, 0xb1, 0x02, 0x0a, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x38, 0x0a, 0x04, 0x68, 0x6f, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x04, 0x68,
	0x6f, 0x73, 0x74, 0x12, 0x38, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x24, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d,
	0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x3c, 0x0a,
	0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x6d, 0x0a, 0x0a, 0x70,
	0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x4d, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x4b, 0x65, 0x79, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a,
	0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x42, 0xdd, 0x01, 0xba, 0x80, 0xc8,
	0xd1, 0x06, 0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4, 0xe1, 0x06, 0x02, 0x08, 0x01, 0x0a, 0x47, 0x69,
	0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x67, 0x65,
	0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x42, 0x0c, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x72, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f,
	0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x69, 0x62, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33,
	0x3b, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescOnce sync.Once
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescData = file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDesc
)

func file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescGZIP() []byte {
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescOnce.Do(func() {
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescData = protoimpl.X.CompressGZIP(file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescData)
	})
	return file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDescData
}

var file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_goTypes = []interface{}{
	(*ServiceMatchInput)(nil),  // 0: envoy.extensions.filters.network.generic_proxy.matcher.v3.ServiceMatchInput
	(*HostMatchInput)(nil),     // 1: envoy.extensions.filters.network.generic_proxy.matcher.v3.HostMatchInput
	(*PathMatchInput)(nil),     // 2: envoy.extensions.filters.network.generic_proxy.matcher.v3.PathMatchInput
	(*MethodMatchInput)(nil),   // 3: envoy.extensions.filters.network.generic_proxy.matcher.v3.MethodMatchInput
	(*PropertyMatchInput)(nil), // 4: envoy.extensions.filters.network.generic_proxy.matcher.v3.PropertyMatchInput
	(*RequestMatchInput)(nil),  // 5: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatchInput
	(*KeyValueMatchEntry)(nil), // 6: envoy.extensions.filters.network.generic_proxy.matcher.v3.KeyValueMatchEntry
	(*RequestMatcher)(nil),     // 7: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher
	(*v3.StringMatcher)(nil),   // 8: envoy.type.matcher.v3.StringMatcher
}
var file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_depIdxs = []int32{
	8, // 0: envoy.extensions.filters.network.generic_proxy.matcher.v3.KeyValueMatchEntry.string_match:type_name -> envoy.type.matcher.v3.StringMatcher
	8, // 1: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher.host:type_name -> envoy.type.matcher.v3.StringMatcher
	8, // 2: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher.path:type_name -> envoy.type.matcher.v3.StringMatcher
	8, // 3: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher.method:type_name -> envoy.type.matcher.v3.StringMatcher
	6, // 4: envoy.extensions.filters.network.generic_proxy.matcher.v3.RequestMatcher.properties:type_name -> envoy.extensions.filters.network.generic_proxy.matcher.v3.KeyValueMatchEntry
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() {
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_init()
}
func file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_init() {
	if File_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ServiceMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PathMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MethodMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PropertyMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RequestMatchInput); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyValueMatchEntry); i {
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
		file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RequestMatcher); i {
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
			RawDescriptor: file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_goTypes,
		DependencyIndexes: file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_depIdxs,
		MessageInfos:      file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_msgTypes,
	}.Build()
	File_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto = out.File
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_rawDesc = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_goTypes = nil
	file_contrib_envoy_extensions_filters_network_generic_proxy_matcher_v3_matcher_proto_depIdxs = nil
}
