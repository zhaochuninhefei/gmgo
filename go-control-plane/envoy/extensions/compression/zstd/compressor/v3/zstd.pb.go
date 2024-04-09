// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.4
// source: envoy/extensions/compression/zstd/compressor/v3/zstd.proto

package compressorv3

import (
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/core/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
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

// Reference to http://facebook.github.io/zstd/zstd_manual.html
type Zstd_Strategy int32

const (
	Zstd_DEFAULT  Zstd_Strategy = 0
	Zstd_FAST     Zstd_Strategy = 1
	Zstd_DFAST    Zstd_Strategy = 2
	Zstd_GREEDY   Zstd_Strategy = 3
	Zstd_LAZY     Zstd_Strategy = 4
	Zstd_LAZY2    Zstd_Strategy = 5
	Zstd_BTLAZY2  Zstd_Strategy = 6
	Zstd_BTOPT    Zstd_Strategy = 7
	Zstd_BTULTRA  Zstd_Strategy = 8
	Zstd_BTULTRA2 Zstd_Strategy = 9
)

// Enum value maps for Zstd_Strategy.
var (
	Zstd_Strategy_name = map[int32]string{
		0: "DEFAULT",
		1: "FAST",
		2: "DFAST",
		3: "GREEDY",
		4: "LAZY",
		5: "LAZY2",
		6: "BTLAZY2",
		7: "BTOPT",
		8: "BTULTRA",
		9: "BTULTRA2",
	}
	Zstd_Strategy_value = map[string]int32{
		"DEFAULT":  0,
		"FAST":     1,
		"DFAST":    2,
		"GREEDY":   3,
		"LAZY":     4,
		"LAZY2":    5,
		"BTLAZY2":  6,
		"BTOPT":    7,
		"BTULTRA":  8,
		"BTULTRA2": 9,
	}
)

func (x Zstd_Strategy) Enum() *Zstd_Strategy {
	p := new(Zstd_Strategy)
	*p = x
	return p
}

func (x Zstd_Strategy) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Zstd_Strategy) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_enumTypes[0].Descriptor()
}

func (Zstd_Strategy) Type() protoreflect.EnumType {
	return &file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_enumTypes[0]
}

func (x Zstd_Strategy) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Zstd_Strategy.Descriptor instead.
func (Zstd_Strategy) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescGZIP(), []int{0, 0}
}

// [#next-free-field: 6]
type Zstd struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Set compression parameters according to pre-defined compression level table.
	// Note that exact compression parameters are dynamically determined,
	// depending on both compression level and source content size (when known).
	// Value 0 means default, and default level is 3.
	// Setting a level does not automatically set all other compression parameters
	// to default. Setting this will however eventually dynamically impact the compression
	// parameters which have not been manually set. The manually set
	// ones will 'stick'.
	CompressionLevel *wrappers.UInt32Value `protobuf:"bytes,1,opt,name=compression_level,json=compressionLevel,proto3" json:"compression_level,omitempty"`
	// A 32-bits checksum of content is written at end of frame. If not set, defaults to false.
	EnableChecksum bool `protobuf:"varint,2,opt,name=enable_checksum,json=enableChecksum,proto3" json:"enable_checksum,omitempty"`
	// The higher the value of selected strategy, the more complex it is,
	// resulting in stronger and slower compression.
	// Special: value 0 means "use default strategy".
	Strategy Zstd_Strategy `protobuf:"varint,3,opt,name=strategy,proto3,enum=envoy.extensions.compression.zstd.compressor.v3.Zstd_Strategy" json:"strategy,omitempty"`
	// A dictionary for compression. Zstd offers dictionary compression, which greatly improves
	// efficiency on small files and messages. Each dictionary will be generated with a dictionary ID
	// that can be used to search the same dictionary during decompression.
	// Please refer to `zstd manual <https://github.com/facebook/zstd/blob/dev/programs/zstd.1.md#dictionary-builder>`_
	// to train a specific dictionary for compression.
	Dictionary *v3.DataSource `protobuf:"bytes,4,opt,name=dictionary,proto3" json:"dictionary,omitempty"`
	// Value for compressor's next output buffer. If not set, defaults to 4096.
	ChunkSize *wrappers.UInt32Value `protobuf:"bytes,5,opt,name=chunk_size,json=chunkSize,proto3" json:"chunk_size,omitempty"`
}

func (x *Zstd) Reset() {
	*x = Zstd{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Zstd) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Zstd) ProtoMessage() {}

func (x *Zstd) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Zstd.ProtoReflect.Descriptor instead.
func (*Zstd) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescGZIP(), []int{0}
}

func (x *Zstd) GetCompressionLevel() *wrappers.UInt32Value {
	if x != nil {
		return x.CompressionLevel
	}
	return nil
}

func (x *Zstd) GetEnableChecksum() bool {
	if x != nil {
		return x.EnableChecksum
	}
	return false
}

func (x *Zstd) GetStrategy() Zstd_Strategy {
	if x != nil {
		return x.Strategy
	}
	return Zstd_DEFAULT
}

func (x *Zstd) GetDictionary() *v3.DataSource {
	if x != nil {
		return x.Dictionary
	}
	return nil
}

func (x *Zstd) GetChunkSize() *wrappers.UInt32Value {
	if x != nil {
		return x.ChunkSize
	}
	return nil
}

var File_envoy_extensions_compression_zstd_compressor_v3_zstd_proto protoreflect.FileDescriptor

var file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDesc = []byte{
	0x0a, 0x3a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x7a,
	0x73, 0x74, 0x64, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6f, 0x72, 0x2f, 0x76,
	0x33, 0x2f, 0x7a, 0x73, 0x74, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x2f, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x63,
	0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x7a, 0x73, 0x74, 0x64, 0x2e,
	0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6f, 0x72, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65,
	0x2f, 0x76, 0x33, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d,
	0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf0, 0x03, 0x0a, 0x04, 0x5a, 0x73, 0x74, 0x64, 0x12,
	0x49, 0x0a, 0x11, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e,
	0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x10, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x27, 0x0a, 0x0f, 0x65, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x5f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0e, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x43, 0x68, 0x65, 0x63, 0x6b,
	0x73, 0x75, 0x6d, 0x12, 0x64, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x3e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x7a, 0x73, 0x74, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65,
	0x73, 0x73, 0x6f, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x5a, 0x73, 0x74, 0x64, 0x2e, 0x53, 0x74, 0x72,
	0x61, 0x74, 0x65, 0x67, 0x79, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x82, 0x01, 0x02, 0x10, 0x01, 0x52,
	0x08, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x12, 0x40, 0x0a, 0x0a, 0x64, 0x69, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52,
	0x0a, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x12, 0x49, 0x0a, 0x0a, 0x63,
	0x68, 0x75, 0x6e, 0x6b, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x0c, 0xfa,
	0x42, 0x09, 0x2a, 0x07, 0x18, 0x80, 0x80, 0x04, 0x28, 0x80, 0x20, 0x52, 0x09, 0x63, 0x68, 0x75,
	0x6e, 0x6b, 0x53, 0x69, 0x7a, 0x65, 0x22, 0x80, 0x01, 0x0a, 0x08, 0x53, 0x74, 0x72, 0x61, 0x74,
	0x65, 0x67, 0x79, 0x12, 0x0b, 0x0a, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x10, 0x00,
	0x12, 0x08, 0x0a, 0x04, 0x46, 0x41, 0x53, 0x54, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x44, 0x46,
	0x41, 0x53, 0x54, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x47, 0x52, 0x45, 0x45, 0x44, 0x59, 0x10,
	0x03, 0x12, 0x08, 0x0a, 0x04, 0x4c, 0x41, 0x5a, 0x59, 0x10, 0x04, 0x12, 0x09, 0x0a, 0x05, 0x4c,
	0x41, 0x5a, 0x59, 0x32, 0x10, 0x05, 0x12, 0x0b, 0x0a, 0x07, 0x42, 0x54, 0x4c, 0x41, 0x5a, 0x59,
	0x32, 0x10, 0x06, 0x12, 0x09, 0x0a, 0x05, 0x42, 0x54, 0x4f, 0x50, 0x54, 0x10, 0x07, 0x12, 0x0b,
	0x0a, 0x07, 0x42, 0x54, 0x55, 0x4c, 0x54, 0x52, 0x41, 0x10, 0x08, 0x12, 0x0c, 0x0a, 0x08, 0x42,
	0x54, 0x55, 0x4c, 0x54, 0x52, 0x41, 0x32, 0x10, 0x09, 0x42, 0xb9, 0x01, 0xba, 0x80, 0xc8, 0xd1,
	0x06, 0x02, 0x10, 0x02, 0x0a, 0x3d, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x2e, 0x7a, 0x73, 0x74, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6f, 0x72,
	0x2e, 0x76, 0x33, 0x42, 0x09, 0x5a, 0x73, 0x74, 0x64, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01,
	0x5a, 0x63, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x7a, 0x73, 0x74, 0x64, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x72,
	0x65, 0x73, 0x73, 0x6f, 0x72, 0x2f, 0x76, 0x33, 0x3b, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73,
	0x73, 0x6f, 0x72, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescOnce sync.Once
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescData = file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDesc
)

func file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescGZIP() []byte {
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescData)
	})
	return file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDescData
}

var file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_goTypes = []interface{}{
	(Zstd_Strategy)(0),           // 0: envoy.extensions.compression.zstd.compressor.v3.Zstd.Strategy
	(*Zstd)(nil),                 // 1: envoy.extensions.compression.zstd.compressor.v3.Zstd
	(*wrappers.UInt32Value)(nil), // 2: google.protobuf.UInt32Value
	(*v3.DataSource)(nil),        // 3: envoy.config.core.v3.DataSource
}
var file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_depIdxs = []int32{
	2, // 0: envoy.extensions.compression.zstd.compressor.v3.Zstd.compression_level:type_name -> google.protobuf.UInt32Value
	0, // 1: envoy.extensions.compression.zstd.compressor.v3.Zstd.strategy:type_name -> envoy.extensions.compression.zstd.compressor.v3.Zstd.Strategy
	3, // 2: envoy.extensions.compression.zstd.compressor.v3.Zstd.dictionary:type_name -> envoy.config.core.v3.DataSource
	2, // 3: envoy.extensions.compression.zstd.compressor.v3.Zstd.chunk_size:type_name -> google.protobuf.UInt32Value
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_init() }
func file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_init() {
	if File_envoy_extensions_compression_zstd_compressor_v3_zstd_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Zstd); i {
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
			RawDescriptor: file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_depIdxs,
		EnumInfos:         file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_enumTypes,
		MessageInfos:      file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_msgTypes,
	}.Build()
	File_envoy_extensions_compression_zstd_compressor_v3_zstd_proto = out.File
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_rawDesc = nil
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_goTypes = nil
	file_envoy_extensions_compression_zstd_compressor_v3_zstd_proto_depIdxs = nil
}
