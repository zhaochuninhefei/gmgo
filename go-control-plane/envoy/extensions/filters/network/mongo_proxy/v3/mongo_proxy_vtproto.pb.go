//go:build vtprotobuf
// +build vtprotobuf

// Code generated by protoc-gen-go-vtproto. DO NOT EDIT.
// source: envoy/extensions/filters/network/mongo_proxy/v3/mongo_proxy.proto

package mongo_proxyv3

import (
	protohelpers "github.com/planetscale/vtprotobuf/protohelpers"
	proto "google.golang.org/protobuf/proto"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

func (m *MongoProxy) MarshalVTStrict() (dAtA []byte, err error) {
	if m == nil {
		return nil, nil
	}
	size := m.SizeVT()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBufferVTStrict(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MongoProxy) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *MongoProxy) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
	if m == nil {
		return 0, nil
	}
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.unknownFields != nil {
		i -= len(m.unknownFields)
		copy(dAtA[i:], m.unknownFields)
	}
	if len(m.Commands) > 0 {
		for iNdEx := len(m.Commands) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Commands[iNdEx])
			copy(dAtA[i:], m.Commands[iNdEx])
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Commands[iNdEx])))
			i--
			dAtA[i] = 0x2a
		}
	}
	if m.EmitDynamicMetadata {
		i--
		if m.EmitDynamicMetadata {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x20
	}
	if m.Delay != nil {
		if vtmsg, ok := interface{}(m.Delay).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.Delay)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x1a
	}
	if len(m.AccessLog) > 0 {
		i -= len(m.AccessLog)
		copy(dAtA[i:], m.AccessLog)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.AccessLog)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.StatPrefix) > 0 {
		i -= len(m.StatPrefix)
		copy(dAtA[i:], m.StatPrefix)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.StatPrefix)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *MongoProxy) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.StatPrefix)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.AccessLog)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.Delay != nil {
		if size, ok := interface{}(m.Delay).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.Delay)
		}
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.EmitDynamicMetadata {
		n += 2
	}
	if len(m.Commands) > 0 {
		for _, s := range m.Commands {
			l = len(s)
			n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
		}
	}
	n += len(m.unknownFields)
	return n
}
