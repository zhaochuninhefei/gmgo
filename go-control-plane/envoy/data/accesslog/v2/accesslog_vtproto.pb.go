//go:build vtprotobuf
// +build vtprotobuf

// Code generated by protoc-gen-go-vtproto. DO NOT EDIT.
// source: envoy/data/accesslog/v2/accesslog.proto

package accesslogv2

import (
	binary "encoding/binary"
	protohelpers "github.com/planetscale/vtprotobuf/protohelpers"
	anypb "github.com/planetscale/vtprotobuf/types/known/anypb"
	durationpb "github.com/planetscale/vtprotobuf/types/known/durationpb"
	timestamppb "github.com/planetscale/vtprotobuf/types/known/timestamppb"
	wrapperspb "github.com/planetscale/vtprotobuf/types/known/wrapperspb"
	proto "google.golang.org/protobuf/proto"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	math "math"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

func (m *TCPAccessLogEntry) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *TCPAccessLogEntry) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TCPAccessLogEntry) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if m.ConnectionProperties != nil {
		size, err := m.ConnectionProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x12
	}
	if m.CommonProperties != nil {
		size, err := m.CommonProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *HTTPAccessLogEntry) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *HTTPAccessLogEntry) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *HTTPAccessLogEntry) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if m.Response != nil {
		size, err := m.Response.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x22
	}
	if m.Request != nil {
		size, err := m.Request.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x1a
	}
	if m.ProtocolVersion != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.ProtocolVersion))
		i--
		dAtA[i] = 0x10
	}
	if m.CommonProperties != nil {
		size, err := m.CommonProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ConnectionProperties) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *ConnectionProperties) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *ConnectionProperties) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if m.SentBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.SentBytes))
		i--
		dAtA[i] = 0x10
	}
	if m.ReceivedBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.ReceivedBytes))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *AccessLogCommon) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *AccessLogCommon) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *AccessLogCommon) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if len(m.FilterStateObjects) > 0 {
		for k := range m.FilterStateObjects {
			v := m.FilterStateObjects[k]
			baseI := i
			size, err := (*anypb.Any)(v).MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = protohelpers.EncodeVarint(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x1
			i--
			dAtA[i] = 0xaa
		}
	}
	if m.DownstreamDirectRemoteAddress != nil {
		if vtmsg, ok := interface{}(m.DownstreamDirectRemoteAddress).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.DownstreamDirectRemoteAddress)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0xa2
	}
	if len(m.RouteName) > 0 {
		i -= len(m.RouteName)
		copy(dAtA[i:], m.RouteName)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.RouteName)))
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x9a
	}
	if len(m.UpstreamTransportFailureReason) > 0 {
		i -= len(m.UpstreamTransportFailureReason)
		copy(dAtA[i:], m.UpstreamTransportFailureReason)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.UpstreamTransportFailureReason)))
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x92
	}
	if m.Metadata != nil {
		if vtmsg, ok := interface{}(m.Metadata).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.Metadata)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x8a
	}
	if m.ResponseFlags != nil {
		size, err := m.ResponseFlags.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x82
	}
	if len(m.UpstreamCluster) > 0 {
		i -= len(m.UpstreamCluster)
		copy(dAtA[i:], m.UpstreamCluster)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.UpstreamCluster)))
		i--
		dAtA[i] = 0x7a
	}
	if m.UpstreamLocalAddress != nil {
		if vtmsg, ok := interface{}(m.UpstreamLocalAddress).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.UpstreamLocalAddress)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x72
	}
	if m.UpstreamRemoteAddress != nil {
		if vtmsg, ok := interface{}(m.UpstreamRemoteAddress).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.UpstreamRemoteAddress)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x6a
	}
	if m.TimeToLastDownstreamTxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToLastDownstreamTxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x62
	}
	if m.TimeToFirstDownstreamTxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToFirstDownstreamTxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x5a
	}
	if m.TimeToLastUpstreamRxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToLastUpstreamRxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x52
	}
	if m.TimeToFirstUpstreamRxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToFirstUpstreamRxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x4a
	}
	if m.TimeToLastUpstreamTxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToLastUpstreamTxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x42
	}
	if m.TimeToFirstUpstreamTxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToFirstUpstreamTxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x3a
	}
	if m.TimeToLastRxByte != nil {
		size, err := (*durationpb.Duration)(m.TimeToLastRxByte).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x32
	}
	if m.StartTime != nil {
		size, err := (*timestamppb.Timestamp)(m.StartTime).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x2a
	}
	if m.TlsProperties != nil {
		size, err := m.TlsProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x22
	}
	if m.DownstreamLocalAddress != nil {
		if vtmsg, ok := interface{}(m.DownstreamLocalAddress).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.DownstreamLocalAddress)
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
	if m.DownstreamRemoteAddress != nil {
		if vtmsg, ok := interface{}(m.DownstreamRemoteAddress).(interface {
			MarshalToSizedBufferVTStrict([]byte) (int, error)
		}); ok {
			size, err := vtmsg.MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		} else {
			encoded, err := proto.Marshal(m.DownstreamRemoteAddress)
			if err != nil {
				return 0, err
			}
			i -= len(encoded)
			copy(dAtA[i:], encoded)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(encoded)))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.SampleRate != 0 {
		i -= 8
		binary.LittleEndian.PutUint64(dAtA[i:], uint64(math.Float64bits(float64(m.SampleRate))))
		i--
		dAtA[i] = 0x9
	}
	return len(dAtA) - i, nil
}

func (m *ResponseFlags_Unauthorized) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *ResponseFlags_Unauthorized) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *ResponseFlags_Unauthorized) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if m.Reason != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.Reason))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *ResponseFlags) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *ResponseFlags) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *ResponseFlags) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if m.DownstreamProtocolError {
		i--
		if m.DownstreamProtocolError {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x98
	}
	if m.InvalidEnvoyRequestHeaders {
		i--
		if m.InvalidEnvoyRequestHeaders {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x90
	}
	if m.StreamIdleTimeout {
		i--
		if m.StreamIdleTimeout {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x88
	}
	if m.UpstreamRetryLimitExceeded {
		i--
		if m.UpstreamRetryLimitExceeded {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x1
		i--
		dAtA[i] = 0x80
	}
	if m.DownstreamConnectionTermination {
		i--
		if m.DownstreamConnectionTermination {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x78
	}
	if m.RateLimitServiceError {
		i--
		if m.RateLimitServiceError {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x70
	}
	if m.UnauthorizedDetails != nil {
		size, err := m.UnauthorizedDetails.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x6a
	}
	if m.RateLimited {
		i--
		if m.RateLimited {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x60
	}
	if m.FaultInjected {
		i--
		if m.FaultInjected {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x58
	}
	if m.DelayInjected {
		i--
		if m.DelayInjected {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x50
	}
	if m.NoRouteFound {
		i--
		if m.NoRouteFound {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x48
	}
	if m.UpstreamOverflow {
		i--
		if m.UpstreamOverflow {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x40
	}
	if m.UpstreamConnectionTermination {
		i--
		if m.UpstreamConnectionTermination {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x38
	}
	if m.UpstreamConnectionFailure {
		i--
		if m.UpstreamConnectionFailure {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x30
	}
	if m.UpstreamRemoteReset {
		i--
		if m.UpstreamRemoteReset {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x28
	}
	if m.LocalReset {
		i--
		if m.LocalReset {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x20
	}
	if m.UpstreamRequestTimeout {
		i--
		if m.UpstreamRequestTimeout {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x18
	}
	if m.NoHealthyUpstream {
		i--
		if m.NoHealthyUpstream {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if m.FailedLocalHealthcheck {
		i--
		if m.FailedLocalHealthcheck {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *TLSProperties_CertificateProperties_SubjectAltName) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *TLSProperties_CertificateProperties_SubjectAltName) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TLSProperties_CertificateProperties_SubjectAltName) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if msg, ok := m.San.(*TLSProperties_CertificateProperties_SubjectAltName_Dns); ok {
		size, err := msg.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
	}
	if msg, ok := m.San.(*TLSProperties_CertificateProperties_SubjectAltName_Uri); ok {
		size, err := msg.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
	}
	return len(dAtA) - i, nil
}

func (m *TLSProperties_CertificateProperties_SubjectAltName_Uri) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TLSProperties_CertificateProperties_SubjectAltName_Uri) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
	i := len(dAtA)
	i -= len(m.Uri)
	copy(dAtA[i:], m.Uri)
	i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Uri)))
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}
func (m *TLSProperties_CertificateProperties_SubjectAltName_Dns) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TLSProperties_CertificateProperties_SubjectAltName_Dns) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
	i := len(dAtA)
	i -= len(m.Dns)
	copy(dAtA[i:], m.Dns)
	i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Dns)))
	i--
	dAtA[i] = 0x12
	return len(dAtA) - i, nil
}
func (m *TLSProperties_CertificateProperties) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *TLSProperties_CertificateProperties) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TLSProperties_CertificateProperties) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if len(m.Subject) > 0 {
		i -= len(m.Subject)
		copy(dAtA[i:], m.Subject)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Subject)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.SubjectAltName) > 0 {
		for iNdEx := len(m.SubjectAltName) - 1; iNdEx >= 0; iNdEx-- {
			size, err := m.SubjectAltName[iNdEx].MarshalToSizedBufferVTStrict(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *TLSProperties) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *TLSProperties) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *TLSProperties) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if len(m.TlsSessionId) > 0 {
		i -= len(m.TlsSessionId)
		copy(dAtA[i:], m.TlsSessionId)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.TlsSessionId)))
		i--
		dAtA[i] = 0x32
	}
	if m.PeerCertificateProperties != nil {
		size, err := m.PeerCertificateProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x2a
	}
	if m.LocalCertificateProperties != nil {
		size, err := m.LocalCertificateProperties.MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x22
	}
	if len(m.TlsSniHostname) > 0 {
		i -= len(m.TlsSniHostname)
		copy(dAtA[i:], m.TlsSniHostname)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.TlsSniHostname)))
		i--
		dAtA[i] = 0x1a
	}
	if m.TlsCipherSuite != nil {
		size, err := (*wrapperspb.UInt32Value)(m.TlsCipherSuite).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x12
	}
	if m.TlsVersion != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.TlsVersion))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *HTTPRequestProperties) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *HTTPRequestProperties) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *HTTPRequestProperties) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if len(m.RequestHeaders) > 0 {
		for k := range m.RequestHeaders {
			v := m.RequestHeaders[k]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = protohelpers.EncodeVarint(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x6a
		}
	}
	if m.RequestBodyBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.RequestBodyBytes))
		i--
		dAtA[i] = 0x60
	}
	if m.RequestHeadersBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.RequestHeadersBytes))
		i--
		dAtA[i] = 0x58
	}
	if len(m.OriginalPath) > 0 {
		i -= len(m.OriginalPath)
		copy(dAtA[i:], m.OriginalPath)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.OriginalPath)))
		i--
		dAtA[i] = 0x52
	}
	if len(m.RequestId) > 0 {
		i -= len(m.RequestId)
		copy(dAtA[i:], m.RequestId)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.RequestId)))
		i--
		dAtA[i] = 0x4a
	}
	if len(m.ForwardedFor) > 0 {
		i -= len(m.ForwardedFor)
		copy(dAtA[i:], m.ForwardedFor)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.ForwardedFor)))
		i--
		dAtA[i] = 0x42
	}
	if len(m.Referer) > 0 {
		i -= len(m.Referer)
		copy(dAtA[i:], m.Referer)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Referer)))
		i--
		dAtA[i] = 0x3a
	}
	if len(m.UserAgent) > 0 {
		i -= len(m.UserAgent)
		copy(dAtA[i:], m.UserAgent)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.UserAgent)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.Path) > 0 {
		i -= len(m.Path)
		copy(dAtA[i:], m.Path)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Path)))
		i--
		dAtA[i] = 0x2a
	}
	if m.Port != nil {
		size, err := (*wrapperspb.UInt32Value)(m.Port).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0x22
	}
	if len(m.Authority) > 0 {
		i -= len(m.Authority)
		copy(dAtA[i:], m.Authority)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Authority)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Scheme) > 0 {
		i -= len(m.Scheme)
		copy(dAtA[i:], m.Scheme)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.Scheme)))
		i--
		dAtA[i] = 0x12
	}
	if m.RequestMethod != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.RequestMethod))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *HTTPResponseProperties) MarshalVTStrict() (dAtA []byte, err error) {
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

func (m *HTTPResponseProperties) MarshalToVTStrict(dAtA []byte) (int, error) {
	size := m.SizeVT()
	return m.MarshalToSizedBufferVTStrict(dAtA[:size])
}

func (m *HTTPResponseProperties) MarshalToSizedBufferVTStrict(dAtA []byte) (int, error) {
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
	if len(m.ResponseCodeDetails) > 0 {
		i -= len(m.ResponseCodeDetails)
		copy(dAtA[i:], m.ResponseCodeDetails)
		i = protohelpers.EncodeVarint(dAtA, i, uint64(len(m.ResponseCodeDetails)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.ResponseTrailers) > 0 {
		for k := range m.ResponseTrailers {
			v := m.ResponseTrailers[k]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = protohelpers.EncodeVarint(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x2a
		}
	}
	if len(m.ResponseHeaders) > 0 {
		for k := range m.ResponseHeaders {
			v := m.ResponseHeaders[k]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = protohelpers.EncodeVarint(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = protohelpers.EncodeVarint(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x22
		}
	}
	if m.ResponseBodyBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.ResponseBodyBytes))
		i--
		dAtA[i] = 0x18
	}
	if m.ResponseHeadersBytes != 0 {
		i = protohelpers.EncodeVarint(dAtA, i, uint64(m.ResponseHeadersBytes))
		i--
		dAtA[i] = 0x10
	}
	if m.ResponseCode != nil {
		size, err := (*wrapperspb.UInt32Value)(m.ResponseCode).MarshalToSizedBufferVTStrict(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = protohelpers.EncodeVarint(dAtA, i, uint64(size))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *TCPAccessLogEntry) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.CommonProperties != nil {
		l = m.CommonProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.ConnectionProperties != nil {
		l = m.ConnectionProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *HTTPAccessLogEntry) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.CommonProperties != nil {
		l = m.CommonProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.ProtocolVersion != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.ProtocolVersion))
	}
	if m.Request != nil {
		l = m.Request.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.Response != nil {
		l = m.Response.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *ConnectionProperties) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ReceivedBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.ReceivedBytes))
	}
	if m.SentBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.SentBytes))
	}
	n += len(m.unknownFields)
	return n
}

func (m *AccessLogCommon) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.SampleRate != 0 {
		n += 9
	}
	if m.DownstreamRemoteAddress != nil {
		if size, ok := interface{}(m.DownstreamRemoteAddress).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.DownstreamRemoteAddress)
		}
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.DownstreamLocalAddress != nil {
		if size, ok := interface{}(m.DownstreamLocalAddress).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.DownstreamLocalAddress)
		}
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TlsProperties != nil {
		l = m.TlsProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.StartTime != nil {
		l = (*timestamppb.Timestamp)(m.StartTime).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToLastRxByte != nil {
		l = (*durationpb.Duration)(m.TimeToLastRxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToFirstUpstreamTxByte != nil {
		l = (*durationpb.Duration)(m.TimeToFirstUpstreamTxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToLastUpstreamTxByte != nil {
		l = (*durationpb.Duration)(m.TimeToLastUpstreamTxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToFirstUpstreamRxByte != nil {
		l = (*durationpb.Duration)(m.TimeToFirstUpstreamRxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToLastUpstreamRxByte != nil {
		l = (*durationpb.Duration)(m.TimeToLastUpstreamRxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToFirstDownstreamTxByte != nil {
		l = (*durationpb.Duration)(m.TimeToFirstDownstreamTxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.TimeToLastDownstreamTxByte != nil {
		l = (*durationpb.Duration)(m.TimeToLastDownstreamTxByte).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.UpstreamRemoteAddress != nil {
		if size, ok := interface{}(m.UpstreamRemoteAddress).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.UpstreamRemoteAddress)
		}
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.UpstreamLocalAddress != nil {
		if size, ok := interface{}(m.UpstreamLocalAddress).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.UpstreamLocalAddress)
		}
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.UpstreamCluster)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.ResponseFlags != nil {
		l = m.ResponseFlags.SizeVT()
		n += 2 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.Metadata != nil {
		if size, ok := interface{}(m.Metadata).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.Metadata)
		}
		n += 2 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.UpstreamTransportFailureReason)
	if l > 0 {
		n += 2 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.RouteName)
	if l > 0 {
		n += 2 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.DownstreamDirectRemoteAddress != nil {
		if size, ok := interface{}(m.DownstreamDirectRemoteAddress).(interface {
			SizeVT() int
		}); ok {
			l = size.SizeVT()
		} else {
			l = proto.Size(m.DownstreamDirectRemoteAddress)
		}
		n += 2 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if len(m.FilterStateObjects) > 0 {
		for k, v := range m.FilterStateObjects {
			_ = k
			_ = v
			l = 0
			if v != nil {
				l = (*anypb.Any)(v).SizeVT()
			}
			l += 1 + protohelpers.SizeOfVarint(uint64(l))
			mapEntrySize := 1 + len(k) + protohelpers.SizeOfVarint(uint64(len(k))) + l
			n += mapEntrySize + 2 + protohelpers.SizeOfVarint(uint64(mapEntrySize))
		}
	}
	n += len(m.unknownFields)
	return n
}

func (m *ResponseFlags_Unauthorized) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Reason != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.Reason))
	}
	n += len(m.unknownFields)
	return n
}

func (m *ResponseFlags) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.FailedLocalHealthcheck {
		n += 2
	}
	if m.NoHealthyUpstream {
		n += 2
	}
	if m.UpstreamRequestTimeout {
		n += 2
	}
	if m.LocalReset {
		n += 2
	}
	if m.UpstreamRemoteReset {
		n += 2
	}
	if m.UpstreamConnectionFailure {
		n += 2
	}
	if m.UpstreamConnectionTermination {
		n += 2
	}
	if m.UpstreamOverflow {
		n += 2
	}
	if m.NoRouteFound {
		n += 2
	}
	if m.DelayInjected {
		n += 2
	}
	if m.FaultInjected {
		n += 2
	}
	if m.RateLimited {
		n += 2
	}
	if m.UnauthorizedDetails != nil {
		l = m.UnauthorizedDetails.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.RateLimitServiceError {
		n += 2
	}
	if m.DownstreamConnectionTermination {
		n += 2
	}
	if m.UpstreamRetryLimitExceeded {
		n += 3
	}
	if m.StreamIdleTimeout {
		n += 3
	}
	if m.InvalidEnvoyRequestHeaders {
		n += 3
	}
	if m.DownstreamProtocolError {
		n += 3
	}
	n += len(m.unknownFields)
	return n
}

func (m *TLSProperties_CertificateProperties_SubjectAltName) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if vtmsg, ok := m.San.(interface{ SizeVT() int }); ok {
		n += vtmsg.SizeVT()
	}
	n += len(m.unknownFields)
	return n
}

func (m *TLSProperties_CertificateProperties_SubjectAltName_Uri) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Uri)
	n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	return n
}
func (m *TLSProperties_CertificateProperties_SubjectAltName_Dns) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Dns)
	n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	return n
}
func (m *TLSProperties_CertificateProperties) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.SubjectAltName) > 0 {
		for _, e := range m.SubjectAltName {
			l = e.SizeVT()
			n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
		}
	}
	l = len(m.Subject)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *TLSProperties) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.TlsVersion != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.TlsVersion))
	}
	if m.TlsCipherSuite != nil {
		l = (*wrapperspb.UInt32Value)(m.TlsCipherSuite).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.TlsSniHostname)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.LocalCertificateProperties != nil {
		l = m.LocalCertificateProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.PeerCertificateProperties != nil {
		l = m.PeerCertificateProperties.SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.TlsSessionId)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}

func (m *HTTPRequestProperties) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.RequestMethod != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.RequestMethod))
	}
	l = len(m.Scheme)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.Authority)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.Port != nil {
		l = (*wrapperspb.UInt32Value)(m.Port).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.Path)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.UserAgent)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.Referer)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.ForwardedFor)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.RequestId)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	l = len(m.OriginalPath)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.RequestHeadersBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.RequestHeadersBytes))
	}
	if m.RequestBodyBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.RequestBodyBytes))
	}
	if len(m.RequestHeaders) > 0 {
		for k, v := range m.RequestHeaders {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + protohelpers.SizeOfVarint(uint64(len(k))) + 1 + len(v) + protohelpers.SizeOfVarint(uint64(len(v)))
			n += mapEntrySize + 1 + protohelpers.SizeOfVarint(uint64(mapEntrySize))
		}
	}
	n += len(m.unknownFields)
	return n
}

func (m *HTTPResponseProperties) SizeVT() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ResponseCode != nil {
		l = (*wrapperspb.UInt32Value)(m.ResponseCode).SizeVT()
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	if m.ResponseHeadersBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.ResponseHeadersBytes))
	}
	if m.ResponseBodyBytes != 0 {
		n += 1 + protohelpers.SizeOfVarint(uint64(m.ResponseBodyBytes))
	}
	if len(m.ResponseHeaders) > 0 {
		for k, v := range m.ResponseHeaders {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + protohelpers.SizeOfVarint(uint64(len(k))) + 1 + len(v) + protohelpers.SizeOfVarint(uint64(len(v)))
			n += mapEntrySize + 1 + protohelpers.SizeOfVarint(uint64(mapEntrySize))
		}
	}
	if len(m.ResponseTrailers) > 0 {
		for k, v := range m.ResponseTrailers {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + protohelpers.SizeOfVarint(uint64(len(k))) + 1 + len(v) + protohelpers.SizeOfVarint(uint64(len(v)))
			n += mapEntrySize + 1 + protohelpers.SizeOfVarint(uint64(mapEntrySize))
		}
	}
	l = len(m.ResponseCodeDetails)
	if l > 0 {
		n += 1 + l + protohelpers.SizeOfVarint(uint64(l))
	}
	n += len(m.unknownFields)
	return n
}
