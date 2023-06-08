package integration

import (
	"context"
	"gitee.com/zhaochuninhefei/gmgo/grpc/credentials/insecure"
	"net"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"github.com/stretchr/testify/assert"

	envoyconfigcorev3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/core/v3"
	envoyconfigendpointv3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/endpoint/v3"
	envoyservicediscoveryv3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/discovery/v3"
	endpointservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/endpoint/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/types"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/resource/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/server/v3"
)

type logger struct {
	t *testing.T
}

func (log logger) Debugf(format string, args ...interface{}) { log.t.Logf(format, args...) }
func (log logger) Infof(format string, args ...interface{})  { log.t.Logf(format, args...) }
func (log logger) Warnf(format string, args ...interface{})  { log.t.Logf(format, args...) }
func (log logger) Errorf(format string, args ...interface{}) { log.t.Logf(format, args...) }

func TestTTLResponse(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snapshotCache := cache.NewSnapshotCacheWithHeartbeating(ctx, false, cache.IDHash{}, logger{t: t}, time.Second)

	ttlServer := server.NewServer(ctx, snapshotCache, nil)

	grpcServer := grpc.NewServer()
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, ttlServer)

	l, err := net.Listen("tcp", ":9999") // nolint:gosec
	assert.NoError(t, err)

	go func() {
		assert.NoError(t, grpcServer.Serve(l))
	}()
	defer grpcServer.Stop()

	// grpc.WithInsecure() is deprecated, use WithTransportCredentials and insecure.NewCredentials() instead.
	//conn, err := grpc.Dial(":9999", grpc.WithInsecure())
	conn, err := grpc.Dial(":9999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)
	client := endpointservice.NewEndpointDiscoveryServiceClient(conn)

	sclient, err := client.StreamEndpoints(ctx)
	assert.NoError(t, err)

	err = sclient.Send(&envoyservicediscoveryv3.DiscoveryRequest{
		Node: &envoyconfigcorev3.Node{
			Id: "test",
		},
		ResourceNames: []string{"resource"},
		TypeUrl:       resource.EndpointType,
	})
	assert.NoError(t, err)

	oneSecond := time.Second
	cla := &envoyconfigendpointv3.ClusterLoadAssignment{ClusterName: "resource"}
	snap, _ := cache.NewSnapshotWithTTLs("1", map[resource.Type][]types.ResourceWithTTL{
		resource.EndpointType: {{
			Resource: cla,
			TTL:      &oneSecond,
		}},
	})
	err = snapshotCache.SetSnapshot(context.Background(), "test", snap)
	assert.NoError(t, err)

	timeout := time.NewTimer(5 * time.Second)

	awaitResponse := func() *envoyservicediscoveryv3.DiscoveryResponse {
		t.Helper()
		doneCh := make(chan *envoyservicediscoveryv3.DiscoveryResponse)
		go func() {

			r, err := sclient.Recv()
			assert.NoError(t, err)

			doneCh <- r
		}()

		select {
		case <-timeout.C:
			assert.Fail(t, "timed out")
			return nil
		case r := <-doneCh:
			return r
		}
	}

	response := awaitResponse()
	isFullResponseWithTTL(t, response)

	err = sclient.Send(&envoyservicediscoveryv3.DiscoveryRequest{
		Node: &envoyconfigcorev3.Node{
			Id: "test",
		},
		ResourceNames: []string{"resource"},
		TypeUrl:       resource.EndpointType,
		VersionInfo:   "1",
		ResponseNonce: response.Nonce,
	})
	assert.NoError(t, err)

	response = awaitResponse()
	isHeartbeatResponseWithTTL(t, response)
}

func isFullResponseWithTTL(t *testing.T, response *envoyservicediscoveryv3.DiscoveryResponse) {
	t.Helper()

	assert.Len(t, response.Resources, 1)
	r := response.Resources[0]
	res := &envoyservicediscoveryv3.Resource{}
	// ptypes.UnmarshalAny is deprecated, Call the any.UnmarshalTo method instead.
	//err := ptypes.UnmarshalAny(r, res)
	err := r.UnmarshalTo(res)

	assert.NoError(t, err)

	assert.NotNil(t, res.Ttl)
	assert.NotNil(t, res.Resource)
}

func isHeartbeatResponseWithTTL(t *testing.T, response *envoyservicediscoveryv3.DiscoveryResponse) {
	t.Helper()

	assert.Len(t, response.Resources, 1)
	r := response.Resources[0]
	res := &envoyservicediscoveryv3.Resource{}
	// ptypes.UnmarshalAny is deprecated, Call the any.UnmarshalTo method instead.
	//err := ptypes.UnmarshalAny(r, res)
	err := r.UnmarshalTo(res)
	assert.NoError(t, err)

	assert.NotNil(t, res.Ttl)
	assert.Nil(t, res.Resource)
}
