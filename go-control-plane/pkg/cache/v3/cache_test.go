package cache_test

import (
	"google.golang.org/protobuf/types/known/anypb"
	"testing"

	"github.com/golang/protobuf/ptypes/any"
	"github.com/stretchr/testify/assert"

	route "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/route/v3"
	discovery "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/discovery/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/types"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/resource/v3"
)

const (
	resourceName = "route1"
)

func TestResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.ResourceWithTTL{{Resource: &route.RouteConfiguration{Name: resourceName}}}
	resp := cache.RawResponse{
		Request:   &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		Version:   "v",
		Resources: routes,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.Version)
	assert.Equal(t, len(discoveryResponse.Resources), 1)

	cachedResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Same(t, discoveryResponse, cachedResponse)

	r := &route.RouteConfiguration{}
	//err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	err = discoveryResponse.Resources[0].UnmarshalTo(r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
}

func TestPassthroughResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.Resource{&route.RouteConfiguration{Name: resourceName}}
	//rsrc, err := ptypes.MarshalAny(routes[0])
	rsrc, err := anypb.New(routes[0].(*route.RouteConfiguration))

	dr := &discovery.DiscoveryResponse{
		TypeUrl:     resource.RouteType,
		Resources:   []*any.Any{rsrc},
		VersionInfo: "v",
	}
	resp := cache.PassthroughResponse{
		Request:           &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		DiscoveryResponse: dr,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.DiscoveryResponse.VersionInfo)
	assert.Equal(t, len(discoveryResponse.Resources), 1)

	r := &route.RouteConfiguration{}
	//err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	err = discoveryResponse.Resources[0].UnmarshalTo(r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
	assert.Equal(t, discoveryResponse, dr)
}

func TestHeartbeatResponseGetDiscoveryResponse(t *testing.T) {
	routes := []types.ResourceWithTTL{{Resource: &route.RouteConfiguration{Name: resourceName}}}
	resp := cache.RawResponse{
		Request:   &discovery.DiscoveryRequest{TypeUrl: resource.RouteType},
		Version:   "v",
		Resources: routes,
		Heartbeat: true,
	}

	discoveryResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Equal(t, discoveryResponse.VersionInfo, resp.Version)
	assert.Equal(t, len(discoveryResponse.Resources), 1)
	assert.False(t, isTTLResource(discoveryResponse.Resources[0]))

	cachedResponse, err := resp.GetDiscoveryResponse()
	assert.Nil(t, err)
	assert.Same(t, discoveryResponse, cachedResponse)

	r := &route.RouteConfiguration{}
	//err = ptypes.UnmarshalAny(discoveryResponse.Resources[0], r)
	err = discoveryResponse.Resources[0].UnmarshalTo(r)
	assert.Nil(t, err)
	assert.Equal(t, r.Name, resourceName)
}

func isTTLResource(resource *any.Any) bool {
	wrappedResource := &discovery.Resource{}
	//err := ptypes.UnmarshalAny(resource, wrappedResource)
	err := resource.UnmarshalTo(wrappedResource)
	if err != nil {
		return false
	}

	return wrappedResource.Resource == nil
}
