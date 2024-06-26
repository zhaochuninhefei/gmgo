// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package test contains test utilities
package test

import (
	"gitee.com/zhaochuninhefei/gmgo/grpc"

	accessloggrpc "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/accesslog/v3"
	clusterservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/discovery/v3"
	endpointservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/listener/v3"
	routeservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/route/v3"
	runtimeservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/runtime/v3"
	secretservice "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/service/secret/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/server/v3"
)

// RegisterAccessLogServer starts an accessloggrpc service.
func RegisterAccessLogServer(grpcServer *grpc.Server, als *AccessLogService) {
	accessloggrpc.RegisterAccessLogServiceServer(grpcServer, als)
}

// RegisterServer registers with v3 services.
func RegisterServer(grpcServer *grpc.Server, server server.Server) {
	// register services
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, server)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, server)
	routeservice.RegisterScopedRoutesDiscoveryServiceServer(grpcServer, server)
	routeservice.RegisterVirtualHostDiscoveryServiceServer(grpcServer, server)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, server)
	secretservice.RegisterSecretDiscoveryServiceServer(grpcServer, server)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(grpcServer, server)
}
