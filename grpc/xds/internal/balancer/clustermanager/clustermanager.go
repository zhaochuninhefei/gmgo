/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package clustermanager implements the cluster manager LB policy for xds.
package clustermanager

import (
	"encoding/json"
	"fmt"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer"
	"gitee.com/zhaochuninhefei/gmgo/grpc/grpclog"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/balancergroup"
	internalgrpclog "gitee.com/zhaochuninhefei/gmgo/grpc/internal/grpclog"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/hierarchy"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/pretty"
	"gitee.com/zhaochuninhefei/gmgo/grpc/resolver"
	"gitee.com/zhaochuninhefei/gmgo/grpc/serviceconfig"
)

const balancerName = "xds_cluster_manager_experimental"

func init() {
	balancer.Register(bb{})
}

type bb struct{}

func (bb) Build(cc balancer.ClientConn, opts balancer.BuildOptions) balancer.Balancer {
	b := &bal{}
	b.logger = prefixLogger(b)
	b.stateAggregator = newBalancerStateAggregator(cc, b.logger)
	b.stateAggregator.start()
	b.bg = balancergroup.New(balancergroup.Options{
		CC:                      cc,
		BuildOpts:               opts,
		StateAggregator:         b.stateAggregator,
		Logger:                  b.logger,
		SubBalancerCloseTimeout: time.Duration(0), // Disable caching of removed child policies
	})
	b.bg.Start()
	b.logger.Infof("Created")
	return b
}

func (bb) Name() string {
	return balancerName
}

func (bb) ParseConfig(c json.RawMessage) (serviceconfig.LoadBalancingConfig, error) {
	return parseConfig(c)
}

type bal struct {
	logger *internalgrpclog.PrefixLogger

	// TODO: make this package not dependent on xds specific code. Same as for
	// weighted target balancer.
	bg              *balancergroup.BalancerGroup
	stateAggregator *balancerStateAggregator

	children map[string]childConfig
}

func (b *bal) updateChildren(s balancer.ClientConnState, newConfig *lbConfig) {
	update := false
	addressesSplit := hierarchy.Group(s.ResolverState.Addresses)

	// Remove sub-pickers and sub-balancers that are not in the new cluster list.
	for name := range b.children {
		if _, ok := newConfig.Children[name]; !ok {
			b.stateAggregator.remove(name)
			b.bg.Remove(name)
			update = true
		}
	}

	// For sub-balancers in the new cluster list,
	// - add to balancer group if it's new,
	// - forward the address/balancer config update.
	for name, newT := range newConfig.Children {
		if _, ok := b.children[name]; !ok {
			// If this is a new sub-balancer, add it to the picker map.
			b.stateAggregator.add(name)
			// Then add to the balancer group.
			b.bg.Add(name, balancer.Get(newT.ChildPolicy.Name))
		} else {
			// Already present, check for type change and if so send down a new builder.
			if newT.ChildPolicy.Name != b.children[name].ChildPolicy.Name {
				b.bg.UpdateBuilder(name, balancer.Get(newT.ChildPolicy.Name))
			}
		}
		// TODO: handle error? How to aggregate errors and return?
		_ = b.bg.UpdateClientConnState(name, balancer.ClientConnState{
			ResolverState: resolver.State{
				Addresses:     addressesSplit[name],
				ServiceConfig: s.ResolverState.ServiceConfig,
				Attributes:    s.ResolverState.Attributes,
			},
			BalancerConfig: newT.ChildPolicy.Config,
		})
	}

	b.children = newConfig.Children
	if update {
		b.stateAggregator.buildAndUpdate()
	}
}

func (b *bal) UpdateClientConnState(s balancer.ClientConnState) error {
	newConfig, ok := s.BalancerConfig.(*lbConfig)
	if !ok {
		return fmt.Errorf("unexpected balancer config with type: %T", s.BalancerConfig)
	}
	b.logger.Infof("update with config %+v, resolver state %+v", pretty.ToJSON(s.BalancerConfig), s.ResolverState)

	b.stateAggregator.pauseStateUpdates()
	defer b.stateAggregator.resumeStateUpdates()
	b.updateChildren(s, newConfig)
	return nil
}

func (b *bal) ResolverError(err error) {
	b.bg.ResolverError(err)
}

func (b *bal) UpdateSubConnState(sc balancer.SubConn, state balancer.SubConnState) {
	b.logger.Errorf("UpdateSubConnState(%v, %+v) called unexpectedly", sc, state)
}

func (b *bal) Close() {
	b.stateAggregator.close()
	b.bg.Close()
	b.logger.Infof("Shutdown")
}

func (b *bal) ExitIdle() {
	b.bg.ExitIdle()
}

const prefix = "[xds-cluster-manager-lb %p] "

var logger = grpclog.Component("xds")

func prefixLogger(p *bal) *internalgrpclog.PrefixLogger {
	return internalgrpclog.NewPrefixLogger(logger, fmt.Sprintf(prefix, p))
}
