/*
 *
 * Copyright 2023 gRPC authors.
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

package clusterresolver

import (
	"sync"

	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/grpclog"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/grpcsync"
	"gitee.com/zhaochuninhefei/gmgo/grpc/xds/internal/xdsclient/xdsresource"
)

type edsDiscoveryMechanism struct {
	nameToWatch      string
	cancelWatch      func()
	topLevelResolver topLevelResolver
	stopped          *grpcsync.Event
	logger           *grpclog.PrefixLogger

	mu     sync.Mutex
	update *xdsresource.EndpointsUpdate // Nil indicates no update received so far.
}

func (er *edsDiscoveryMechanism) lastUpdate() (any, bool) {
	er.mu.Lock()
	defer er.mu.Unlock()

	if er.update == nil {
		return nil, false
	}
	return *er.update, true
}

func (er *edsDiscoveryMechanism) resolveNow() {
}

// The definition of stop() mentions that implementations must not invoke any
// methods on the topLevelResolver once the call to `stop()` returns.
func (er *edsDiscoveryMechanism) stop() {
	// Canceling a watch with the xDS client can race with an xDS response
	// received around the same time, and can result in the watch callback being
	// invoked after the watch is canceled. Callers need to handle this race,
	// and we fire the stopped event here to ensure that a watch callback
	// invocation around the same time becomes a no-op.
	er.stopped.Fire()
	er.cancelWatch()
}

// newEDSResolver returns an implementation of the endpointsResolver interface
// that uses EDS to resolve the given name to endpoints.
func newEDSResolver(nameToWatch string, producer xdsresource.Producer, topLevelResolver topLevelResolver, logger *grpclog.PrefixLogger) *edsDiscoveryMechanism {
	ret := &edsDiscoveryMechanism{
		nameToWatch:      nameToWatch,
		topLevelResolver: topLevelResolver,
		logger:           logger,
		stopped:          grpcsync.NewEvent(),
	}
	ret.cancelWatch = xdsresource.WatchEndpoints(producer, nameToWatch, ret)
	return ret
}

// OnUpdate is invoked to report an update for the resource being watched.
func (er *edsDiscoveryMechanism) OnUpdate(update *xdsresource.EndpointsResourceData) {
	if er.stopped.HasFired() {
		return
	}

	er.mu.Lock()
	er.update = &update.Resource
	er.mu.Unlock()

	er.topLevelResolver.onUpdate()
}

func (er *edsDiscoveryMechanism) OnError(err error) {
	if er.stopped.HasFired() {
		return
	}

	if er.logger.V(2) {
		er.logger.Infof("EDS discovery mechanism for resource %q reported error: %v", er.nameToWatch, err)
	}

	er.mu.Lock()
	if er.update != nil {
		// Continue using a previously received good configuration if one
		// exists.
		er.mu.Unlock()
		return
	}

	// Else report an empty update that would result in no priority child being
	// created for this discovery mechanism. This would result in the priority
	// LB policy reporting TRANSIENT_FAILURE (as there would be no priorities or
	// localities) if this was the only discovery mechanism, or would result in
	// the priority LB policy using a lower priority discovery mechanism when
	// that becomes available.
	er.update = &xdsresource.EndpointsUpdate{}
	er.mu.Unlock()

	er.topLevelResolver.onUpdate()
}

func (er *edsDiscoveryMechanism) OnResourceDoesNotExist() {
	if er.stopped.HasFired() {
		return
	}

	if er.logger.V(2) {
		er.logger.Infof("EDS discovery mechanism for resource %q reported resource-does-not-exist error", er.nameToWatch)
	}

	// Report an empty update that would result in no priority child being
	// created for this discovery mechanism. This would result in the priority
	// LB policy reporting TRANSIENT_FAILURE (as there would be no priorities or
	// localities) if this was the only discovery mechanism, or would result in
	// the priority LB policy using a lower priority discovery mechanism when
	// that becomes available.
	er.mu.Lock()
	er.update = &xdsresource.EndpointsUpdate{}
	er.mu.Unlock()

	er.topLevelResolver.onUpdate()
}
