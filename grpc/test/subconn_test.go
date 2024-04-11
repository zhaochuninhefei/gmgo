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

package test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer"
	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer/base"
	"gitee.com/zhaochuninhefei/gmgo/grpc/connectivity"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/balancer/stub"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/stubserver"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/testutils"
	testpb "gitee.com/zhaochuninhefei/gmgo/grpc/interop/grpc_testing"
	"gitee.com/zhaochuninhefei/gmgo/grpc/resolver"
)

type tsccPicker struct {
	sc balancer.SubConn
}

func (p *tsccPicker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	return balancer.PickResult{SubConn: p.sc}, nil
}

// TestSubConnEmpty tests that removing all addresses from a SubConn and then
// re-adding them does not cause a panic and properly reconnects.
func (s) TestSubConnEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	// sc is the one SubConn used throughout the test.  Created on demand and
	// re-used on every update.
	var sc balancer.SubConn

	// Simple custom balancer that sets the address list to empty if the
	// resolver produces no addresses.  Pickfirst, by default, will remove the
	// SubConn in this case instead.
	bal := stub.BalancerFuncs{
		UpdateClientConnState: func(d *stub.BalancerData, ccs balancer.ClientConnState) error {
			if sc == nil {
				var err error
				sc, err = d.ClientConn.NewSubConn(ccs.ResolverState.Addresses, balancer.NewSubConnOptions{
					StateListener: func(state balancer.SubConnState) {
						switch state.ConnectivityState {
						case connectivity.Ready:
							d.ClientConn.UpdateState(balancer.State{
								ConnectivityState: connectivity.Ready,
								Picker:            &tsccPicker{sc: sc},
							})
						case connectivity.TransientFailure:
							d.ClientConn.UpdateState(balancer.State{
								ConnectivityState: connectivity.TransientFailure,
								Picker:            base.NewErrPicker(fmt.Errorf("error connecting: %v", state.ConnectionError)),
							})
						}
					},
				})
				if err != nil {
					t.Errorf("error creating initial subconn: %v", err)
				}
			} else {
				d.ClientConn.UpdateAddresses(sc, ccs.ResolverState.Addresses)
			}
			sc.Connect()

			if len(ccs.ResolverState.Addresses) == 0 {
				d.ClientConn.UpdateState(balancer.State{
					ConnectivityState: connectivity.TransientFailure,
					Picker:            base.NewErrPicker(errors.New("no addresses")),
				})
			} else {
				d.ClientConn.UpdateState(balancer.State{
					ConnectivityState: connectivity.Connecting,
					Picker:            &tsccPicker{sc: sc},
				})
			}
			return nil
		},
	}
	stub.Register("tscc", bal)

	// Start the stub server with our stub balancer.
	ss := &stubserver.StubServer{
		EmptyCallF: func(ctx context.Context, in *testpb.Empty) (*testpb.Empty, error) {
			return &testpb.Empty{}, nil
		},
	}
	if err := ss.Start(nil, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"tscc":{}}]}`)); err != nil {
		t.Fatalf("Error starting server: %v", err)
	}
	defer ss.Stop()
	if _, err := ss.Client.EmptyCall(ctx, &testpb.Empty{}); err != nil {
		t.Fatalf("EmptyCall failed: %v", err)
	}

	t.Log("Removing addresses from resolver and SubConn")
	ss.R.UpdateState(resolver.State{Addresses: []resolver.Address{}})
	testutils.AwaitState(ctx, t, ss.CC, connectivity.TransientFailure)

	t.Log("Re-adding addresses to resolver and SubConn")
	ss.R.UpdateState(resolver.State{Addresses: []resolver.Address{{Addr: ss.Address}}})
	if _, err := ss.Client.EmptyCall(ctx, &testpb.Empty{}); err != nil {
		t.Fatalf("EmptyCall failed: %v", err)
	}
}
