/*
 * Copyright 2019 gRPC authors.
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
 */

package balancergroup

import (
	"fmt"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer"
	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer/roundrobin"
	"gitee.com/zhaochuninhefei/gmgo/grpc/balancer/weightedtarget/weightedaggregator"
	"gitee.com/zhaochuninhefei/gmgo/grpc/connectivity"
	"gitee.com/zhaochuninhefei/gmgo/grpc/credentials/insecure"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/balancer/stub"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/grpctest"
	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/testutils"
	"gitee.com/zhaochuninhefei/gmgo/grpc/resolver"
	"github.com/google/go-cmp/cmp"
)

var (
	rrBuilder        = balancer.Get(roundrobin.Name)
	testBalancerIDs  = []string{"b1", "b2", "b3"}
	testBackendAddrs []resolver.Address
)

const testBackendAddrsCount = 12

func init() {
	for i := 0; i < testBackendAddrsCount; i++ {
		testBackendAddrs = append(testBackendAddrs, resolver.Address{Addr: fmt.Sprintf("%d.%d.%d.%d:%d", i, i, i, i, i)})
	}

	// Disable caching for all tests. It will be re-enabled in caching specific
	// tests.
	DefaultSubBalancerCloseTimeout = time.Millisecond
}

type s struct {
	grpctest.Tester
}

func Test(t *testing.T) {
	grpctest.RunSubTests(t, s{})
}

func subConnFromPicker(p balancer.Picker) func() balancer.SubConn {
	return func() balancer.SubConn {
		scst, _ := p.Pick(balancer.PickInfo{})
		return scst.SubConn
	}
}

// Create a new balancer group, add balancer and backends, but not start.
// - b1, weight 2, backends [0,1]
// - b2, weight 1, backends [2,3]
// Start the balancer group and check behavior.
//
// Close the balancer group, call add/remove/change weight/change address.
// - b2, weight 3, backends [0,3]
// - b3, weight 1, backends [1,2]
// Start the balancer group again and check for behavior.
func (s) TestBalancerGroup_start_close(t *testing.T) {
	cc := testutils.NewTestClientConn(t)
	gator := weightedaggregator.New(cc, nil, testutils.NewTestWRR)
	gator.Start()
	bg := New(cc, balancer.BuildOptions{}, gator, nil)

	// Add two balancers to group and send two resolved addresses to both
	// balancers.
	gator.Add(testBalancerIDs[0], 2)
	bg.Add(testBalancerIDs[0], rrBuilder)
	_ = bg.UpdateClientConnState(testBalancerIDs[0], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[0:2]}})
	gator.Add(testBalancerIDs[1], 1)
	bg.Add(testBalancerIDs[1], rrBuilder)
	_ = bg.UpdateClientConnState(testBalancerIDs[1], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[2:4]}})

	bg.Start()

	m1 := make(map[resolver.Address]balancer.SubConn)
	for i := 0; i < 4; i++ {
		addrs := <-cc.NewSubConnAddrsCh
		sc := <-cc.NewSubConnCh
		m1[addrs[0]] = sc
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Connecting})
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Ready})
	}

	// Test roundrobin on the last picker.
	p1 := <-cc.NewPickerCh
	want := []balancer.SubConn{
		m1[testBackendAddrs[0]], m1[testBackendAddrs[0]],
		m1[testBackendAddrs[1]], m1[testBackendAddrs[1]],
		m1[testBackendAddrs[2]], m1[testBackendAddrs[3]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p1)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}

	gator.Stop()
	bg.Close()
	for i := 0; i < 4; i++ {
		bg.UpdateSubConnState(<-cc.RemoveSubConnCh, balancer.SubConnState{ConnectivityState: connectivity.Shutdown})
	}

	// Add b3, weight 1, backends [1,2].
	gator.Add(testBalancerIDs[2], 1)
	bg.Add(testBalancerIDs[2], rrBuilder)
	_ = bg.UpdateClientConnState(testBalancerIDs[2], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[1:3]}})

	// Remove b1.
	gator.Remove(testBalancerIDs[0])
	bg.Remove(testBalancerIDs[0])

	// Update b2 to weight 3, backends [0,3].
	gator.UpdateWeight(testBalancerIDs[1], 3)
	_ = bg.UpdateClientConnState(testBalancerIDs[1], balancer.ClientConnState{ResolverState: resolver.State{Addresses: append([]resolver.Address(nil), testBackendAddrs[0], testBackendAddrs[3])}})

	gator.Start()
	bg.Start()

	m2 := make(map[resolver.Address]balancer.SubConn)
	for i := 0; i < 4; i++ {
		addrs := <-cc.NewSubConnAddrsCh
		sc := <-cc.NewSubConnCh
		m2[addrs[0]] = sc
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Connecting})
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Ready})
	}

	// Test roundrobin on the last picker.
	p2 := <-cc.NewPickerCh
	want = []balancer.SubConn{
		m2[testBackendAddrs[0]], m2[testBackendAddrs[0]], m2[testBackendAddrs[0]],
		m2[testBackendAddrs[3]], m2[testBackendAddrs[3]], m2[testBackendAddrs[3]],
		m2[testBackendAddrs[1]], m2[testBackendAddrs[2]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p2)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}
}

// Test that balancer group start() doesn't deadlock if the balancer calls back
// into balancer group inline when it gets an update.
//
// The potential deadlock can happen if we
//  - hold a lock and send updates to balancer (e.g. update resolved addresses)
//  - the balancer calls back (NewSubConn or update picker) in line
// The callback will try to hold hte same lock again, which will cause a
// deadlock.
//
// This test starts the balancer group with a test balancer, will updates picker
// whenever it gets an address update. It's expected that start() doesn't block
// because of deadlock.
func (s) TestBalancerGroup_start_close_deadlock(t *testing.T) {
	const balancerName = "stub-TestBalancerGroup_start_close_deadlock"
	stub.Register(balancerName, stub.BalancerFuncs{})
	builder := balancer.Get(balancerName)

	cc := testutils.NewTestClientConn(t)
	gator := weightedaggregator.New(cc, nil, testutils.NewTestWRR)
	gator.Start()
	bg := New(cc, balancer.BuildOptions{}, gator, nil)

	gator.Add(testBalancerIDs[0], 2)
	bg.Add(testBalancerIDs[0], builder)
	_ = bg.UpdateClientConnState(testBalancerIDs[0], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[0:2]}})
	gator.Add(testBalancerIDs[1], 1)
	bg.Add(testBalancerIDs[1], builder)
	_ = bg.UpdateClientConnState(testBalancerIDs[1], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[2:4]}})

	bg.Start()
}

func replaceDefaultSubBalancerCloseTimeout(n time.Duration) func() {
	old := DefaultSubBalancerCloseTimeout
	DefaultSubBalancerCloseTimeout = n
	return func() { DefaultSubBalancerCloseTimeout = old }
}

// initBalancerGroupForCachingTest creates a balancer group, and initialize it
// to be ready for caching tests.
//
// Two rr balancers are added to bg, each with 2 ready subConns. A sub-balancer
// is removed later, so the balancer group returned has one sub-balancer in its
// own map, and one sub-balancer in cache.
func initBalancerGroupForCachingTest(t *testing.T) (*weightedaggregator.Aggregator, *BalancerGroup, *testutils.TestClientConn, map[resolver.Address]balancer.SubConn) {
	cc := testutils.NewTestClientConn(t)
	gator := weightedaggregator.New(cc, nil, testutils.NewTestWRR)
	gator.Start()
	bg := New(cc, balancer.BuildOptions{}, gator, nil)

	// Add two balancers to group and send two resolved addresses to both
	// balancers.
	gator.Add(testBalancerIDs[0], 2)
	bg.Add(testBalancerIDs[0], rrBuilder)
	_ = bg.UpdateClientConnState(testBalancerIDs[0], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[0:2]}})
	gator.Add(testBalancerIDs[1], 1)
	bg.Add(testBalancerIDs[1], rrBuilder)
	_ = bg.UpdateClientConnState(testBalancerIDs[1], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[2:4]}})

	bg.Start()

	m1 := make(map[resolver.Address]balancer.SubConn)
	for i := 0; i < 4; i++ {
		addrs := <-cc.NewSubConnAddrsCh
		sc := <-cc.NewSubConnCh
		m1[addrs[0]] = sc
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Connecting})
		bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Ready})
	}

	// Test roundrobin on the last picker.
	p1 := <-cc.NewPickerCh
	want := []balancer.SubConn{
		m1[testBackendAddrs[0]], m1[testBackendAddrs[0]],
		m1[testBackendAddrs[1]], m1[testBackendAddrs[1]],
		m1[testBackendAddrs[2]], m1[testBackendAddrs[3]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p1)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}

	gator.Remove(testBalancerIDs[1])
	bg.Remove(testBalancerIDs[1])
	gator.BuildAndUpdate()
	// Don't wait for SubConns to be removed after close, because they are only
	// removed after close timeout.
	for i := 0; i < 10; i++ {
		select {
		case <-cc.RemoveSubConnCh:
			t.Fatalf("Got request to remove subconn, want no remove subconn (because subconns were still in cache)")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	// Test roundrobin on the with only sub-balancer0.
	p2 := <-cc.NewPickerCh
	want = []balancer.SubConn{
		m1[testBackendAddrs[0]], m1[testBackendAddrs[1]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p2)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}

	return gator, bg, cc, m1
}

// Test that if a sub-balancer is removed, and re-added within close timeout,
// the subConns won't be re-created.
func (s) TestBalancerGroup_locality_caching(t *testing.T) {
	defer replaceDefaultSubBalancerCloseTimeout(10 * time.Second)()
	gator, bg, cc, addrToSC := initBalancerGroupForCachingTest(t)

	// Turn down subconn for addr2, shouldn't get picker update because
	// sub-balancer1 was removed.
	bg.UpdateSubConnState(addrToSC[testBackendAddrs[2]], balancer.SubConnState{ConnectivityState: connectivity.TransientFailure})
	for i := 0; i < 10; i++ {
		select {
		case <-cc.NewPickerCh:
			t.Fatalf("Got new picker, want no new picker (because the sub-balancer was removed)")
		default:
		}
		time.Sleep(time.Millisecond)
	}

	// Sleep, but sleep less then close timeout.
	time.Sleep(time.Millisecond * 100)

	// Re-add sub-balancer-1, because subconns were in cache, no new subconns
	// should be created. But a new picker will still be generated, with subconn
	// states update to date.
	gator.Add(testBalancerIDs[1], 1)
	bg.Add(testBalancerIDs[1], rrBuilder)

	p3 := <-cc.NewPickerCh
	want := []balancer.SubConn{
		addrToSC[testBackendAddrs[0]], addrToSC[testBackendAddrs[0]],
		addrToSC[testBackendAddrs[1]], addrToSC[testBackendAddrs[1]],
		// addr2 is down, b2 only has addr3 in READY state.
		addrToSC[testBackendAddrs[3]], addrToSC[testBackendAddrs[3]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p3)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}

	for i := 0; i < 10; i++ {
		select {
		case <-cc.NewSubConnAddrsCh:
			t.Fatalf("Got new subconn, want no new subconn (because subconns were still in cache)")
		default:
		}
		time.Sleep(time.Millisecond * 10)
	}
}

// Sub-balancers are put in cache when they are removed. If balancer group is
// closed within close timeout, all subconns should still be rmeoved
// immediately.
func (s) TestBalancerGroup_locality_caching_close_group(t *testing.T) {
	defer replaceDefaultSubBalancerCloseTimeout(10 * time.Second)()
	_, bg, cc, addrToSC := initBalancerGroupForCachingTest(t)

	bg.Close()
	// The balancer group is closed. The subconns should be removed immediately.
	removeTimeout := time.After(time.Millisecond * 500)
	scToRemove := map[balancer.SubConn]int{
		addrToSC[testBackendAddrs[0]]: 1,
		addrToSC[testBackendAddrs[1]]: 1,
		addrToSC[testBackendAddrs[2]]: 1,
		addrToSC[testBackendAddrs[3]]: 1,
	}
	for i := 0; i < len(scToRemove); i++ {
		select {
		case sc := <-cc.RemoveSubConnCh:
			c := scToRemove[sc]
			if c == 0 {
				t.Fatalf("Got removeSubConn for %v when there's %d remove expected", sc, c)
			}
			scToRemove[sc] = c - 1
		case <-removeTimeout:
			t.Fatalf("timeout waiting for subConns (from balancer in cache) to be removed")
		}
	}
}

// Sub-balancers in cache will be closed if not re-added within timeout, and
// subConns will be removed.
func (s) TestBalancerGroup_locality_caching_not_readd_within_timeout(t *testing.T) {
	defer replaceDefaultSubBalancerCloseTimeout(time.Second)()
	_, _, cc, addrToSC := initBalancerGroupForCachingTest(t)

	// The sub-balancer is not re-added within timeout. The subconns should be
	// removed.
	removeTimeout := time.After(DefaultSubBalancerCloseTimeout)
	scToRemove := map[balancer.SubConn]int{
		addrToSC[testBackendAddrs[2]]: 1,
		addrToSC[testBackendAddrs[3]]: 1,
	}
	for i := 0; i < len(scToRemove); i++ {
		select {
		case sc := <-cc.RemoveSubConnCh:
			c := scToRemove[sc]
			if c == 0 {
				t.Fatalf("Got removeSubConn for %v when there's %d remove expected", sc, c)
			}
			scToRemove[sc] = c - 1
		case <-removeTimeout:
			t.Fatalf("timeout waiting for subConns (from balancer in cache) to be removed")
		}
	}
}

// Wrap the rr builder, so it behaves the same, but has a different pointer.
type noopBalancerBuilderWrapper struct {
	balancer.Builder
}

// After removing a sub-balancer, re-add with same ID, but different balancer
// builder. Old subconns should be removed, and new subconns should be created.
func (s) TestBalancerGroup_locality_caching_readd_with_different_builder(t *testing.T) {
	defer replaceDefaultSubBalancerCloseTimeout(10 * time.Second)()
	gator, bg, cc, addrToSC := initBalancerGroupForCachingTest(t)

	// Re-add sub-balancer-1, but with a different balancer builder. The
	// sub-balancer was still in cache, but cann't be reused. This should cause
	// old sub-balancer's subconns to be removed immediately, and new subconns
	// to be created.
	gator.Add(testBalancerIDs[1], 1)
	bg.Add(testBalancerIDs[1], &noopBalancerBuilderWrapper{rrBuilder})

	// The cached sub-balancer should be closed, and the subconns should be
	// removed immediately.
	removeTimeout := time.After(time.Millisecond * 500)
	scToRemove := map[balancer.SubConn]int{
		addrToSC[testBackendAddrs[2]]: 1,
		addrToSC[testBackendAddrs[3]]: 1,
	}
	for i := 0; i < len(scToRemove); i++ {
		select {
		case sc := <-cc.RemoveSubConnCh:
			c := scToRemove[sc]
			if c == 0 {
				t.Fatalf("Got removeSubConn for %v when there's %d remove expected", sc, c)
			}
			scToRemove[sc] = c - 1
		case <-removeTimeout:
			t.Fatalf("timeout waiting for subConns (from balancer in cache) to be removed")
		}
	}

	_ = bg.UpdateClientConnState(testBalancerIDs[1], balancer.ClientConnState{ResolverState: resolver.State{Addresses: testBackendAddrs[4:6]}})

	newSCTimeout := time.After(time.Millisecond * 500)
	scToAdd := map[resolver.Address]int{
		testBackendAddrs[4]: 1,
		testBackendAddrs[5]: 1,
	}
	for i := 0; i < len(scToAdd); i++ {
		select {
		case addr := <-cc.NewSubConnAddrsCh:
			c := scToAdd[addr[0]]
			if c == 0 {
				t.Fatalf("Got newSubConn for %v when there's %d new expected", addr, c)
			}
			scToAdd[addr[0]] = c - 1
			sc := <-cc.NewSubConnCh
			addrToSC[addr[0]] = sc
			bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Connecting})
			bg.UpdateSubConnState(sc, balancer.SubConnState{ConnectivityState: connectivity.Ready})
		case <-newSCTimeout:
			t.Fatalf("timeout waiting for subConns (from new sub-balancer) to be newed")
		}
	}

	// Test roundrobin on the new picker.
	p3 := <-cc.NewPickerCh
	want := []balancer.SubConn{
		addrToSC[testBackendAddrs[0]], addrToSC[testBackendAddrs[0]],
		addrToSC[testBackendAddrs[1]], addrToSC[testBackendAddrs[1]],
		addrToSC[testBackendAddrs[4]], addrToSC[testBackendAddrs[5]],
	}
	if err := testutils.IsRoundRobin(want, subConnFromPicker(p3)); err != nil {
		t.Fatalf("want %v, got %v", want, err)
	}
}

// After removing a sub-balancer, it will be kept in cache. Make sure that this
// sub-balancer's Close is called when the balancer group is closed.
func (s) TestBalancerGroup_CloseStopsBalancerInCache(t *testing.T) {
	const balancerName = "stub-TestBalancerGroup_check_close"
	closed := make(chan struct{})
	stub.Register(balancerName, stub.BalancerFuncs{Close: func(_ *stub.BalancerData) {
		close(closed)
	}})
	builder := balancer.Get(balancerName)

	defer replaceDefaultSubBalancerCloseTimeout(time.Second)()
	gator, bg, _, _ := initBalancerGroupForCachingTest(t)

	// Add balancer, and remove
	gator.Add(testBalancerIDs[2], 1)
	bg.Add(testBalancerIDs[2], builder)
	gator.Remove(testBalancerIDs[2])
	bg.Remove(testBalancerIDs[2])

	// Immediately close balancergroup, before the cache timeout.
	bg.Close()

	// Make sure the removed child balancer is closed eventually.
	select {
	case <-closed:
	case <-time.After(time.Second * 2):
		t.Fatalf("timeout waiting for the child balancer in cache to be closed")
	}
}

// TestBalancerGroupBuildOptions verifies that the balancer.BuildOptions passed
// to the balancergroup at creation time is passed to child policies.
func (s) TestBalancerGroupBuildOptions(t *testing.T) {
	const (
		balancerName       = "stubBalancer-TestBalancerGroupBuildOptions"
		parent             = int64(1234)
		userAgent          = "ua"
		defaultTestTimeout = 1 * time.Second
	)

	// Setup the stub balancer such that we can read the build options passed to
	// it in the UpdateClientConnState method.
	bOpts := balancer.BuildOptions{
		DialCreds:        insecure.NewCredentials(),
		ChannelzParentID: parent,
		CustomUserAgent:  userAgent,
	}
	stub.Register(balancerName, stub.BalancerFuncs{
		UpdateClientConnState: func(bd *stub.BalancerData, _ balancer.ClientConnState) error {
			if !cmp.Equal(bd.BuildOptions, bOpts) {
				return fmt.Errorf("buildOptions in child balancer: %v, want %v", bd, bOpts)
			}
			return nil
		},
	})
	cc := testutils.NewTestClientConn(t)
	bg := New(cc, bOpts, nil, nil)
	bg.Start()

	// Add the stub balancer build above as a child policy.
	balancerBuilder := balancer.Get(balancerName)
	bg.Add(testBalancerIDs[0], balancerBuilder)

	// Send an empty clientConn state change. This should trigger the
	// verification of the buildOptions being passed to the child policy.
	if err := bg.UpdateClientConnState(testBalancerIDs[0], balancer.ClientConnState{}); err != nil {
		t.Fatal(err)
	}
}

func (s) TestBalancerExitIdleOne(t *testing.T) {
	const balancerName = "stub-balancer-test-balancergroup-exit-idle-one"
	exitIdleCh := make(chan struct{}, 1)
	stub.Register(balancerName, stub.BalancerFuncs{
		ExitIdle: func(*stub.BalancerData) {
			exitIdleCh <- struct{}{}
		},
	})
	cc := testutils.NewTestClientConn(t)
	bg := New(cc, balancer.BuildOptions{}, nil, nil)
	bg.Start()
	defer bg.Close()

	// Add the stub balancer build above as a child policy.
	builder := balancer.Get(balancerName)
	bg.Add(testBalancerIDs[0], builder)

	// Call ExitIdle on the child policy.
	bg.ExitIdleOne(testBalancerIDs[0])
	select {
	case <-time.After(time.Second):
		t.Fatal("Timeout when waiting for ExitIdle to be invoked on child policy")
	case <-exitIdleCh:
	}
}
