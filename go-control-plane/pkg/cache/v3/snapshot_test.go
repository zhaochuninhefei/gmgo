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

package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/types"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/cache/v3"
	rsrc "gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/resource/v3"
	"gitee.com/zhaochuninhefei/gmgo/go-control-plane/pkg/test/resource/v3"
)

func TestSnapshotConsistent(t *testing.T) {
	if err := snapshot.Consistent(); err != nil {
		t.Errorf("got inconsistent snapshot for %#v", snapshot)
	}

	if snap, _ := cache.NewSnapshot(version, map[rsrc.Type][]types.Resource{
		rsrc.EndpointType: {testEndpoint},
	}); snap.Consistent() == nil {
		t.Errorf("got consistent snapshot %#v", snap)
	}

	if snap, _ := cache.NewSnapshot(version, map[rsrc.Type][]types.Resource{
		rsrc.EndpointType: {resource.MakeEndpoint("missing", 8080)},
		rsrc.ClusterType:  {testCluster},
	}); snap.Consistent() == nil {
		t.Errorf("got consistent snapshot %#v", snap)
	}

	if snap, _ := cache.NewSnapshot(version, map[rsrc.Type][]types.Resource{
		rsrc.ListenerType: {testListener}},
	); snap.Consistent() == nil {
		t.Errorf("got consistent snapshot %#v", snap)
	}

	if snap, _ := cache.NewSnapshot(version, map[rsrc.Type][]types.Resource{
		rsrc.RouteType:    {resource.MakeRoute("test", clusterName)},
		rsrc.ListenerType: {testListener},
	}); snap.Consistent() == nil {
		t.Errorf("got consistent snapshot %#v", snap)
	}
}

func TestSnapshotGetters(t *testing.T) {
	var nilsnap *cache.Snapshot
	if out := nilsnap.GetResources(rsrc.EndpointType); out != nil {
		t.Errorf("got non-empty resources for nil snapshot: %#v", out)
	}
	if out := nilsnap.Consistent(); out == nil {
		t.Errorf("nil snapshot should be inconsistent")
	}
	if out := nilsnap.GetVersion(rsrc.EndpointType); out != "" {
		t.Errorf("got non-empty version for nil snapshot: %#v", out)
	}
	if out := snapshot.GetResources("not a type"); out != nil {
		t.Errorf("got non-empty resources for unknown type: %#v", out)
	}
	if out := snapshot.GetVersion("not a type"); out != "" {
		t.Errorf("got non-empty version for unknown type: %#v", out)
	}
}

func TestNewSnapshotBadType(t *testing.T) {
	snap, err := cache.NewSnapshot(version, map[rsrc.Type][]types.Resource{
		"random.type": nil,
	})

	// Should receive an error from an unknown type
	assert.Error(t, err)
	assert.Equal(t, cache.Snapshot{}, snap)
}
