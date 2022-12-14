/*
 *
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
 *
 */

package controller

import (
	"testing"
	"time"

	v2xdspb "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/api/v2"
	"gitee.com/zhaochuninhefei/gmgo/grpc/xds/internal/xdsclient/xdsresource"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestLDSHandleResponse starts a fake xDS server, makes a ClientConn to it,
// and creates a client using it. Then, it registers a watchLDS and tests
// different LDS responses.
func (s) TestLDSHandleResponse(t *testing.T) {
	tests := []struct {
		name          string
		ldsResponse   *v2xdspb.DiscoveryResponse
		wantErr       bool
		wantUpdate    map[string]xdsresource.ListenerUpdateErrTuple
		wantUpdateMD  xdsresource.UpdateMetadata
		wantUpdateErr bool
	}{
		// Badly marshaled LDS response.
		{
			name:        "badly-marshaled-response",
			ldsResponse: badlyMarshaledLDSResponse,
			wantErr:     true,
			wantUpdate:  nil,
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusNACKed,
				ErrState: &xdsresource.UpdateErrorMetadata{
					Err: cmpopts.AnyError,
				},
			},
			wantUpdateErr: false,
		},
		// Response does not contain Listener proto.
		{
			name:        "no-listener-proto-in-response",
			ldsResponse: badResourceTypeInLDSResponse,
			wantErr:     true,
			wantUpdate:  nil,
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusNACKed,
				ErrState: &xdsresource.UpdateErrorMetadata{
					Err: cmpopts.AnyError,
				},
			},
			wantUpdateErr: false,
		},
		// No APIListener in the response. Just one test case here for a bad
		// ApiListener, since the others are covered in
		// TestGetRouteConfigNameFromListener.
		{
			name:        "no-apiListener-in-response",
			ldsResponse: noAPIListenerLDSResponse,
			wantErr:     true,
			wantUpdate: map[string]xdsresource.ListenerUpdateErrTuple{
				goodLDSTarget1: {Err: cmpopts.AnyError},
			},
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusNACKed,
				ErrState: &xdsresource.UpdateErrorMetadata{
					Err: cmpopts.AnyError,
				},
			},
			wantUpdateErr: false,
		},
		// Response contains one listener and it is good.
		{
			name:        "one-good-listener",
			ldsResponse: goodLDSResponse1,
			wantErr:     false,
			wantUpdate: map[string]xdsresource.ListenerUpdateErrTuple{
				goodLDSTarget1: {Update: xdsresource.ListenerUpdate{RouteConfigName: goodRouteName1, Raw: marshaledListener1}},
			},
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusACKed,
			},
			wantUpdateErr: false,
		},
		// Response contains multiple good listeners, including the one we are
		// interested in.
		{
			name:        "multiple-good-listener",
			ldsResponse: ldsResponseWithMultipleResources,
			wantErr:     false,
			wantUpdate: map[string]xdsresource.ListenerUpdateErrTuple{
				goodLDSTarget1: {Update: xdsresource.ListenerUpdate{RouteConfigName: goodRouteName1, Raw: marshaledListener1}},
				goodLDSTarget2: {Update: xdsresource.ListenerUpdate{RouteConfigName: goodRouteName1, Raw: marshaledListener2}},
			},
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusACKed,
			},
			wantUpdateErr: false,
		},
		// Response contains two good listeners (one interesting and one
		// uninteresting), and one badly marshaled listener. This will cause a
		// nack because the uninteresting listener will still be parsed.
		{
			name:        "good-bad-ugly-listeners",
			ldsResponse: goodBadUglyLDSResponse,
			wantErr:     true,
			wantUpdate: map[string]xdsresource.ListenerUpdateErrTuple{
				goodLDSTarget1: {Update: xdsresource.ListenerUpdate{RouteConfigName: goodRouteName1, Raw: marshaledListener1}},
				goodLDSTarget2: {Err: cmpopts.AnyError},
			},
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusNACKed,
				ErrState: &xdsresource.UpdateErrorMetadata{
					Err: cmpopts.AnyError,
				},
			},
			wantUpdateErr: false,
		},
		// Response contains one listener, but we are not interested in it.
		{
			name:        "one-uninteresting-listener",
			ldsResponse: goodLDSResponse2,
			wantErr:     false,
			wantUpdate: map[string]xdsresource.ListenerUpdateErrTuple{
				goodLDSTarget2: {Update: xdsresource.ListenerUpdate{RouteConfigName: goodRouteName1, Raw: marshaledListener2}},
			},
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusACKed,
			},
			wantUpdateErr: false,
		},
		// Response constains no resources. This is the case where the server
		// does not know about the target we are interested in.
		{
			name:        "empty-response",
			ldsResponse: emptyLDSResponse,
			wantErr:     false,
			wantUpdate:  nil,
			wantUpdateMD: xdsresource.UpdateMetadata{
				Status: xdsresource.ServiceStatusACKed,
			},
			wantUpdateErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testWatchHandle(t, &watchHandleTestcase{
				rType:            xdsresource.ListenerResource,
				resourceName:     goodLDSTarget1,
				responseToHandle: test.ldsResponse,
				wantHandleErr:    test.wantErr,
				wantUpdate:       test.wantUpdate,
				wantUpdateMD:     test.wantUpdateMD,
				wantUpdateErr:    test.wantUpdateErr,
			})
		})
	}
}

// TestLDSHandleResponseWithoutWatch tests the case where the client receives
// an LDS response without a registered watcher.
func (s) TestLDSHandleResponseWithoutWatch(t *testing.T) {
	fakeServer, cleanup := startServer(t)
	defer cleanup()

	v2c, err := newTestController(&testUpdateReceiver{
		f: func(xdsresource.ResourceType, map[string]interface{}, xdsresource.UpdateMetadata) {},
	}, fakeServer.Address, goodNodeProto, func(int) time.Duration { return 0 }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v2c.Close()

	if _, _, _, err := v2c.handleResponse(badResourceTypeInLDSResponse); err == nil {
		t.Fatal("v2c.handleLDSResponse() succeeded, should have failed")
	}

	if _, _, _, err := v2c.handleResponse(goodLDSResponse1); err != nil {
		t.Fatal("v2c.handleLDSResponse() succeeded, should have failed")
	}
}
