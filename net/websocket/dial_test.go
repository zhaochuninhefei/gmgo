// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"errors"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/gmhttp/httptest"

	tls "gitee.com/zhaochuninhefei/gmgo/gmtls"
)

// This test depend on Go 1.3+ because in earlier versions the Dialer won't be
// used in TLS connections and a timeout won't be triggered.
func TestDialConfigTLSWithDialer(t *testing.T) {
	tlsServer := httptest.NewTLSServer(nil)
	tlsServerAddr := tlsServer.Listener.Addr().String()
	log.Print("Test TLS WebSocket server listening on ", tlsServerAddr)
	defer tlsServer.Close()
	config, _ := NewConfig(fmt.Sprintf("wss://%s/echo", tlsServerAddr), "http://localhost")
	config.Dialer = &net.Dialer{
		Deadline: time.Now().Add(-time.Minute),
	}
	config.TlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	_, err := DialConfig(config)
	var dialerr *DialError
	ok := errors.As(err, &dialerr)
	if !ok {
		t.Fatalf("DialError expected, got %#v", err)
	}
	var neterr *net.OpError
	ok = errors.As(dialerr.Err, &neterr)
	if !ok {
		t.Fatalf("net.OpError error expected, got %#v", dialerr.Err)
	}
	if !neterr.Timeout() {
		t.Fatalf("expected timeout error, got %#v", neterr)
	}
}
