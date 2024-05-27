// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9

package ctxhttp

import (
	"context"
	"io"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/gmhttp/httptest"

	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"
)

func TestGo17Context(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()
	ctx := context.Background()
	resp, err := Get(ctx, http.DefaultClient, ts.URL)
	if resp == nil || err != nil {
		t.Fatalf("error received from client: %v %v", err, resp)
	}
	_ = resp.Body.Close()
}

const (
	requestDuration = 100 * time.Millisecond
	requestBody     = "ok"
)

//goland:noinspection GoUnusedParameter
func okHandler(w http.ResponseWriter, r *http.Request) {
	time.Sleep(requestDuration)
	_, _ = io.WriteString(w, requestBody)
}

func TestNoTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(okHandler))
	defer ts.Close()

	ctx := context.Background()
	res, err := Get(ctx, nil, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != requestBody {
		t.Errorf("body = %q; want %q", slurp, requestBody)
	}
}

func TestCancelBeforeHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	blockServer := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-blockServer
		_, _ = io.WriteString(w, requestBody)
	}))
	defer ts.Close()
	defer close(blockServer)

	res, err := Get(ctx, nil, ts.URL)
	if err == nil {
		_ = res.Body.Close()
		t.Fatal("Get returned unexpected nil error")
	}
	if err != context.Canceled {
		t.Errorf("err = %v; want %v", err, context.Canceled)
	}
}

func TestCancelAfterHangingRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-w.(http.CloseNotifier).CloseNotify()
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	resp, err := Get(ctx, nil, ts.URL)
	if err != nil {
		t.Fatalf("unexpected error in Get: %v", err)
	}

	// Cancel befer reading the body.
	// Reading Request.Body should fail, since the request was
	// canceled before anything was written.
	cancel()

	done := make(chan struct{})

	go func() {
		b, err := io.ReadAll(resp.Body)
		if len(b) != 0 || err == nil {
			t.Errorf(`Read got (%q, %v); want ("", error)`, b, err)
		}
		close(done)
	}()

	select {
	case <-time.After(1 * time.Second):
		t.Errorf("Test timed out")
	case <-done:
	}
}
