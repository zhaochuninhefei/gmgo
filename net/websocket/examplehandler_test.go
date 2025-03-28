// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket_test

import (
	"io"

	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"

	"gitee.com/zhaochuninhefei/gmgo/net/websocket"
)

// Echo the data received on the WebSocket.
func EchoServer(ws *websocket.Conn) {
	_, _ = io.Copy(ws, ws)
}

// This example demonstrates a trivial echo server.
func ExampleHandler() {
	http.Handle("/echo", websocket.Handler(EchoServer))
	err := http.ListenAndServe(":12345", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
