// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"

	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"
)

func newServerConn(rwc io.ReadWriteCloser, buf *bufio.ReadWriter, req *http.Request, config *Config, handshake func(*Config, *http.Request) error) (conn *Conn, err error) {
	var hs serverHandshaker = &hybiServerHandshaker{Config: config}
	code, err := hs.ReadHandshake(buf.Reader, req)
	if errors.Is(err, ErrBadWebSocketVersion) {
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n", code, http.StatusText(code))
		_, _ = fmt.Fprintf(buf, "Sec-WebSocket-Version: %s\r\n", SupportedProtocolVersion)
		_, _ = buf.WriteString("\r\n")
		_, _ = buf.WriteString(err.Error())
		_ = buf.Flush()
		return
	}
	if err != nil {
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n", code, http.StatusText(code))
		_, _ = buf.WriteString("\r\n")
		_, _ = buf.WriteString(err.Error())
		_ = buf.Flush()
		return
	}
	if handshake != nil {
		err = handshake(config, req)
		if err != nil {
			code = http.StatusForbidden
			_, _ = fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n", code, http.StatusText(code))
			_, _ = buf.WriteString("\r\n")
			_ = buf.Flush()
			return
		}
	}
	err = hs.AcceptHandshake(buf.Writer)
	if err != nil {
		code = http.StatusBadRequest
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 %03d %s\r\n", code, http.StatusText(code))
		_, _ = buf.WriteString("\r\n")
		_ = buf.Flush()
		return
	}
	conn = hs.NewServerConn(buf, rwc, req)
	return
}

// Server represents a server of a WebSocket.
type Server struct {
	// Config is a WebSocket configuration for new WebSocket connection.
	Config

	// Handshake is an optional function in WebSocket handshake.
	// For example, you can check, or don't check Origin header.
	// Another example, you can select config.Protocol.
	Handshake func(*Config, *http.Request) error

	// Handler handles a WebSocket connection.
	Handler
}

// ServeHTTP implements the http.Handler interface for a WebSocket
func (s Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.serveWebSocket(w, req)
}

func (s Server) serveWebSocket(w http.ResponseWriter, req *http.Request) {
	rwc, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic("Hijack failed: " + err.Error())
	}
	// The server should abort the WebSocket connection if it finds
	// the client did not send a handshake that matches with protocol
	// specification.
	defer func(rwc net.Conn) {
		_ = rwc.Close()
	}(rwc)
	conn, err := newServerConn(rwc, buf, req, &s.Config, s.Handshake)
	if err != nil {
		return
	}
	if conn == nil {
		panic("unexpected nil conn")
	}
	s.Handler(conn)
}

// Handler is a simple interface to a WebSocket browser client.
// It checks if Origin header is valid URL by default.
// You might want to verify websocket.Conn.Config().Origin in the func.
// If you use Server instead of Handler, you could call websocket.Origin and
// check the origin in your Handshake func. So, if you want to accept
// non-browser clients, which do not send an Origin header, set a
// Server.Handshake that does not check the origin.
type Handler func(*Conn)

func checkOrigin(config *Config, req *http.Request) (err error) {
	config.Origin, err = Origin(config, req)
	if err == nil && config.Origin == nil {
		return fmt.Errorf("null origin")
	}
	return err
}

// ServeHTTP implements the http.Handler interface for a WebSocket
func (h Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s := Server{Handler: h, Handshake: checkOrigin}
	s.serveWebSocket(w, req)
}
