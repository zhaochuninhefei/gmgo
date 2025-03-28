// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6_test

import (
	"bytes"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/net/icmp"
	"gitee.com/zhaochuninhefei/gmgo/net/internal/iana"
	"gitee.com/zhaochuninhefei/gmgo/net/ipv6"
	"gitee.com/zhaochuninhefei/gmgo/net/nettest"
)

var packetConnReadWriteMulticastUDPTests = []struct {
	addr     string
	grp, src *net.UDPAddr
}{
	{"[ff02::]:0", &net.UDPAddr{IP: net.ParseIP("ff02::114")}, nil}, // see RFC 4727

	{"[ff30::8000:0]:0", &net.UDPAddr{IP: net.ParseIP("ff30::8000:1")}, &net.UDPAddr{IP: net.IPv6loopback}}, // see RFC 5771
}

func TestPacketConnReadWriteMulticastUDP(t *testing.T) {
	switch runtime.GOOS {
	case "fuchsia", "hurd", "js", "nacl", "plan9", "windows":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !nettest.SupportsIPv6() {
		t.Skip("ipv6 is not supported")
	}
	if m, ok := supportsIPv6MulticastDeliveryOnLoopback(); !ok {
		t.Skip(m)
	}
	ifi, err := nettest.RoutedInterface("ip6", net.FlagUp|net.FlagMulticast|net.FlagLoopback)
	if err != nil {
		t.Skipf("not available on %s", runtime.GOOS)
	}

	for _, tt := range packetConnReadWriteMulticastUDPTests {
		c, err := net.ListenPacket("udp6", tt.addr)
		if err != nil {
			t.Fatal(err)
		}
		//goland:noinspection GoDeferInLoop
		defer func(c net.PacketConn) {
			_ = c.Close()
		}(c)

		grp := *tt.grp
		grp.Port = c.LocalAddr().(*net.UDPAddr).Port
		p := ipv6.NewPacketConn(c)
		//goland:noinspection GoDeferInLoop
		defer func(p *ipv6.PacketConn) {
			_ = p.Close()
		}(p)
		if tt.src == nil {
			if err := p.JoinGroup(ifi, &grp); err != nil {
				t.Fatal(err)
			}
			//goland:noinspection GoDeferInLoop
			defer func(p *ipv6.PacketConn, ifi *net.Interface, group net.Addr) {
				_ = p.LeaveGroup(ifi, group)
			}(p, ifi, &grp)
		} else {
			if err := p.JoinSourceSpecificGroup(ifi, &grp, tt.src); err != nil {
				switch runtime.GOOS {
				case "freebsd", "linux":
				default: // platforms that don't support MLDv2 fail here
					t.Logf("not supported on %s", runtime.GOOS)
					continue
				}
				t.Fatal(err)
			}
			//goland:noinspection GoDeferInLoop
			defer func(p *ipv6.PacketConn, ifi *net.Interface, group, source net.Addr) {
				_ = p.LeaveSourceSpecificGroup(ifi, group, source)
			}(p, ifi, &grp, tt.src)
		}
		if err := p.SetMulticastInterface(ifi); err != nil {
			t.Fatal(err)
		}
		if _, err := p.MulticastInterface(); err != nil {
			t.Fatal(err)
		}
		if err := p.SetMulticastLoopback(true); err != nil {
			t.Fatal(err)
		}
		if _, err := p.MulticastLoopback(); err != nil {
			t.Fatal(err)
		}

		cm := ipv6.ControlMessage{
			TrafficClass: iana.DiffServAF11 | iana.CongestionExperienced,
			Src:          net.IPv6loopback,
			IfIndex:      ifi.Index,
		}
		cf := ipv6.FlagTrafficClass | ipv6.FlagHopLimit | ipv6.FlagSrc | ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagPathMTU
		wb := []byte("HELLO-R-U-THERE")

		for i, toggle := range []bool{true, false, true} {
			if err := p.SetControlMessage(cf, toggle); err != nil {
				if protocolNotSupported(err) {
					t.Logf("not supported on %s", runtime.GOOS)
					continue
				}
				t.Fatal(err)
			}
			cm.HopLimit = i + 1

			backoff := time.Millisecond
			for {
				n, err := p.WriteTo(wb, &cm, &grp)
				if err != nil {
					if n == 0 && isENOBUFS(err) {
						time.Sleep(backoff)
						backoff *= 2
						continue
					}
					t.Fatal(err)
				}
				if n != len(wb) {
					t.Fatalf("wrote %v bytes; want %v", n, len(wb))
				}
				break
			}

			rb := make([]byte, 128)
			if n, _, _, err := p.ReadFrom(rb); err != nil {
				t.Fatal(err)
			} else if !bytes.Equal(rb[:n], wb) {
				t.Fatalf("got %v; want %v", rb[:n], wb)
			}
		}
	}
}

var packetConnReadWriteMulticastICMPTests = []struct {
	grp, src *net.IPAddr
}{
	{&net.IPAddr{IP: net.ParseIP("ff02::114")}, nil}, // see RFC 4727

	{&net.IPAddr{IP: net.ParseIP("ff30::8000:1")}, &net.IPAddr{IP: net.IPv6loopback}}, // see RFC 5771
}

func TestPacketConnReadWriteMulticastICMP(t *testing.T) {
	if os.Getenv("GO_BUILDER_NAME") == "openbsd-amd64-68" ||
		os.Getenv("GO_BUILDER_NAME") == "openbsd-386-68" {
		t.Skip(`this test is currently failing on OpenBSD 6.8 builders with "raw-read ip6: i/o timeout" ` +
			`and needs investigation, see golang.org/issue/42064`)
	}
	switch runtime.GOOS {
	case "fuchsia", "hurd", "js", "nacl", "plan9", "windows":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !nettest.SupportsIPv6() {
		t.Skip("ipv6 is not supported")
	}
	if m, ok := supportsIPv6MulticastDeliveryOnLoopback(); !ok {
		t.Skip(m)
	}
	if !nettest.SupportsRawSocket() {
		t.Skipf("not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	ifi, err := nettest.RoutedInterface("ip6", net.FlagUp|net.FlagMulticast|net.FlagLoopback)
	if err != nil {
		t.Skipf("not available on %s", runtime.GOOS)
	}

	for _, tt := range packetConnReadWriteMulticastICMPTests {
		c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			t.Fatal(err)
		}
		//goland:noinspection GoDeferInLoop
		defer func(c net.PacketConn) {
			_ = c.Close()
		}(c)

		pshicmp := icmp.IPv6PseudoHeader(c.LocalAddr().(*net.IPAddr).IP, tt.grp.IP)
		p := ipv6.NewPacketConn(c)
		//goland:noinspection GoDeferInLoop
		defer func(p *ipv6.PacketConn) {
			_ = p.Close()
		}(p)
		if tt.src == nil {
			if err := p.JoinGroup(ifi, tt.grp); err != nil {
				t.Fatal(err)
			}
			//goland:noinspection GoDeferInLoop
			defer func(p *ipv6.PacketConn, ifi *net.Interface, group net.Addr) {
				_ = p.LeaveGroup(ifi, group)
			}(p, ifi, tt.grp)
		} else {
			if err := p.JoinSourceSpecificGroup(ifi, tt.grp, tt.src); err != nil {
				switch runtime.GOOS {
				case "freebsd", "linux":
				default: // platforms that don't support MLDv2 fail here
					t.Logf("not supported on %s", runtime.GOOS)
					continue
				}
				t.Fatal(err)
			}
			//goland:noinspection GoDeferInLoop
			defer func(p *ipv6.PacketConn, ifi *net.Interface, group, source net.Addr) {
				_ = p.LeaveSourceSpecificGroup(ifi, group, source)
			}(p, ifi, tt.grp, tt.src)
		}
		if err := p.SetMulticastInterface(ifi); err != nil {
			t.Fatal(err)
		}
		if _, err := p.MulticastInterface(); err != nil {
			t.Fatal(err)
		}
		if err := p.SetMulticastLoopback(true); err != nil {
			t.Fatal(err)
		}
		if _, err := p.MulticastLoopback(); err != nil {
			t.Fatal(err)
		}

		cm := ipv6.ControlMessage{
			TrafficClass: iana.DiffServAF11 | iana.CongestionExperienced,
			Src:          net.IPv6loopback,
			IfIndex:      ifi.Index,
		}
		cf := ipv6.FlagTrafficClass | ipv6.FlagHopLimit | ipv6.FlagSrc | ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagPathMTU

		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeEchoReply)
		if err := p.SetICMPFilter(&f); err != nil {
			t.Fatal(err)
		}

		var psh []byte
		for i, toggle := range []bool{true, false, true} {
			if toggle {
				psh = nil
				if err := p.SetChecksum(true, 2); err != nil {
					// Illumos and Solaris never allow
					// modification of ICMP properties.
					if runtime.GOOS != "illumos" && runtime.GOOS != "solaris" {
						t.Fatal(err)
					}
				}
			} else {
				psh = pshicmp
				// Some platforms never allow to
				// disable the kernel checksum
				// processing.
				_ = p.SetChecksum(false, -1)
			}
			wb, err := (&icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest, Code: 0,
				Body: &icmp.Echo{
					ID: os.Getpid() & 0xffff, Seq: i + 1,
					Data: []byte("HELLO-R-U-THERE"),
				},
			}).Marshal(psh)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.SetControlMessage(cf, toggle); err != nil {
				if protocolNotSupported(err) {
					t.Logf("not supported on %s", runtime.GOOS)
					continue
				}
				t.Fatal(err)
			}
			cm.HopLimit = i + 1
			if n, err := p.WriteTo(wb, &cm, tt.grp); err != nil {
				t.Fatal(err)
			} else if n != len(wb) {
				t.Fatalf("got %v; want %v", n, len(wb))
			}
			rb := make([]byte, 128)
			if n, _, _, err := p.ReadFrom(rb); err != nil {
				switch runtime.GOOS {
				case "darwin", "ios": // older darwin kernels have some limitation on receiving icmp packet through raw socket
					t.Logf("not supported on %s", runtime.GOOS)
					continue
				}
				t.Fatal(err)
			} else {
				if m, err := icmp.ParseMessage(iana.ProtocolIPv6ICMP, rb[:n]); err != nil {
					t.Fatal(err)
				} else if m.Type != ipv6.ICMPTypeEchoReply || m.Code != 0 {
					t.Fatalf("got type=%v, code=%v; want type=%v, code=%v", m.Type, m.Code, ipv6.ICMPTypeEchoReply, 0)
				}
			}
		}
	}
}
