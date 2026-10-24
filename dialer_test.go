package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type testPeer struct {
	stack    *netstack.Net
	identity *Identity
}

func localPeer(t *testing.T) *testPeer {
	t.Helper()
	clientPrivate, clientPublic := testKey(t)
	serverPrivate, serverPublic := testKey(t)
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	// The test peer normalizes WARP's reserved bytes, exercising both directions.
	dev := device.NewDevice(tun, &reservedBind{Bind: conn.NewDefaultBind(), reserved: [3]byte{7, 8, 9}}, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	priv, _ := base64.StdEncoding.DecodeString(serverPrivate)
	pub, _ := base64.StdEncoding.DecodeString(clientPublic)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.77.0.2/32\nallowed_ip=fd77::2/128\n", hex.EncodeToString(priv), hex.EncodeToString(pub))); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("no peer port")
	}
	return &testPeer{stack: stack, identity: &Identity{PrivateKey: clientPrivate, PeerPublicKey: serverPublic, Endpoint: net.JoinHostPort("127.0.0.1", port), Addresses: []netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77::2")}, Reserved: [3]byte{7, 8, 9}}}
}
func (p *testPeer) dialer(t *testing.T, configure func(*Config)) *Dialer {
	t.Helper()
	config := Config{Identity: p.identity, DNS: []netip.Addr{netip.MustParseAddr("10.77.0.1")}}
	if configure != nil {
		configure(&config)
	}
	d, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func TestTunnelConnections(t *testing.T) {
	p := localPeer(t)
	listener, err := p.stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	requestStarted := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stall":
			requestStarted <- struct{}{}
			<-r.Context().Done()
		case "/upgrade":
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
			rw.Flush()
			frame := make([]byte, 11)
			if _, err := io.ReadFull(rw, frame); err != nil {
				return
			}
			if frame[0] != 0x81 || frame[1] != 0x85 {
				return
			}
			for i := 0; i < 5; i++ {
				frame[6+i] ^= frame[2+i%4]
			}
			c.Write(append([]byte{0x81, 5}, frame[6:]...))
		default:
			fmt.Fprint(w, "through-wireguard")
		}
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	// A tiny DNS server on the remote netstack answers A/AAAA queries. No host
	// resolver or public network is involved in these integration tests.
	dns, err := p.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dns.Close() })
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 1500)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			answer := dnsAnswer(buf[:n])
			if answer != nil {
				dns.WriteTo(answer, addr)
			}
		}
	}()
	d := p.dialer(t, nil)
	t.Run("HTTPS", func(t *testing.T) {
		ln, err := p.stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:443"))
		if err != nil {
			t.Fatal(err)
		}
		tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secure") }))
		tlsServer.Listener.Close()
		tlsServer.Listener = ln
		tlsServer.StartTLS()
		defer tlsServer.Close()
		roots := x509.NewCertPool()
		roots.AddCert(tlsServer.Certificate())
		tr := &http.Transport{DialContext: d.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		resp, err := client.Get("https://10.77.0.1/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "secure" {
			t.Fatalf("HTTPS: body %q, err %v", body, err)
		}
	})
	t.Run("TCP half close", func(t *testing.T) {
		ln, err := p.stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:82"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		done := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			b, err := io.ReadAll(c)
			if err == nil {
				_, err = c.Write(b)
			}
			done <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp4", "10.77.0.1:82")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("after EOF")); err != nil {
			t.Fatal(err)
		}
		if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(c)
		if err != nil || string(b) != "after EOF" {
			t.Fatalf("half-close: body %q, err %v", b, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("IPv6 blackhole falls back to IPv4", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		started := time.Now()
		c, err := d.dialTCP(ctx, []netip.AddrPort{netip.MustParseAddrPort("[fd77::99]:80"), netip.MustParseAddrPort("10.77.0.1:80")})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if time.Since(started) > 1500*time.Millisecond {
			t.Fatal("address family fallback waited for blackhole")
		}
	})
	t.Run("UDP echo", func(t *testing.T) {
		remote, err := p.stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:83"))
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Close()
		done := make(chan error, 1)
		go func() {
			b := make([]byte, 100)
			n, addr, err := remote.ReadFrom(b)
			if err == nil {
				_, err = remote.WriteTo(b[:n], addr)
			}
			done <- err
		}()
		c, err := d.DialContext(context.Background(), "udp4", "10.77.0.1:83")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("datagram")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 100)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != "datagram" {
			t.Fatalf("UDP: body %q, err %v", b[:n], err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("HTTP with tunnel DNS", func(t *testing.T) {
		tr := &http.Transport{DialContext: d.DialContext}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		resp, err := client.Get("http://warp.test/")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "through-wireguard" {
			t.Fatalf("unexpected body %q", body)
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		ln, err := p.stack.ListenTCPAddrPort(netip.MustParseAddrPort("[fd77::1]:81"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			c.Write([]byte("v6"))
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp6", "[fd77::1]:81")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 2)
		if _, err := io.ReadFull(c, b); err != nil {
			t.Fatal(err)
		}
		if string(b) != "v6" {
			t.Fatal("wrong v6 payload")
		}
		<-done
	})
	t.Run("WebSocket upgrade and frame", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp4", "10.77.0.1:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(c, "GET /upgrade HTTP/1.1\r\nHost: warp.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		reader := bufio.NewReader(c)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 101 {
			t.Fatal(resp.Status)
		}
		frame := []byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1}
		if _, err := c.Write(frame); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 7)
		if _, err := io.ReadFull(reader, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply, []byte{0x81, 5, 'h', 'e', 'l', 'l', 'o'}) {
			t.Fatalf("unexpected WebSocket frame: %x", reply)
		}
	})
	t.Run("HTTP cancellation after establishment", func(t *testing.T) {
		tr := &http.Transport{DialContext: d.DialContext}
		defer tr.CloseIdleConnections()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://10.77.0.1/stall", nil)
		done := make(chan error, 1)
		go func() {
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			done <- err
		}()
		select {
		case <-requestStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not arrive")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTP did not cancel")
		}
	})
	t.Run("dial context does not own connection lifetime", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		c, err := d.DialContext(ctx, "tcp", "10.77.0.1:80")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		defer c.Close()
		cancel()
		c.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: warp.test\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	})
	t.Run("close wakes blocked reads and pending dials", func(t *testing.T) {
		own := p.dialer(t, nil)
		c, err := own.DialContext(context.Background(), "tcp4", "10.77.0.1:80")
		if err != nil {
			t.Fatal(err)
		}
		readDone := make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 1)); readDone <- err }()
		dialDone := make(chan error, 1)
		go func() { _, err := own.DialContext(context.Background(), "tcp4", "10.77.0.99:80"); dialDone <- err }()
		time.Sleep(20 * time.Millisecond)
		closed := make(chan struct{})
		go func() { own.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("Close hung")
		}
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("blocked read succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("read stuck")
		}
		select {
		case err := <-dialDone:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("dial stuck")
		}
		if _, err := own.DialContext(context.Background(), "tcp", "10.77.0.1:80"); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
		own.mu.Lock()
		n := len(own.connections)
		own.mu.Unlock()
		if n != 0 {
			t.Fatalf("%d retained connections", n)
		}
	})
	t.Run("concurrent close and dialing", func(t *testing.T) {
		own := p.dialer(t, nil)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				c, err := own.DialContext(ctx, "tcp4", "10.77.0.1:80")
				if err == nil {
					c.Close()
				}
			}()
		}
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); own.Close() }()
		}
		wg.Wait()
	})
	dns.Close()
	<-dnsDone
}

func dnsAnswer(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	end := 12
	for end < len(query) && query[end] != 0 {
		end += 1 + int(query[end])
	}
	end += 5
	if end > len(query) {
		return nil
	}
	kind := binary.BigEndian.Uint16(query[end-4 : end-2])
	answer := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	binary.BigEndian.PutUint16(answer[6:8], 0)
	binary.BigEndian.PutUint16(answer[8:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 0)
	var ip []byte
	switch kind {
	case 1:
		ip = net.ParseIP("10.77.0.1").To4()
	case 28:
		ip = net.ParseIP("fd77::1").To16()
	default:
		return answer
	}
	binary.BigEndian.PutUint16(answer[6:8], 1)
	answer = append(answer, 0xc0, 0x0c, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
	return append(answer, ip...)
}

func TestCancellationAndValidation(t *testing.T) {
	// No peer answers: cancellation must interrupt both DNS and TCP immediately.
	identity := testIdentity(t)
	d, err := New(context.Background(), Config{Identity: identity, DialTimeout: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, address := range []string{"does-not-exist.test:80", "10.77.0.99:80"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := d.DialContext(ctx, "tcp4", address); done <- err }()
			time.Sleep(30 * time.Millisecond)
			start := time.Now()
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if time.Since(start) > 500*time.Millisecond {
					t.Fatal("slow cancellation")
				}
			case <-time.After(time.Second):
				t.Fatal("dial did not cancel")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp4", "10.77.0.99:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for _, network := range []string{"unix", "tcp7"} {
		if _, err := d.DialContext(context.Background(), network, "a:80"); err == nil {
			t.Fatal("accepted unsupported network")
		}
	}
	for _, address := range []string{"host", "host:abc", "host:65536", ":80"} {
		if _, err := d.DialContext(context.Background(), "tcp", address); err == nil {
			t.Fatalf("accepted address %s", address)
		}
	}
	for _, config := range []Config{{}, {Identity: identity, MTU: 100}, {Identity: identity, KeepAlive: time.Millisecond}, {Identity: identity, DNS: []netip.Addr{{}}}} {
		if _, err := New(context.Background(), config); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	t.Run("Close cancels pending DNS", func(t *testing.T) {
		own, err := New(context.Background(), Config{Identity: identity, DialTimeout: -1})
		if err != nil {
			t.Fatal(err)
		}
		defer own.Close()
		done := make(chan error, 1)
		go func() { _, err := own.DialContext(context.Background(), "tcp4", "silent.test:80"); done <- err }()
		time.Sleep(30 * time.Millisecond)
		closed := make(chan struct{})
		go func() { own.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("shutdown blocked on DNS")
		}
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("DNS dial stuck after shutdown")
		}
		own.mu.Lock()
		n := len(own.connections)
		own.mu.Unlock()
		if n != 0 {
			t.Fatalf("%d retained DNS connections", n)
		}
	})
	t.Run("configured timeout includes DNS", func(t *testing.T) {
		own, err := New(context.Background(), Config{Identity: identity, DialTimeout: 30 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer own.Close()
		start := time.Now()
		_, err = own.DialContext(context.Background(), "tcp4", "silent.test:80")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("DNS ignored dial timeout")
		}
	})
}
