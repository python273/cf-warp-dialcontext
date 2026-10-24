// Package warp provides an in-process Cloudflare WARP dialer for TCP and UDP.
// It uses userspace WireGuard and TCP/IP; no OS interface or route is created.
package warp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config configures a tunnel. New snapshots the supplied identity and slices.
type Config struct {
	Identity *Identity
	// Endpoint optionally overrides the registered endpoint (host:port).
	// Endpoint hostname resolution uses the host resolver during New only.
	Endpoint string
	// DNS servers are IP addresses reached inside the tunnel. Default: 1.1.1.1.
	DNS []netip.Addr
	// MTU defaults to 1280. Valid range: 1280..65535.
	MTU int
	// DialTimeout includes DNS and connection establishment. Default: 30 seconds.
	// A negative value disables the default limit; the caller's context still applies.
	DialTimeout time.Duration
	// KeepAlive is the WireGuard persistent keepalive interval. Zero disables it.
	// When set, it must be a whole number of seconds in 1..65535.
	KeepAlive time.Duration
}

// Dialer owns one tunnel and all of its connections. It is safe for concurrent
// use. Always call Close. A Dialer must be constructed with New, not copied.
type Dialer struct {
	network     *netstack.Net
	device      *device.Device
	resolver    *net.Resolver
	timeout     time.Duration
	has4, has6  bool
	life        context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
	pending     sync.WaitGroup
	closeOnce   sync.Once
	dnsNext     atomic.Uint64
}

// New starts a userspace tunnel. ctx controls initialization only; Close controls
// the tunnel's lifetime. A successful New does not imply a successful handshake:
// WireGuard initiates one when the first packet is sent.
func New(ctx context.Context, config Config) (*Dialer, error) {
	if ctx == nil {
		panic("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.Identity.Validate(); err != nil {
		return nil, err
	}
	identity := *config.Identity
	identity.Addresses = append([]netip.Addr(nil), identity.Addresses...)
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = identity.Endpoint
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if config.MTU == 0 {
		config.MTU = 1280
	}
	if config.MTU < 1280 || config.MTU > 65535 {
		return nil, errors.New("warp: MTU must be in 1280..65535")
	}
	if config.KeepAlive < 0 || config.KeepAlive > 65535*time.Second || config.KeepAlive%time.Second != 0 {
		return nil, errors.New("warp: keepalive must be whole seconds in 0..65535")
	}
	dns := append([]netip.Addr(nil), config.DNS...)
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	has4, has6 := false, false
	for _, addr := range identity.Addresses {
		has4 = has4 || addr.Is4()
		has6 = has6 || addr.Is6()
	}
	for _, addr := range dns {
		if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || (addr.Is4() && !has4) || (addr.Is6() && !has6) {
			return nil, errors.New("warp: DNS server must be a usable IP in a configured tunnel address family")
		}
	}
	resolved, err := resolveEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	tun, stack, err := netstack.CreateNetTUN(identity.Addresses, nil, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("warp: create netstack: %w", err)
	}
	bind := &reservedBind{Bind: conn.NewDefaultBind(), reserved: identity.Reserved}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	private, _ := decodeKey(identity.PrivateKey)
	public, _ := decodeKey(identity.PeerPublicKey)
	settings := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%d\n", hex.EncodeToString(private), hex.EncodeToString(public), resolved, config.KeepAlive/time.Second)
	if err := dev.IpcSet(settings); err != nil {
		dev.Close()
		return nil, errors.New("warp: configure WireGuard device failed")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: start WireGuard: %w", err)
	}
	if err := ctx.Err(); err != nil {
		dev.Close()
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	timeout := config.DialTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	d := &Dialer{network: stack, device: dev, timeout: timeout, has4: has4, has6: has6,
		life: life, cancel: cancel, connections: make(map[*trackedConn]struct{})}
	d.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.dialDNS(ctx, network, dns)
	}}
	return d, nil
}

func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	host, port, _ := net.SplitHostPort(endpoint)
	p, _ := strconv.ParseUint(port, 10, 16)
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr, uint16(p)), nil
	}
	// Bootstrap DNS is outside the tunnel. Destination DNS never uses this path.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("warp: resolve endpoint: %w", err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, errors.New("warp: no endpoint addresses")
	}
	for _, addr := range addrs {
		if addr.Is4() {
			return netip.AddrPortFrom(addr, uint16(p)), nil
		}
	}
	return netip.AddrPortFrom(addrs[0], uint16(p)), nil
}

func (d *Dialer) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.pending.Add(1)
	return true
}

// DialContext opens a tunnel connection. Supported networks are tcp, tcp4, tcp6,
// udp, udp4 and udp6. address is host:port with a numeric port. DNS goes through
// WARP. For TCP, IPv4/IPv6 attempts use a 250ms fallback delay.
// As with net.Dialer, ctx controls establishment, not the returned connection's
// lifetime. Use Close or deadlines to interrupt established I/O.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	opErr := func(err error) (net.Conn, error) { return nil, &net.OpError{Op: "dial", Net: network, Err: err} }
	if !d.begin() {
		return opErr(net.ErrClosed)
	}
	defer d.pending.Done()
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.life, cancel)
	defer stop()
	defer cancel()
	if d.timeout > 0 {
		var cancelTimeout context.CancelFunc
		dialCtx, cancelTimeout = context.WithTimeout(dialCtx, d.timeout)
		defer cancelTimeout()
	}
	if err := dialCtx.Err(); err != nil {
		return opErr(d.dialError(ctx, dialCtx, err))
	}
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return opErr(net.UnknownNetworkError(network))
	}
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return opErr(err)
	}
	port, err := strconv.ParseUint(sport, 10, 16)
	if err != nil || host == "" {
		return opErr(errors.New("warp: address must be host:numeric-port"))
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		lookupNetwork := "ip"
		if strings.HasSuffix(network, "4") || !d.has6 {
			lookupNetwork = "ip4"
		}
		if strings.HasSuffix(network, "6") || !d.has4 {
			lookupNetwork = "ip6"
		}
		ips, err = d.resolver.LookupNetIP(dialCtx, lookupNetwork, host)
		if err != nil {
			return opErr(d.dialError(ctx, dialCtx, err))
		}
	}
	var addresses []netip.AddrPort
	for _, ip := range ips {
		if ip.Zone() != "" || (ip.Is4() && (!d.has4 || strings.HasSuffix(network, "6"))) || (ip.Is6() && (!d.has6 || strings.HasSuffix(network, "4"))) {
			continue
		}
		addresses = append(addresses, netip.AddrPortFrom(ip, uint16(port)))
	}
	if len(addresses) == 0 {
		return opErr(errors.New("warp: no addresses in requested family"))
	}
	var raw net.Conn
	if strings.HasPrefix(network, "tcp") {
		raw, err = d.dialTCP(dialCtx, addresses)
	} else {
		raw, err = d.network.DialUDPAddrPort(netip.AddrPort{}, addresses[0])
	}
	if err != nil {
		return opErr(d.dialError(ctx, dialCtx, err))
	}
	if err := dialCtx.Err(); err != nil {
		raw.Close()
		return opErr(d.dialError(ctx, dialCtx, err))
	}
	c, err := d.track(raw)
	if err != nil {
		return opErr(err)
	}
	return c, nil
}

func (d *Dialer) dialError(caller, attempt context.Context, err error) error {
	if d.life.Err() != nil {
		return net.ErrClosed
	}
	if caller.Err() != nil {
		return caller.Err()
	}
	if attempt.Err() != nil {
		return attempt.Err()
	}
	return err
}

// dialTCP races address families, cancels and joins the losing attempt, and
// closes any connection that wins concurrently with cancellation.
func (d *Dialer) dialTCP(ctx context.Context, addresses []netip.AddrPort) (net.Conn, error) {
	var first, fallback []netip.AddrPort
	for _, addr := range addresses {
		if addr.Addr().Is4() == addresses[0].Addr().Is4() {
			first = append(first, addr)
		} else {
			fallback = append(fallback, addr)
		}
	}
	if len(fallback) == 0 {
		return d.dialSerial(ctx, first)
	}
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	start := func(addrs []netip.AddrPort) {
		wg.Add(1)
		go func() { defer wg.Done(); c, err := d.dialSerial(ctx, addrs); results <- result{c, err} }()
	}
	defer func() {
		cancel()
		wg.Wait()
		close(results)
		for r := range results {
			if r.c != nil {
				r.c.Close()
			}
		}
	}()
	start(first)
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case r := <-results:
		if r.err == nil {
			return r.c, nil
		}
		return d.dialSerial(ctx, fallback)
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	start(fallback)
	var firstErr error
	for n := 0; n < 2; n++ {
		select {
		case r := <-results:
			if r.err == nil {
				return r.c, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, firstErr
}

func (d *Dialer) dialSerial(ctx context.Context, addresses []netip.AddrPort) (net.Conn, error) {
	var firstErr error
	for i, addr := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			budget := time.Until(deadline) / time.Duration(len(addresses)-i)
			if budget < 2*time.Second {
				budget = 2 * time.Second
			}
			attempt, cancel = context.WithTimeout(ctx, budget)
		}
		c, err := d.network.DialContextTCPAddrPort(attempt, addr)
		cancel()
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func (d *Dialer) dialDNS(ctx context.Context, network string, servers []netip.Addr) (net.Conn, error) {
	if !d.begin() {
		return nil, net.ErrClosed
	}
	defer d.pending.Done()
	ctx, cancel := context.WithCancel(ctx)
	stopLife := context.AfterFunc(d.life, cancel)
	// Keep this context alive until the resolver closes the connection.
	var lastErr error
	// Rotate on each resolver attempt so an unresponsive UDP DNS server does
	// not pin every retry to the first configured address.
	start := int((d.dnsNext.Add(1) - 1) % uint64(len(servers)))
	for n := range servers {
		ip := servers[(start+n)%len(servers)]
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		var raw net.Conn
		var err error
		address := netip.AddrPortFrom(ip, 53)
		if strings.HasPrefix(network, "tcp") {
			raw, err = d.network.DialContextTCPAddrPort(ctx, address)
		} else {
			raw, err = d.network.DialUDPAddrPort(netip.AddrPort{}, address)
		}
		if err != nil {
			lastErr = err
			continue
		}
		c, err := d.track(raw)
		if err != nil {
			lastErr = err
			break
		}
		stop := context.AfterFunc(ctx, func() { c.Close() })
		result := &dnsConn{trackedConn: c, stop: func() { stop(); stopLife(); cancel() }}
		// net.Resolver uses this interface to select datagram DNS framing.
		// Hiding PacketConn behind a net.Conn wrapper would make it send TCP
		// length prefixes over UDP.
		if packet, ok := raw.(net.PacketConn); ok {
			return &dnsPacketConn{dnsConn: result, packet: packet}, nil
		}
		return result, nil
	}
	stopLife()
	cancel()
	return nil, lastErr
}

func (d *Dialer) track(raw net.Conn) (*trackedConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		raw.Close()
		return nil, net.ErrClosed
	}
	c := &trackedConn{Conn: raw, owner: d}
	d.connections[c] = struct{}{}
	return c, nil
}

// Close cancels pending dials and DNS, closes established connections and the
// WireGuard device (including its UDP sockets and userspace stack), and waits for
// active dial calls. It is idempotent. New dials fail with net.ErrClosed.
func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.cancel()
		connections := make([]*trackedConn, 0, len(d.connections))
		for c := range d.connections {
			connections = append(connections, c)
		}
		d.mu.Unlock()
		for _, c := range connections {
			c.Close()
		}
		d.pending.Wait()
		d.device.Close()
	})
	return nil
}

type trackedConn struct {
	net.Conn
	owner    *Dialer
	once     sync.Once
	closeErr error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.closeErr
}

// CloseWrite supports TCP half-close when the underlying connection supports it.
func (c *trackedConn) CloseWrite() error {
	if tcp, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return tcp.CloseWrite()
	}
	return errors.New("warp: connection does not support CloseWrite")
}

// CloseRead closes the read side of a TCP connection.
func (c *trackedConn) CloseRead() error {
	if tcp, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return tcp.CloseRead()
	}
	return errors.New("warp: connection does not support CloseRead")
}

type dnsConn struct {
	*trackedConn
	stop func()
}

func (c *dnsConn) Close() error { c.stop(); return c.trackedConn.Close() }

type dnsPacketConn struct {
	*dnsConn
	packet net.PacketConn
}

func (c *dnsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(p)
}

func (c *dnsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(p, addr)
}
