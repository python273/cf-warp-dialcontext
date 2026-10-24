# cf-warp-dialcontext

A Go `DialContext` implementation for proxying any TCP/UDP connections through
Cloudflare WARP.

Runs entirely in your process using WireGuard and a userspace TCP/IP stack.
Requires no root privileges, OS network interfaces, route changes, or local
proxy server. Destination DNS queries travel through the tunnel.

## Install

Requires Go 1.23.1 or newer.

```sh
go get github.com/python273/cf-warp-dialcontext
```

```go
import warp "github.com/python273/cf-warp-dialcontext"
```

## Usage

Register once and save the identity for reuse:

```go
identity, err := warp.LoadIdentity("warp-identity.json")
if errors.Is(err, os.ErrNotExist) {
    identity, err = warp.Register(ctx, warp.RegistrationOptions{})
    if err == nil {
        err = identity.Save("warp-identity.json")
    }
}
if err != nil {
    return err
}
```

Create a dialer and use it in an HTTP transport:

```go
d, err := warp.New(ctx, warp.Config{Identity: identity})
if err != nil {
    return err
}
defer d.Close()

transport := http.DefaultTransport.(*http.Transport).Clone()
transport.Proxy = nil
transport.DialContext = d.DialContext
defer transport.CloseIdleConnections()

client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
if err != nil {
    return err
}
defer resp.Body.Close()
```

The trace response should contain `warp=on`. Share one dialer across requests
and clients. TLS and application protocols are handled by the calling client.

For WebSockets, pass `d.DialContext` to your client's dial hook, such as Gorilla
WebSocket's `Dialer.NetDialContext`. For HTTP reverse proxies, assign the
transport above to `httputil.ReverseProxy.Transport`; WebSocket upgrades are
handled by Go's reverse proxy.

Runnable examples, from a checkout of this repository:

```sh
# Register if needed, save the identity, and make an HTTPS request.
go run ./examples/http

# Proxy HTTP and WebSocket upgrades using the saved identity.
go run ./examples/reverseproxy -upstream https://example.com
```

The reverse proxy listens on `127.0.0.1:8080` by default.

## Configuration

```go
d, err := warp.New(ctx, warp.Config{
    Identity:    identity,
    DNS:         []netip.Addr{netip.MustParseAddr("1.1.1.1")},
    MTU:         1280,
    DialTimeout: 15 * time.Second,
    KeepAlive:   25 * time.Second,
})
```

| Option | Default | Description |
| --- | --- | --- |
| `Identity` | Required | Saved registration or manually supplied tunnel credentials. |
| `Endpoint` | Registered endpoint | Optional `host:port` override. |
| `DNS` | `1.1.1.1` | DNS server IPs reached through WARP; rotated across resolver attempts. |
| `MTU` | `1280` | Tunnel MTU, in `1280..65535`. |
| `DialTimeout` | 30 seconds | Covers DNS and connection establishment; a negative value disables the limit. |
| `KeepAlive` | Disabled | WireGuard keepalive interval; whole seconds in `1..65535` when enabled. |

DNS servers must match a configured tunnel address family. The Go resolver's
host settings still control search domains and retry timing. Endpoint hostnames
use the host resolver during initialization; a numeric endpoint avoids this
bootstrap lookup.

`RegistrationOptions` supports a custom `HTTPClient`, versioned `BaseURL`,
`UserAgent`, `ClientVersion`, and device `Model`. Registration uses the unofficial
consumer WARP API, submits a terms-of-service timestamp, rejects redirects, and
does not retry POST requests automatically.

`Identity.Save` writes credentials atomically with mode `0600`, creating parent
directories with mode `0700`. Keep the private key and API token out of logs and
version control. Only register when the identity file is missing; report other
load errors rather than replacing the file.

Existing credentials can be supplied directly in `Identity`: base64 private key,
peer public key, tunnel IP addresses, endpoint, and the three reserved bytes
from the base64-decoded WARP `client_id`. `DeviceID` and `Token` are optional for
this use. `New` makes no registration API calls.

## Cancellation and cleanup

- `New`'s context controls initialization. Call `Close` to shut down the tunnel.
  The WireGuard handshake starts on first traffic.
- `DialContext` accepts `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, and `udp6`, with
  `host:numeric-port` addresses. TCP uses a 250 ms address-family fallback delay.
- A dial context controls DNS and connection establishment. As with `net.Dialer`,
  canceling it after a successful dial does not close the connection. HTTP
  transports handle request cancellation; raw clients should close connections
  or set deadlines. TCP half-close is available through `CloseRead`/`CloseWrite`
  interface assertions.
- `Close` cancels pending dials and DNS queries, closes active connections, and
  releases the tunnel and UDP sockets. It is safe to call concurrently and
  repeatedly. Subsequent dials return an error wrapping `net.ErrClosed`.

`Dialer` is safe for concurrent use. Construct it with `New` and do not copy it.

## Dependencies and scope

The only direct dependency is upstream
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/). Its `tun/netstack` package
uses gVisor to provide TCP/IP without OS interfaces. The WireGuard implementation
is unmodified; a small transport adapter handles WARP's reserved header bytes.

Supports consumer WARP over WireGuard. MASQUE, Zero Trust enrollment, WARP+
account management, endpoint scanning, and automatic endpoint failover are not
implemented. UDP is exposed as connected `net.Conn`, without a `net.PacketConn`
API. Failed tunnel connections never fall back to a direct connection.

The registration API may change. A successful registration or constructor does
not verify connectivity; test a request through the tunnel before treating it
as ready.

## Tests

```sh
go test -race ./...
go vet ./...
```

Tests use a local userspace WireGuard peer and mock registration endpoints,
with no public network access. They cover HTTP, HTTPS, WebSocket upgrades,
IPv6, UDP, DNS, half-close, cancellation, persistence, and concurrent shutdown.

## License

MIT. Not affiliated with Cloudflare.
