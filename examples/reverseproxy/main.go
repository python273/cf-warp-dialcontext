// Proxies HTTP and WebSocket upgrades to one upstream through WARP.
// First create an identity with the HTTP example, then run:
// go run ./examples/reverseproxy -upstream https://example.com
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"time"

	warp "github.com/python273/cf-warp-dialcontext"
)

func main() {
	identityPath := flag.String("identity", "warp-identity.json", "existing saved WARP identity")
	listen := flag.String("listen", "127.0.0.1:8080", "local proxy listen address")
	upstream := flag.String("upstream", "", "upstream HTTP(S) URL; WebSocket upgrades are supported")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, *identityPath, *listen, *upstream)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, identityPath, listen, upstream string) error {
	target, err := url.Parse(upstream)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return errors.New("-upstream must be an http:// or https:// URL")
	}
	identity, err := warp.LoadIdentity(identityPath)
	if err != nil {
		return err
	}
	d, err := warp.New(ctx, warp.Config{Identity: identity})
	if err != nil {
		return err
	}
	defer d.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = d.DialContext
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(req *httputil.ProxyRequest) { req.SetURL(target) },
		Transport: transport,
	}
	server := &http.Server{Addr: listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	stop := context.AfterFunc(ctx, func() { d.Close(); server.Close() })
	defer stop()
	fmt.Fprintln(os.Stderr, "Listening on", listen)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
