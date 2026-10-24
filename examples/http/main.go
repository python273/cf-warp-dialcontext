// Run from the repository root:
// go run ./examples/http -identity ./warp-identity.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	warp "github.com/python273/cf-warp-dialcontext"
)

func main() {
	path := flag.String("identity", "warp-identity.json", "saved WARP identity (created if absent)")
	target := flag.String("url", "https://www.cloudflare.com/cdn-cgi/trace", "URL to request through WARP")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *path, *target); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, path, target string) error {
	identity, err := warp.LoadIdentity(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "Registering a WARP identity...")
		registrationCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		identity, err = warp.Register(registrationCtx, warp.RegistrationOptions{})
		cancel()
		if err != nil {
			return err
		}
		if err = identity.Save(path); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Saved identity to", path)
	} else if err != nil {
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
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request: %s", resp.Status)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}
