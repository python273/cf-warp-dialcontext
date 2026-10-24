package warp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (private, public string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}
func testIdentity(t *testing.T) *Identity {
	private, _ := testKey(t)
	_, public := testKey(t)
	return &Identity{PrivateKey: private, PeerPublicKey: public, Addresses: []netip.Addr{netip.MustParseAddr("10.77.0.2")}, Endpoint: "127.0.0.1:2408", Reserved: [3]byte{7, 8, 9}}
}
func registrationResponse(t *testing.T, key string) map[string]any {
	t.Helper()
	_, peer := testKey(t)
	return map[string]any{
		"id": "test-device", "token": "secret-token", "key": key, "tunnel_type": "wireguard",
		"config": map[string]any{
			"client_id": "BwgJ", "interface": map[string]any{"addresses": map[string]string{"v4": "10.77.0.2/32", "v6": "fd77::2"}},
			"peers": []any{map[string]any{"public_key": peer, "endpoint": map[string]any{"v4": "127.0.0.1", "ports": []int{2408}}}},
		},
	}
}
func TestRegisterAndPersist(t *testing.T) {
	var sentKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/reg" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("CF-Client-Version") == "" {
			t.Error("missing client version")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		sentKey, _ = body["key"].(string)
		if body["key_type"] != "curve25519" || body["tunnel_type"] != "wireguard" {
			t.Error("wrong key/tunnel type")
		}
		if _, err := time.Parse(time.RFC3339Nano, body["tos"].(string)); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(registrationResponse(t, sentKey))
	}))
	defer server.Close()
	identity, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	private, err := decodeKey(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()); got != sentKey {
		t.Fatal("private key does not match registered public key")
	}
	if identity.Endpoint != "127.0.0.1:2408" || identity.Reserved != [3]byte{7, 8, 9} || len(identity.Addresses) != 2 {
		t.Fatalf("wrong parsed identity configuration")
	}
	path := filepath.Join(t.TempDir(), "state", "identity.json")
	if err := identity.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("identity permissions: %o", info.Mode().Perm())
	}
	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PrivateKey != identity.PrivateKey || loaded.Token != identity.Token {
		t.Fatal("credentials did not round trip")
	}
	// Replacing an existing permissive file also replaces its permissions.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Save(path); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("overwrite retained permissive file mode")
	}
}
func TestRegisterRefreshAndValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"valid", func(map[string]any) {}, ""},
		{"wrong key", func(m map[string]any) { m["key"] = "wrong" }, "public key mismatch"},
		{"wrong tunnel", func(m map[string]any) { m["tunnel_type"] = "masque" }, "WireGuard tunnel"},
		{"missing token", func(m map[string]any) { delete(m, "token") }, "missing device ID or token"},
		{"bad reserved", func(m map[string]any) { m["config"].(map[string]any)["client_id"] = "AA==" }, "client ID"},
		{"missing peer", func(m map[string]any) { m["config"].(map[string]any)["peers"] = []any{} }, "missing WireGuard peer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if r.Method == "POST" {
					json.NewDecoder(r.Body).Decode(&body)
				}
				key, _ := body["key"].(string)
				m := registrationResponse(t, key)
				tt.mutate(m)
				json.NewEncoder(w).Encode(m)
			}))
			defer server.Close()
			_, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL})
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
	t.Run("refresh", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				fmt.Fprint(w, `{"id":"test-device","token":"secret-token"}`)
			case "GET":
				if r.URL.Path != "/reg/test-device" || r.Header.Get("Authorization") != "Bearer secret-token" {
					t.Error("wrong refresh request")
				}
				json.NewEncoder(w).Encode(registrationResponse(t, ""))
			}
		}))
		defer server.Close()
		if _, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL}); err != nil {
			t.Fatal(err)
		}
	})
}
func TestRegistrationErrorsAndCancellation(t *testing.T) {
	t.Run("status redacts secrets", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429); fmt.Fprint(w, "super-secret-token") }))
		defer server.Close()
		_, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 429 || strings.Contains(err.Error(), "super-secret") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("redirect is not followed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", 307) }))
		defer server.Close()
		_, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 307 {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("canceled request", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release }))
		defer server.Close()
		defer close(release)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := Register(ctx, RegistrationOptions{BaseURL: server.URL}); done <- err }()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("registration did not cancel")
		}
	})
	t.Run("oversized response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat(" ", maxJSONSize+1)) }))
		defer server.Close()
		_, err := Register(context.Background(), RegistrationOptions{BaseURL: server.URL})
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatal(err)
		}
	})
}
func TestIdentityValidationAndCorruption(t *testing.T) {
	i := testIdentity(t)
	tests := []struct {
		name   string
		change func(*Identity)
	}{
		{"bad private", func(i *Identity) { i.PrivateKey = "secret-not-a-key" }},
		{"zero public", func(i *Identity) { i.PeerPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"empty addresses", func(i *Identity) { i.Addresses = nil }},
		{"bad address", func(i *Identity) { i.Addresses = []netip.Addr{{}} }},
		{"bad endpoint", func(i *Identity) { i.Endpoint = "hostname:abc" }},
		{"zero port", func(i *Identity) { i.Endpoint = "hostname:0" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := *i
			tt.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected invalid identity")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte("broken-secret-json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentity(path)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("invalid file error must not expose file contents")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "broken-secret-json" {
		t.Fatal("load modified corrupt identity")
	}
}
