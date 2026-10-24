package warp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxJSONSize = 1 << 20

// RegistrationOptions configures the unofficial consumer WARP registration API.
// A zero value uses the public API and a 30-second HTTP client timeout.
// Registration records the current time in the API's terms-of-service field.
type RegistrationOptions struct {
	HTTPClient *http.Client
	// BaseURL includes the API version. Override for testing or API changes.
	BaseURL       string
	UserAgent     string
	ClientVersion string
	Model         string
}

// APIError reports an unsuccessful registration request. Response bodies are
// deliberately excluded because they may contain credentials.
type APIError struct {
	StatusCode int
	Status     string
}

func (e *APIError) Error() string { return "warp: registration API: " + e.Status }

type apiRegistration struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	Key        string `json:"key"`
	TunnelType string `json:"tunnel_type"`
	Config     struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host  string   `json:"host"`
				V4    string   `json:"v4"`
				V6    string   `json:"v6"`
				Ports []uint16 `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// Register creates one WARP device with a freshly generated X25519 key.
// Save and reuse the result instead of registering on every application start.
// No automatic retries are made: POST registration is not idempotent.
func Register(ctx context.Context, opts RegistrationOptions) (*Identity, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("warp: generate key: %w", err)
	}
	// Match WireGuard's canonical private key representation.
	private := key.Bytes()
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	key, err = ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	pub := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if opts.BaseURL == "" {
		opts.BaseURL = "https://api.cloudflareclient.com/v0a5641"
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, errors.New("warp: invalid registration base URL")
	}
	if opts.Model == "" {
		opts.Model = "PC"
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
	}
	if opts.ClientVersion == "" {
		opts.ClientVersion = "a-6.38.9-5641"
	}
	payload, err := json.Marshal(map[string]any{
		"key": pub, "key_type": "curve25519", "tunnel_type": "wireguard",
		"tos": time.Now().UTC().Format(time.RFC3339Nano), "type": "Android", "model": opts.Model,
		"locale": "en_US", "os_version": "16.0.0", "warp_enabled": true,
		"install_id": "", "fcm_token": "", "serial_number": "",
	})
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	// Never forward the generated key or bearer token to a redirect destination.
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(method, path, token string, body []byte, result any) error {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(opts.BaseURL, "/")+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("User-Agent", opts.UserAgent)
		req.Header.Set("CF-Client-Version", opts.ClientVersion)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := clientCopy.Do(req)
		if err != nil {
			return fmt.Errorf("warp: registration request: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &APIError{resp.StatusCode, resp.Status}
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONSize+1))
		if err != nil {
			return fmt.Errorf("warp: read registration response: %w", err)
		}
		if len(data) > maxJSONSize {
			return errors.New("warp: registration response too large")
		}
		if err := json.Unmarshal(data, result); err != nil {
			return errors.New("warp: invalid registration JSON")
		}
		return nil
	}
	var response apiRegistration
	if err := request(http.MethodPost, "/reg", "", payload, &response); err != nil {
		return nil, err
	}
	if response.ID == "" || response.Token == "" {
		return nil, errors.New("warp: registration response missing device ID or token")
	}
	if len(response.Config.Peers) == 0 {
		var refreshed apiRegistration
		if err := request(http.MethodGet, "/reg/"+url.PathEscape(response.ID), response.Token, nil, &refreshed); err != nil {
			return nil, err
		}
		response.Config = refreshed.Config
		if refreshed.Key != "" && refreshed.Key != pub {
			return nil, errors.New("warp: registration public key mismatch")
		}
		if refreshed.TunnelType != "" {
			response.TunnelType = refreshed.TunnelType
		}
	}
	if response.TunnelType != "" && response.TunnelType != "wireguard" {
		return nil, errors.New("warp: registration did not return a WireGuard tunnel")
	}
	if response.Key != "" && response.Key != pub {
		return nil, errors.New("warp: registration public key mismatch")
	}
	if len(response.Config.Peers) == 0 {
		return nil, errors.New("warp: registration response missing WireGuard peer")
	}
	reserved, err := base64.StdEncoding.DecodeString(response.Config.ClientID)
	if err != nil || len(reserved) != 3 {
		return nil, errors.New("warp: invalid registration client ID")
	}
	peer := response.Config.Peers[0]
	endpoint := peer.Endpoint.Host
	if endpoint == "" {
		endpoint = peer.Endpoint.V4
	}
	if endpoint == "" {
		endpoint = peer.Endpoint.V6
	}
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		port := uint16(2408)
		if len(peer.Endpoint.Ports) != 0 {
			port = peer.Endpoint.Ports[0]
		}
		endpoint = net.JoinHostPort(endpoint, strconv.Itoa(int(port)))
	}
	identity := &Identity{DeviceID: response.ID, Token: response.Token,
		PrivateKey: base64.StdEncoding.EncodeToString(private), PeerPublicKey: peer.PublicKey, Endpoint: endpoint,
		Reserved: [3]byte(reserved),
	}
	for _, s := range []string{response.Config.Interface.Addresses.V4, response.Config.Interface.Addresses.V6} {
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			prefix, prefixErr := netip.ParsePrefix(s)
			if prefixErr != nil {
				return nil, errors.New("warp: invalid registration tunnel address")
			}
			addr = prefix.Addr()
		}
		identity.Addresses = append(identity.Addresses, addr)
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	return identity, nil
}
