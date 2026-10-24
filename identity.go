package warp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
)

// Identity contains a reusable WARP registration and its WireGuard credentials.
// PrivateKey and Token are secrets. Do not log an Identity.
// Addresses are tunnel addresses, not addresses assigned to the host OS.
type Identity struct {
	DeviceID      string       `json:"device_id,omitempty"`
	Token         string       `json:"token,omitempty"`
	PrivateKey    string       `json:"private_key"`
	PeerPublicKey string       `json:"peer_public_key"`
	Addresses     []netip.Addr `json:"addresses"`
	Endpoint      string       `json:"endpoint"`
	Reserved      [3]byte      `json:"reserved"`
}

func decodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != 32 {
		return nil, errors.New("expected a base64-encoded 32-byte key")
	}
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("key must not be all zero")
	}
	return key, nil
}

// Validate checks the tunnel credentials without contacting Cloudflare.
// DeviceID and Token are optional when supplying tunnel credentials manually.
func (i *Identity) Validate() error {
	if i == nil {
		return errors.New("warp: identity is required")
	}
	if _, err := decodeKey(i.PrivateKey); err != nil {
		return fmt.Errorf("warp: private key: %w", err)
	}
	if _, err := decodeKey(i.PeerPublicKey); err != nil {
		return fmt.Errorf("warp: peer public key: %w", err)
	}
	if len(i.Addresses) == 0 {
		return errors.New("warp: at least one tunnel address is required")
	}
	seen := make(map[netip.Addr]bool)
	for _, addr := range i.Addresses {
		if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || seen[addr] {
			return errors.New("warp: invalid or duplicate tunnel address")
		}
		seen[addr] = true
	}
	return validateEndpoint(i.Endpoint)
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return errors.New("warp: endpoint must be host:port")
	}
	// ParseAddrPort checks the numeric port without resolving the hostname.
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return errors.New("warp: endpoint must have a numeric port in 1..65535")
	}
	return nil
}

// LoadIdentity loads and validates a saved identity. It never registers or repairs
// an invalid file; callers should only register on errors.Is(err, os.ErrNotExist).
func LoadIdentity(path string) (*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxJSONSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJSONSize {
		return nil, errors.New("warp: identity file too large")
	}
	var i Identity
	if err := json.Unmarshal(data, &i); err != nil {
		return nil, errors.New("warp: invalid identity JSON")
	}
	if err := i.Validate(); err != nil {
		return nil, err
	}
	return &i, nil
}

// Save writes an identity atomically with mode 0600. Parent directories are
// created with mode 0700. Concurrent writers must be serialized by the caller.
func (i *Identity) Save(path string) error {
	if err := i.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".warp-identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
