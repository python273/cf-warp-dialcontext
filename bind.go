package warp

import (
	"golang.zx2c4.com/wireguard/conn"
)

// WARP puts its three-byte client ID in WireGuard's reserved header bytes.
// Adapt the transport boundary so the upstream WireGuard implementation can
// remain unmodified. The underlying Bind consumes sends synchronously.
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, packet := range bufs {
		if len(packet) >= 4 {
			copy(packet[1:4], b.reserved[:])
		}
	}
	defer func() {
		for _, packet := range bufs {
			if len(packet) >= 4 {
				clear(packet[1:4])
			}
		}
	}()
	return b.Bind.Send(bufs, ep)
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, receive := range fns {
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					clear(packets[j][1:4])
				}
			}
			return n, err
		}
	}
	return wrapped, actual, nil
}
