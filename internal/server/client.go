package server

import (
	"net"
	"sync"
	"time"
)

// Client represents a connected VPN client.
type Client struct {
	mu sync.RWMutex

	SessionID  uint32
	DeviceName string
	VirtualIP  net.IP

	// TCP connection for control plane.
	TCPConn net.Conn

	// UDP address for data plane.
	UDPAddr *net.UDPAddr

	// Timestamps.
	ConnectedAt time.Time
	LastSeen    time.Time
}

// NewClient creates a new client session.
func NewClient(sessionID uint32, deviceName string, virtualIP net.IP, tcpConn net.Conn) *Client {
	now := time.Now()
	return &Client{
		SessionID:   sessionID,
		DeviceName:  deviceName,
		VirtualIP:   virtualIP,
		TCPConn:     tcpConn,
		ConnectedAt: now,
		LastSeen:    now,
	}
}

// SetUDPAddr sets the client's UDP address (learned from the first UDP packet).
func (c *Client) SetUDPAddr(addr *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UDPAddr = addr
}

// GetUDPAddr returns the client's UDP address.
func (c *Client) GetUDPAddr() *net.UDPAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UDPAddr
}

// Touch updates the last-seen timestamp.
func (c *Client) Touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastSeen = time.Now()
}

// IsAlive checks if the client has been seen within the timeout.
func (c *Client) IsAlive(timeout time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.LastSeen) < timeout
}

// VirtualIPBytes returns the virtual IP as a 4-byte array.
func (c *Client) VirtualIPBytes() [4]byte {
	ip := c.VirtualIP.To4()
	var b [4]byte
	copy(b[:], ip)
	return b
}
