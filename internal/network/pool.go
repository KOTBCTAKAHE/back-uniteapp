package network

import (
	"fmt"
	"net"
	"sync"
)

// IPPool manages virtual IP address allocation.
type IPPool struct {
	mu        sync.Mutex
	subnet    *net.IPNet
	serverIP  net.IP
	allocated map[string]bool // virtualIP -> allocated
	nextOctet byte
}

// NewIPPool creates a new IP pool for the given subnet.
// serverIP is reserved and not allocated to clients.
func NewIPPool(subnetCIDR string, serverIP string) (*IPPool, error) {
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}

	sIP := net.ParseIP(serverIP).To4()
	if sIP == nil {
		return nil, fmt.Errorf("invalid server IP: %s", serverIP)
	}

	pool := &IPPool{
		subnet:    subnet,
		serverIP:  sIP,
		allocated: make(map[string]bool),
		nextOctet: 2, // Start from .2 (server is .1)
	}

	// Reserve server IP.
	pool.allocated[serverIP] = true

	return pool, nil
}

// Allocate assigns the next available virtual IP.
func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find a free IP starting from nextOctet.
	startOctet := p.nextOctet
	for {
		ip := make(net.IP, 4)
		copy(ip, p.subnet.IP.To4())
		ip[3] = p.nextOctet

		ipStr := ip.String()

		// Skip broadcast (.255) and network (.0) addresses.
		if p.nextOctet != 0 && p.nextOctet != 255 && !p.allocated[ipStr] {
			p.allocated[ipStr] = true
			p.nextOctet++
			if p.nextOctet == 0 || p.nextOctet == 255 {
				p.nextOctet = 2
			}
			return ip, nil
		}

		p.nextOctet++
		if p.nextOctet == 0 || p.nextOctet == 255 {
			p.nextOctet = 2
		}

		if p.nextOctet == startOctet {
			return nil, fmt.Errorf("no available IP addresses")
		}
	}
}

// Release frees a virtual IP for reuse.
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.To4().String()
	if ipStr != p.serverIP.String() {
		delete(p.allocated, ipStr)
	}
}

// ServerIP returns the server's virtual IP.
func (p *IPPool) ServerIP() net.IP {
	return p.serverIP
}

// SubnetMask returns the subnet mask as 4 bytes.
func (p *IPPool) SubnetMask() [4]byte {
	mask := p.subnet.Mask
	var m [4]byte
	copy(m[:], mask)
	return m
}

// IsInSubnet checks if an IP belongs to this subnet.
func (p *IPPool) IsInSubnet(ip net.IP) bool {
	return p.subnet.Contains(ip)
}
