package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/KOTBCTAKAHE/back-uniteapp/internal/network"
	"github.com/KOTBCTAKAHE/back-uniteapp/internal/protocol"
)

// Server is the UNITEAPP VPN server.
type Server struct {
	tcpPort int
	udpPort int

	ipPool *network.IPPool

	mu      sync.RWMutex
	clients map[uint32]*Client // sessionID -> client
	ipIndex map[string]*Client // virtualIP string -> client

	udpConn *net.UDPConn

	quit chan struct{}
}

// New creates a new Server.
func New(tcpPort, udpPort int) (*Server, error) {
	subnetCIDR := fmt.Sprintf("%s/%d", protocol.VirtualSubnet, protocol.VirtualSubnetCIDR)
	pool, err := network.NewIPPool(subnetCIDR, protocol.ServerVirtualIP)
	if err != nil {
		return nil, fmt.Errorf("create IP pool: %w", err)
	}

	return &Server{
		tcpPort: tcpPort,
		udpPort: udpPort,
		ipPool:  pool,
		clients: make(map[uint32]*Client),
		ipIndex: make(map[string]*Client),
		quit:    make(chan struct{}),
	}, nil
}

// Run starts the server (TCP + UDP listeners).
func (s *Server) Run() error {
	// Start UDP listener.
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", s.udpPort))
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}

	s.udpConn, err = net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer s.udpConn.Close()
	log.Printf("[UDP] Listening on :%d", s.udpPort)

	// Start TCP listener.
	tcpListener, err := net.Listen("tcp4", fmt.Sprintf(":%d", s.tcpPort))
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer tcpListener.Close()
	log.Printf("[TCP] Listening on :%d", s.tcpPort)

	log.Printf("[NET] Virtual network: %s/%d", protocol.VirtualSubnet, protocol.VirtualSubnetCIDR)
	log.Printf("[NET] Server virtual IP: %s", protocol.ServerVirtualIP)

	// Start background goroutines.
	go s.handleUDP()
	go s.keepaliveLoop()

	// Accept TCP connections.
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				log.Printf("[TCP] Accept error: %v", err)
				continue
			}
		}

		go s.handleTCPClient(conn)
	}
}

// handleTCPClient handles a new TCP connection (control plane).
func (s *Server) handleTCPClient(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[TCP] New connection from %s", remoteAddr)

	// Read HELLO packet with timeout.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		log.Printf("[TCP] Failed to read HELLO from %s: %v", remoteAddr, err)
		conn.Close()
		return
	}

	if pkt.Type != protocol.TypeHello {
		log.Printf("[TCP] Expected HELLO from %s, got type 0x%02x", remoteAddr, pkt.Type)
		errPkt := protocol.NewErrorPacket(0, protocol.ErrBadPacket, "expected HELLO")
		protocol.WritePacket(conn, errPkt)
		conn.Close()
		return
	}

	deviceName := string(pkt.Payload)
	if deviceName == "" {
		deviceName = "unknown"
	}
	if len(deviceName) > 64 {
		deviceName = deviceName[:64]
	}

	// Allocate virtual IP.
	virtualIP, err := s.ipPool.Allocate()
	if err != nil {
		log.Printf("[TCP] No IPs available for %s: %v", remoteAddr, err)
		errPkt := protocol.NewErrorPacket(0, protocol.ErrServerFull, "server full")
		protocol.WritePacket(conn, errPkt)
		conn.Close()
		return
	}

	// Generate session ID.
	sessionID := s.generateSessionID()

	// Create client.
	client := NewClient(sessionID, deviceName, virtualIP, conn)

	// Register client.
	s.mu.Lock()
	s.clients[sessionID] = client
	s.ipIndex[virtualIP.String()] = client
	s.mu.Unlock()

	log.Printf("[TCP] Client connected: %s (%s) -> %s [session=%08x]",
		deviceName, remoteAddr, virtualIP, sessionID)

	// Send WELCOME.
	var vipBytes, maskBytes, sipBytes [4]byte
	copy(vipBytes[:], virtualIP.To4())
	maskBytes = s.ipPool.SubnetMask()
	copy(sipBytes[:], net.ParseIP(protocol.ServerVirtualIP).To4())

	welcomePkt := protocol.NewWelcomePacket(sessionID, vipBytes, maskBytes, sipBytes, 1400)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WritePacket(conn, welcomePkt); err != nil {
		log.Printf("[TCP] Failed to send WELCOME to %s: %v", remoteAddr, err)
		s.removeClient(client)
		conn.Close()
		return
	}

	// Notify all clients about new peer.
	s.broadcastPeerList()

	// Handle control messages.
	conn.SetReadDeadline(time.Time{}) // Clear deadline.
	s.controlLoop(client)
}

// controlLoop reads control messages from a TCP client.
func (s *Server) controlLoop(client *Client) {
	defer func() {
		log.Printf("[TCP] Client disconnected: %s (%s) [session=%08x]",
			client.DeviceName, client.VirtualIP, client.SessionID)
		s.removeClient(client)
		client.TCPConn.Close()
		s.broadcastPeerList()
	}()

	for {
		client.TCPConn.SetReadDeadline(time.Now().Add(time.Duration(protocol.KeepaliveTimeout) * time.Second))
		pkt, err := protocol.ReadPacket(client.TCPConn)
		if err != nil {
			return
		}

		client.Touch()

		switch pkt.Type {
		case protocol.TypePing:
			pong := protocol.NewPongPacket(client.SessionID)
			client.TCPConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := protocol.WritePacket(client.TCPConn, pong); err != nil {
				return
			}

		case protocol.TypePong:
			// Client responded to our ping, nothing to do.

		case protocol.TypeDisconnect:
			return

		default:
			log.Printf("[TCP] Unexpected packet type 0x%02x from %s", pkt.Type, client.DeviceName)
		}
	}
}

// handleUDP reads UDP packets (data plane) and routes them.
func (s *Server) handleUDP() {
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[UDP] Read error: %v", err)
			continue
		}

		pkt, err := protocol.DecodePacket(buf[:n])
		if err != nil {
			continue // Drop malformed packets silently.
		}

		// Find the sending client.
		s.mu.RLock()
		sender, exists := s.clients[pkt.SessionID]
		s.mu.RUnlock()

		if !exists {
			continue // Unknown session, drop.
		}

		sender.Touch()

		// Learn or update the client's UDP address.
		if sender.GetUDPAddr() == nil || sender.GetUDPAddr().String() != remoteAddr.String() {
			sender.SetUDPAddr(remoteAddr)
			log.Printf("[UDP] Learned UDP address for %s: %s", sender.DeviceName, remoteAddr)
		}

		if pkt.Type == protocol.TypeData {
			s.routePacket(sender, pkt.Payload)
		} else if pkt.Type == protocol.TypePing {
			// Respond via UDP.
			pong := protocol.NewPongPacket(sender.SessionID)
			s.udpConn.WriteToUDP(pong.Encode(), remoteAddr)
		}
	}
}

// routePacket forwards an IP packet to the right client(s).
func (s *Server) routePacket(sender *Client, ipPacket []byte) {
	if len(ipPacket) < 20 {
		return // Too short to be an IP packet.
	}

	// Extract destination IP from the IP header.
	dstIP := net.IP(ipPacket[16:20])

	// Check if it's a broadcast.
	isBroadcast := dstIP.Equal(net.IPv4bcast) ||
		dstIP.String() == protocol.BroadcastIP ||
		dstIP[3] == 255

	if isBroadcast {
		// Forward to all clients except the sender.
		s.mu.RLock()
		for _, client := range s.clients {
			if client.SessionID != sender.SessionID {
				s.sendDataToClient(client, ipPacket)
			}
		}
		s.mu.RUnlock()
		return
	}

	// Unicast — find the destination client.
	s.mu.RLock()
	dst, exists := s.ipIndex[dstIP.String()]
	s.mu.RUnlock()

	if exists && dst.SessionID != sender.SessionID {
		s.sendDataToClient(dst, ipPacket)
	}
}

// sendDataToClient sends an IP packet to a client via UDP.
func (s *Server) sendDataToClient(client *Client, ipPacket []byte) {
	udpAddr := client.GetUDPAddr()
	if udpAddr == nil {
		return // Client hasn't sent UDP yet, can't send.
	}

	dataPkt := protocol.NewDataPacket(client.SessionID, ipPacket)
	_, err := s.udpConn.WriteToUDP(dataPkt.Encode(), udpAddr)
	if err != nil {
		log.Printf("[UDP] Send to %s failed: %v", client.DeviceName, err)
	}
}

// keepaliveLoop periodically pings clients and removes dead ones.
func (s *Server) keepaliveLoop() {
	ticker := time.NewTicker(time.Duration(protocol.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.mu.RLock()
			deadClients := make([]*Client, 0)
			for _, client := range s.clients {
				if !client.IsAlive(time.Duration(protocol.KeepaliveTimeout) * time.Second) {
					deadClients = append(deadClients, client)
				} else {
					// Send ping via TCP.
					ping := protocol.NewPingPacket(client.SessionID)
					client.TCPConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					protocol.WritePacket(client.TCPConn, ping)
				}
			}
			s.mu.RUnlock()

			for _, client := range deadClients {
				log.Printf("[TCP] Client timed out: %s (%s)", client.DeviceName, client.VirtualIP)
				client.TCPConn.Close()
				s.removeClient(client)
			}

			if len(deadClients) > 0 {
				s.broadcastPeerList()
			}
		}
	}
}

// removeClient removes a client from the server.
func (s *Server) removeClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.clients, client.SessionID)
	delete(s.ipIndex, client.VirtualIP.String())
	s.ipPool.Release(client.VirtualIP)
}

// broadcastPeerList sends the current peer list to all connected clients.
func (s *Server) broadcastPeerList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build peer list.
	peers := make([]protocol.PeerInfo, 0, len(s.clients))
	for _, client := range s.clients {
		peers = append(peers, protocol.PeerInfo{
			VirtualIP: client.VirtualIPBytes(),
			Name:      client.DeviceName,
		})
	}

	for _, client := range s.clients {
		pkt := protocol.NewPeerListPacket(client.SessionID, peers)
		client.TCPConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		protocol.WritePacket(client.TCPConn, pkt)
	}
}

// generateSessionID creates a unique random session ID.
func (s *Server) generateSessionID() uint32 {
	for {
		id := rand.Uint32()
		if id == 0 {
			continue
		}

		s.mu.RLock()
		_, exists := s.clients[id]
		s.mu.RUnlock()

		if !exists {
			return id
		}
	}
}

// GetClientCount returns the number of connected clients.
func (s *Server) GetClientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// ipToBytes converts an IP to 4-byte array.
func ipToBytes(ip net.IP) [4]byte {
	ip4 := ip.To4()
	var b [4]byte
	if ip4 != nil {
		copy(b[:], ip4)
	}
	return b
}

// init is a placeholder to suppress the unused import warning for binary.
var _ = binary.BigEndian
