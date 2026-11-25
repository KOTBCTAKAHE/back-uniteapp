package protocol

// UNITEAPP Protocol (UAP) — custom minimalist VPN protocol.
//
// Packet format (binary, big-endian):
//   [Magic: 2 bytes "UA"]
//   [Version: 1 byte]
//   [Type: 1 byte]
//   [SessionID: 4 bytes]
//   [PayloadLength: 2 bytes]
//   [Payload: variable]
//
// Control plane: TCP (reliable handshake, keepalive, disconnect)
// Data plane: UDP (low-latency IP packet forwarding)

const (
	// Magic bytes identifying UNITEAPP packets.
	MagicByte0 byte = 'U'
	MagicByte1 byte = 'A'

	// Protocol version.
	ProtocolVersion byte = 1

	// Header size: magic(2) + version(1) + type(1) + sessionID(4) + payloadLen(2) = 10.
	HeaderSize = 10

	// Maximum payload size (64KB - header).
	MaxPayloadSize = 65525

	// Default server ports.
	DefaultTCPPort = 7655
	DefaultUDPPort = 7655

	// Keepalive interval and timeout.
	KeepaliveInterval = 10 // seconds
	KeepaliveTimeout  = 30 // seconds

	// Virtual network settings.
	VirtualSubnet     = "10.10.0.0"
	VirtualSubnetMask = "255.255.255.0"
	VirtualSubnetCIDR = 24
	ServerVirtualIP   = "10.10.0.1"
	FirstClientIP     = "10.10.0.2"
	LastClientIP      = "10.10.0.254"
	BroadcastIP       = "10.10.0.255"
)

// Packet types.
const (
	// Client → Server: initial handshake. Payload: device name (UTF-8).
	TypeHello byte = 0x01

	// Server → Client: handshake response.
	// Payload: virtualIP(4) + subnetMask(4) + serverVirtualIP(4) + mtu(2).
	TypeWelcome byte = 0x02

	// Bidirectional: encapsulated IP packet. Payload: raw IP packet.
	TypeData byte = 0x03

	// Bidirectional: keepalive ping.
	TypePing byte = 0x04

	// Bidirectional: keepalive pong.
	TypePong byte = 0x05

	// Client → Server: clean disconnect.
	TypeDisconnect byte = 0x06

	// Server → Client: list of connected peers.
	// Payload: count(1) + [virtualIP(4) + nameLen(1) + name(variable)] * count.
	TypePeerList byte = 0x07

	// Server → Client: error message.
	// Payload: error code(1) + message (UTF-8).
	TypeError byte = 0xFF
)

// Error codes sent in TypeError packets.
const (
	ErrServerFull    byte = 0x01
	ErrBadPacket     byte = 0x02
	ErrBadVersion    byte = 0x03
	ErrSessionExists byte = 0x04
)
