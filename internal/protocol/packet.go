package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidMagic   = errors.New("invalid magic bytes")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrPayloadTooLong = errors.New("payload exceeds maximum size")
	ErrShortRead      = errors.New("short read")
)

// Packet represents a UNITEAPP protocol packet.
type Packet struct {
	Type      byte
	SessionID uint32
	Payload   []byte
}

// Encode serializes a Packet into binary form.
func (p *Packet) Encode() []byte {
	payloadLen := len(p.Payload)
	buf := make([]byte, HeaderSize+payloadLen)

	buf[0] = MagicByte0
	buf[1] = MagicByte1
	buf[2] = ProtocolVersion
	buf[3] = p.Type
	binary.BigEndian.PutUint32(buf[4:8], p.SessionID)
	binary.BigEndian.PutUint16(buf[8:10], uint16(payloadLen))

	if payloadLen > 0 {
		copy(buf[HeaderSize:], p.Payload)
	}

	return buf
}

// DecodePacket reads a Packet from a byte slice (for UDP).
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrShortRead
	}

	if data[0] != MagicByte0 || data[1] != MagicByte1 {
		return nil, ErrInvalidMagic
	}

	if data[2] != ProtocolVersion {
		return nil, ErrInvalidVersion
	}

	payloadLen := int(binary.BigEndian.Uint16(data[8:10]))
	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooLong
	}

	if len(data) < HeaderSize+payloadLen {
		return nil, ErrShortRead
	}

	p := &Packet{
		Type:      data[3],
		SessionID: binary.BigEndian.Uint32(data[4:8]),
	}

	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[HeaderSize:HeaderSize+payloadLen])
	}

	return p, nil
}

// ReadPacket reads a single Packet from a TCP stream.
func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	if header[0] != MagicByte0 || header[1] != MagicByte1 {
		return nil, ErrInvalidMagic
	}

	if header[2] != ProtocolVersion {
		return nil, ErrInvalidVersion
	}

	payloadLen := int(binary.BigEndian.Uint16(header[8:10]))
	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooLong
	}

	p := &Packet{
		Type:      header[3],
		SessionID: binary.BigEndian.Uint32(header[4:8]),
	}

	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, p.Payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return p, nil
}

// WritePacket writes a Packet to a TCP stream.
func WritePacket(w io.Writer, p *Packet) error {
	data := p.Encode()
	_, err := w.Write(data)
	return err
}

// NewHelloPacket creates a HELLO packet with device name.
func NewHelloPacket(deviceName string) *Packet {
	return &Packet{
		Type:    TypeHello,
		Payload: []byte(deviceName),
	}
}

// NewWelcomePacket creates a WELCOME packet with network config.
func NewWelcomePacket(sessionID uint32, virtualIP, subnetMask, serverIP [4]byte, mtu uint16) *Packet {
	payload := make([]byte, 14)
	copy(payload[0:4], virtualIP[:])
	copy(payload[4:8], subnetMask[:])
	copy(payload[8:12], serverIP[:])
	binary.BigEndian.PutUint16(payload[12:14], mtu)

	return &Packet{
		Type:      TypeWelcome,
		SessionID: sessionID,
		Payload:   payload,
	}
}

// ParseWelcomePayload extracts fields from a WELCOME payload.
func ParseWelcomePayload(payload []byte) (virtualIP, subnetMask, serverIP [4]byte, mtu uint16, err error) {
	if len(payload) < 14 {
		err = ErrShortRead
		return
	}
	copy(virtualIP[:], payload[0:4])
	copy(subnetMask[:], payload[4:8])
	copy(serverIP[:], payload[8:12])
	mtu = binary.BigEndian.Uint16(payload[12:14])
	return
}

// NewDataPacket wraps a raw IP packet in a DATA packet.
func NewDataPacket(sessionID uint32, ipPacket []byte) *Packet {
	return &Packet{
		Type:      TypeData,
		SessionID: sessionID,
		Payload:   ipPacket,
	}
}

// NewPingPacket creates a PING packet.
func NewPingPacket(sessionID uint32) *Packet {
	return &Packet{
		Type:      TypePing,
		SessionID: sessionID,
	}
}

// NewPongPacket creates a PONG packet.
func NewPongPacket(sessionID uint32) *Packet {
	return &Packet{
		Type:      TypePong,
		SessionID: sessionID,
	}
}

// NewDisconnectPacket creates a DISCONNECT packet.
func NewDisconnectPacket(sessionID uint32) *Packet {
	return &Packet{
		Type:      TypeDisconnect,
		SessionID: sessionID,
	}
}

// NewPeerListPacket creates a PEER_LIST packet.
func NewPeerListPacket(sessionID uint32, peers []PeerInfo) *Packet {
	// Calculate payload size.
	size := 1 // count byte
	for _, p := range peers {
		size += 4 + 1 + len(p.Name) // ip(4) + nameLen(1) + name
	}

	payload := make([]byte, size)
	payload[0] = byte(len(peers))
	offset := 1
	for _, p := range peers {
		copy(payload[offset:offset+4], p.VirtualIP[:])
		offset += 4
		nameBytes := []byte(p.Name)
		if len(nameBytes) > 255 {
			nameBytes = nameBytes[:255]
		}
		payload[offset] = byte(len(nameBytes))
		offset++
		copy(payload[offset:], nameBytes)
		offset += len(nameBytes)
	}

	return &Packet{
		Type:      TypePeerList,
		SessionID: sessionID,
		Payload:   payload,
	}
}

// PeerInfo holds info about a connected peer.
type PeerInfo struct {
	VirtualIP [4]byte
	Name      string
}

// ParsePeerListPayload extracts peer info from a PEER_LIST payload.
func ParsePeerListPayload(payload []byte) ([]PeerInfo, error) {
	if len(payload) < 1 {
		return nil, ErrShortRead
	}

	count := int(payload[0])
	peers := make([]PeerInfo, 0, count)
	offset := 1

	for i := 0; i < count; i++ {
		if offset+5 > len(payload) {
			return nil, ErrShortRead
		}

		var p PeerInfo
		copy(p.VirtualIP[:], payload[offset:offset+4])
		offset += 4

		nameLen := int(payload[offset])
		offset++

		if offset+nameLen > len(payload) {
			return nil, ErrShortRead
		}

		p.Name = string(payload[offset : offset+nameLen])
		offset += nameLen
		peers = append(peers, p)
	}

	return peers, nil
}

// NewErrorPacket creates an ERROR packet.
func NewErrorPacket(sessionID uint32, code byte, message string) *Packet {
	msgBytes := []byte(message)
	payload := make([]byte, 1+len(msgBytes))
	payload[0] = code
	copy(payload[1:], msgBytes)

	return &Packet{
		Type:      TypeError,
		SessionID: sessionID,
		Payload:   payload,
	}
}
