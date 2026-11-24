package quicwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PacketClass is the parser-level QUIC packet classification.
type PacketClass string

const (
	ClassInitial            PacketClass = "Initial"
	ClassZeroRTT            PacketClass = "0-RTT"
	ClassHandshake          PacketClass = "Handshake"
	ClassRetry              PacketClass = "Retry"
	ClassVersionNegotiation PacketClass = "VersionNegotiation"
	ClassShort              PacketClass = "1-RTTShort"
	ClassStatelessReset     PacketClass = "StatelessReset"
)

// QUIC v1 version.
const Version1 uint32 = 0x00000001

var (
	ErrTruncated       = errors.New("quic: truncated packet")
	ErrBadLongHeader   = errors.New("quic: malformed long header")
	ErrUnsupportedCIDL = errors.New("quic: cid length exceeds 20 bytes")
)

// Header contains the routing-relevant fields of a QUIC header. Payload is not
// parsed because the simulator models transfer semantics above packet
// protection.
type Header struct {
	FirstByte       byte
	Long            bool
	Class           PacketClass
	Version         uint32
	DCID            []byte
	SCID            []byte
	Versions        []uint32
	ShortDCIDLength int
}

// Parse parses enough of a real QUIC v1/version-negotiation header to route a
// packet. Short headers have no DCID length field, so the deployment's fixed,
// agreed CID length must be supplied.
func Parse(packet []byte, shortDCIDLen int) (*Header, error) {
	if len(packet) < 1 {
		return nil, ErrTruncated
	}
	h := &Header{FirstByte: packet[0], ShortDCIDLength: shortDCIDLen}

	if packet[0]&0x80 == 0 {
		h.Long = false
		h.Class = ClassShort
		if shortDCIDLen < 0 || shortDCIDLen > 20 {
			return nil, ErrUnsupportedCIDL
		}
		if len(packet) < 1+shortDCIDLen {
			return nil, fmt.Errorf("%w: short header needs %d DCID bytes", ErrTruncated, shortDCIDLen)
		}
		h.DCID = append([]byte(nil), packet[1:1+shortDCIDLen]...)
		return h, nil
	}

	h.Long = true
	if len(packet) < 6 {
		return nil, fmt.Errorf("%w: long header fixed prefix", ErrTruncated)
	}
	h.Version = binary.BigEndian.Uint32(packet[1:5])
	off := 5

	dcid, next, err := parseLengthPrefixedCID(packet, off)
	if err != nil {
		return nil, err
	}
	h.DCID, off = dcid, next

	scid, next, err := parseLengthPrefixedCID(packet, off)
	if err != nil {
		return nil, err
	}
	h.SCID, off = scid, next

	if h.Version == 0 {
		h.Class = ClassVersionNegotiation
		for off+4 <= len(packet) {
			h.Versions = append(h.Versions, binary.BigEndian.Uint32(packet[off:off+4]))
			off += 4
		}
		return h, nil
	}

	switch packet[0] & 0x30 {
	case 0x00:
		h.Class = ClassInitial
	case 0x10:
		h.Class = ClassZeroRTT
	case 0x20:
		h.Class = ClassHandshake
	case 0x30:
		h.Class = ClassRetry
	default:
		return nil, ErrBadLongHeader
	}
	return h, nil
}

func parseLengthPrefixedCID(b []byte, off int) ([]byte, int, error) {
	if off >= len(b) {
		return nil, 0, fmt.Errorf("%w: missing CID length", ErrTruncated)
	}
	n := int(b[off])
	off++
	if n > 20 {
		return nil, 0, ErrUnsupportedCIDL
	}
	if len(b)-off < n {
		return nil, 0, fmt.Errorf("%w: cid of length %d", ErrTruncated, n)
	}
	cid := append([]byte(nil), b[off:off+n]...)
	return cid, off + n, nil
}

// BuildShort builds a QUIC v1 short header followed by simplified payload.
func BuildShort(dcid []byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(dcid)+len(payload))
	out = append(out, 0x40) // header form 0, fixed bit 1; spin/key bits zero
	out = append(out, dcid...)
	out = append(out, payload...)
	return out
}

// BuildInitial builds a realistic-enough Initial long header. The cryptographic
// payload is replaced by a plaintext simulation marker.
func BuildInitial(dcid, scid []byte, payload []byte) []byte {
	out := buildLongFirst(ClassInitial, Version1, dcid, scid)
	out = appendQUICVarint(out, 0)           // Initial Token Length
	body := append([]byte{0x00}, payload...) // one-byte packet number placeholder
	out = appendQUICVarint(out, uint64(len(body)))
	out = append(out, body...)
	return out
}

// BuildHandshake builds a Handshake long header plus simplified payload.
func BuildHandshake(dcid, scid []byte, payload []byte) []byte {
	out := buildLongFirst(ClassHandshake, Version1, dcid, scid)
	body := append([]byte{0x00}, payload...)
	out = appendQUICVarint(out, uint64(len(body)))
	out = append(out, body...)
	return out
}

// BuildUnsupportedInitial builds an Initial-like long header with an unknown
// version, prompting a Version Negotiation response.
func BuildUnsupportedInitial(version uint32, dcid, scid []byte) []byte {
	return buildLongFirst(ClassInitial, version, dcid, scid)
}

// BuildVersionNegotiation builds a version negotiation packet. Version is zero
// in the header and supported versions follow the two CIDs.
func BuildVersionNegotiation(dcid, scid []byte, versions ...uint32) []byte {
	out := buildLongFirst(ClassVersionNegotiation, 0, dcid, scid)
	for _, v := range versions {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], v)
		out = append(out, buf[:]...)
	}
	return out
}

// BuildStatelessReset appends a 16-byte reset token at the tail as required by
// QUIC. The preceding bytes are intentionally random-looking.
func BuildStatelessReset(lookedLikeDCID, randomPrefix, token []byte) []byte {
	if len(token) != 16 {
		panic("quic: stateless reset token must be 16 bytes")
	}
	out := make([]byte, 0, 1+len(lookedLikeDCID)+len(randomPrefix)+16)
	out = append(out, 0x40)
	out = append(out, lookedLikeDCID...)
	out = append(out, randomPrefix...)
	out = append(out, token...)
	return out
}

// IsStatelessReset reports whether b ends with token. Callers should first
// ensure the packet is long enough; QUIC endpoints identify resets by the
// final 16 bytes rather than by a distinct packet-type field.
func IsStatelessReset(packet, token []byte) bool {
	if len(token) != 16 || len(packet) < 21 {
		return false
	}
	return subtleConstantTimeEqual(packet[len(packet)-16:], token)
}

// TrailingToken returns the final 16 bytes, which may be a reset token.
func TrailingToken(packet []byte) []byte {
	if len(packet) < 16 {
		return nil
	}
	return packet[len(packet)-16:]
}

func buildLongFirst(class PacketClass, version uint32, dcid, scid []byte) []byte {
	first := byte(0xC0)
	switch class {
	case ClassInitial:
		first |= 0x00
	case ClassZeroRTT:
		first |= 0x10
	case ClassHandshake:
		first |= 0x20
	case ClassRetry:
		first |= 0x30
	case ClassVersionNegotiation:
		// RFC 9000 leaves the seven low bits unprotected/reserved in VN.
		first = 0x80
	}
	out := []byte{first}
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], version)
	out = append(out, ver[:]...)
	out = appendLengthCID(out, dcid)
	out = appendLengthCID(out, scid)
	return out
}

func appendLengthCID(out, cid []byte) []byte {
	if len(cid) > 20 {
		panic("quic: cid longer than 20 bytes")
	}
	out = append(out, byte(len(cid)))
	return append(out, cid...)
}

// appendQUICVarint encodes values used by the simplified builder. Values in
// this program are small, but implementing the real two-bit prefix keeps the
// framing recognizable.
func appendQUICVarint(out []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(out, byte(v))
	case v <= 16383:
		return append(out, byte(0x40|(v>>8)), byte(v))
	case v <= 1073741823:
		return append(out, byte(0x80|(v>>24)), byte(v>>16), byte(v>>8), byte(v))
	default:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], v|0xc000000000000000)
		return append(out, buf[:]...)
	}
}

func subtleConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
