package quicwire

import (
	"bytes"
	"testing"
)

func TestCIDEncodeDecode(t *testing.T) {
	codec := NewCIDCodec("shared-lb-backend-secret", 0xC1)
	nonce := [7]byte{1, 2, 3, 4, 5, 6, 7}
	cid, err := codec.Encode(42, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(cid) != CIDLength {
		t.Fatalf("CID length = %d, want %d", len(cid), CIDLength)
	}
	got, err := codec.Decode(cid)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != 42 {
		t.Fatalf("backend = %d, want 42", got)
	}

	other, err := codec.Encode(42, [7]byte{9, 8, 7, 6, 5, 4, 3})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cid, other) {
		t.Fatal("same backend with different nonce produced identical CIDs")
	}
}

func TestCIDRejectsTamperingAndWrongSecret(t *testing.T) {
	codec := NewCIDCodec("shared-secret", 0xC1)
	cid, err := codec.Encode(7, [7]byte{0, 1, 2, 3, 4, 5, 6})
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), cid...)
	tampered[9] ^= 0xff // encrypted backend identity
	if _, err := codec.Decode(tampered); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}

	forged := append([]byte(nil), cid...)
	forged[15] ^= 0x01 // truncated MAC
	if _, err := codec.Decode(forged); err == nil {
		t.Fatal("tampered MAC was accepted")
	}

	attacker := NewCIDCodec("attacker-secret", 0xC1)
	fake, err := attacker.Encode(1, [7]byte{6, 5, 4, 3, 2, 1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(fake); err == nil {
		t.Fatal("CID minted with wrong secret was accepted")
	}
}

func TestHeaderParsing(t *testing.T) {
	dcid := []byte("server-cid-123456789") // exactly 20 bytes
	scid := []byte("client-scid")
	initial := BuildInitial(dcid, scid, []byte("payload"))
	h, err := Parse(initial, CIDLength)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Long || h.Class != ClassInitial || h.Version != Version1 {
		t.Fatalf("bad initial header: %+v", h)
	}
	if !bytes.Equal(h.DCID, dcid) || !bytes.Equal(h.SCID, scid) {
		t.Fatalf("CID mismatch: %x / %x", h.DCID, h.SCID)
	}

	short := BuildShort(dcid, []byte("0rtt-ish"))
	sh, err := Parse(short, CIDLength)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Long || sh.Class != ClassShort || !bytes.Equal(sh.DCID, dcid) {
		t.Fatalf("bad short header: %+v", sh)
	}
	wrongLen, err := Parse(short, 19)
	if err != nil {
		t.Fatalf("a shorter agreed length can still slice a long packet: %v", err)
	}
	if len(wrongLen.DCID) != 19 {
		t.Fatalf("agreed length was not honored: %d", len(wrongLen.DCID))
	}

	vn := BuildVersionNegotiation(dcid, scid, Version1, 0x6b3343cf)
	vh, err := Parse(vn, CIDLength)
	if err != nil {
		t.Fatal(err)
	}
	if vh.Class != ClassVersionNegotiation || vh.Version != 0 || len(vh.Versions) != 2 {
		t.Fatalf("bad VN header: %+v", vh)
	}

	token := bytes.Repeat([]byte{0x42}, 16)
	reset := BuildStatelessReset(dcid, []byte("unpredictable-padding"), token)
	if !IsStatelessReset(reset, token) {
		t.Fatal("valid stateless reset token not recognized")
	}
	if IsStatelessReset(reset, bytes.Repeat([]byte{0x99}, 16)) {
		t.Fatal("stateless reset accepted wrong token")
	}
}
