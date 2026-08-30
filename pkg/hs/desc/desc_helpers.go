package desc

import (
	"encoding/base64"
	"fmt"
	"io"

	"github.com/robogg133/gonion/pkg/lspec"
)

// bufReader is a tiny big-endian byte reader over a slice, used to decode the
// binary intro-point block without pulling in the full relay cell decoder.
type bufReader struct {
	b   []byte
	pos int
}

func newBufReader(b []byte) *bufReader { return &bufReader{b: b} }

func (r *bufReader) remaining() int { return len(r.b) - r.pos }

func (r *bufReader) PeekByte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	return r.b[r.pos], nil
}

func (r *bufReader) ReadByte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *bufReader) UnreadByte() error {
	if r.pos == 0 {
		return fmt.Errorf("hs/desc: unread past start")
	}
	r.pos--
	return nil
}

func (r *bufReader) ReadU16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, fmt.Errorf("hs/desc: short u16")
	}
	v := uint16(r.b[r.pos])<<8 | uint16(r.b[r.pos+1])
	r.pos += 2
	return v, nil
}

func (r *bufReader) ReadExact(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, fmt.Errorf("hs/desc: short read want %d have %d", n, r.remaining())
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

// readKeyField reads TYPE(1) LEN(2) KEY(LE) — shared by the onion and auth keys.
func readKeyField(r *bufReader) ([]byte, error) {
	if _, err := r.ReadByte(); err != nil { // type
		return nil, err
	}
	n, err := r.ReadU16()
	if err != nil {
		return nil, err
	}
	return r.ReadExact(int(n))
}

// skipExt skips one extension: TYPE(1) LEN(1) DATA(LEN).
func skipExt(r *bufReader) error {
	if _, err := r.ReadByte(); err != nil { // type
		return err
	}
	n, err := r.ReadByte()
	if err != nil {
		return err
	}
	_, err = r.ReadExact(int(n))
	return err
}

// readLinkSpecifiers reads a length-delimited list of link specifiers. Each is
// TYPE(1) LEN(1) DATA(LEN) — lspec does the structured parse per specifier.
func readLinkSpecifiers(r *bufReader) ([]lspec.Lspec, error) {
	n, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var specs []lspec.Lspec
	for range n {
		lsType, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		l, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		raw, err := r.ReadExact(int(l))
		if err != nil {
			return nil, err
		}
		s, err := lspec.FromWire(lsType, raw)
		if err != nil {
			return nil, fmt.Errorf("hs/desc: link specifier: %w", err)
		}
		specs = append(specs, s)
	}
	return specs, nil
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
