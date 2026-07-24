package gonion

import (
	"errors"
	"fmt"
)

// Public sentinel errors for API consumers. Internal detail is logged, not exposed.
var (
	ErrClosed            = errors.New("gonion: closed")
	ErrProtocolViolation = errors.New("gonion: protocol violation")
	ErrHandshake         = errors.New("gonion: handshake failed")
	ErrTLS               = errors.New("gonion: tls failed")
	ErrVersion           = errors.New("gonion: version negotiation failed")
	ErrCircuit           = errors.New("gonion: circuit error")
	ErrExtend            = errors.New("gonion: circuit extend failed")
	ErrStream            = errors.New("gonion: stream error")
	ErrStreamClosed      = errors.New("gonion: stream closed")
	ErrDecrypt           = errors.New("gonion: relay decrypt failed")
	ErrInvalidHop        = errors.New("gonion: invalid hop")
	ErrSendMe            = errors.New("gonion: sendme verification failed")
	ErrIO                = errors.New("gonion: i/o error")
	ErrTimeout           = errors.New("gonion: timeout")
	ErrBootstrap         = errors.New("gonion: bootstrap failed")
	ErrDirectory         = errors.New("gonion: directory fetch failed")
)

// publicError is a stable API error. Message is safe for callers; Unwrap is the sentinel.
type publicError struct {
	sent error
	msg  string
}

func (e *publicError) Error() string {
	if e.msg == "" {
		return e.sent.Error()
	}
	return e.sent.Error() + ": " + e.msg
}

func (e *publicError) Unwrap() error { return e.sent }

func (e *publicError) Is(target error) bool {
	return errors.Is(e.sent, target)
}

// Public returns a caller-safe error rooted at sentinel.
func Public(sentinel error, msg string) error {
	if msg == "" {
		return sentinel
	}
	return &publicError{sent: sentinel, msg: msg}
}

// Publicf is Public with fmt.Sprintf.
func Publicf(sentinel error, format string, args ...any) error {
	return Public(sentinel, fmt.Sprintf(format, args...))
}
