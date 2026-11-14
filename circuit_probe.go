package gonion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/robogg133/gonion/pkg/cells/relay"
	"github.com/robogg133/gonion/pkg/hs/capi"
)

// path-spec §7.2: "all circuits that are still marked as usage attempts are
// probed using a RELAY_BEGIN cell constructed with a destination of the form
// 0.a.b.c:25, where a.b.c is a 24 bit random nonce. If we get a
// RELAY_COMMAND_END in response matching our nonce, the circuit is counted as
// successfully used." C Tor implements this in
// src/feature/client/circpathbias.c:pathbias_send_usable_probe and
// pathbias_check_probe_response.
const (
	// pathBiasProbePort is the fixed port of the probe destination.
	pathBiasProbePort uint16 = 25

	// pathBiasProbeNonceMask keeps the random destination a 24-bit value, so
	// the first address octet is always zero and the remaining three octets
	// carry the nonce (tor_dup_ip of a masked uint32).
	pathBiasProbeNonceMask uint32 = 0x00ffffff
)

// pathBiasProbeKey identifies one outstanding probe. StreamIDs are unique per
// circuit (tor-spec 6.2), not globally, so the owning circuit is part of the
// key.
type pathBiasProbeKey struct {
	circuit  *Circuit
	streamID uint16
}

// pathBiasProbe is the transient state of one probe. The read loop delivers
// the first relay cell that arrives on the reserved StreamID.
type pathBiasProbe struct {
	nonce     uint32
	responses chan pathBiasProbeResponse
}

type pathBiasProbeResponse struct {
	matched bool
}

// pathBiasProbes holds probes that are on the wire for a live circuit. Entries
// exist only for the duration of PathBiasProbe; the read loop needs them to
// recognize a reply for a StreamID that has no Stream.
var pathBiasProbes sync.Map // pathBiasProbeKey -> *pathBiasProbe

// newPathBiasProbeNonce draws the 24-bit probe nonce from crypto/rand.
func newPathBiasProbeNonce() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]) & pathBiasProbeNonceMask, nil
}

// pathBiasProbeTarget formats a nonce as path-spec §7.2's 0.a.b.c:25, matching
// C Tor's tor_dup_ip of the masked nonce followed by ":25".
func pathBiasProbeTarget(nonce uint32) string {
	return fmt.Sprintf("0.%d.%d.%d:%d",
		(nonce>>16)&0xff, (nonce>>8)&0xff, nonce&0xff, pathBiasProbePort)
}

// reservePathBiasProbeStreamID allocates a never-reused StreamID for a probe
// without installing a Stream. It mirrors reserveStream's allocator
// (tor-spec 6.2: IDs may not be reused, even after a stream closes) but skips
// the live-stream ceiling: a probe is not a stream, and C Tor's
// get_unique_stream_id_by_circ only requires uniqueness.
func (c *Circuit) reservePathBiasProbeStreamID() (uint16, error) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	for c.nextStreamID <= 65535 && (c.nextStreamID == 0 || c.usedStreamIDs[c.nextStreamID/8]&(1<<(c.nextStreamID%8)) != 0) {
		c.nextStreamID++
	}
	if c.nextStreamID > 65535 {
		return 0, Public(ErrStream, "circuit stream IDs exhausted")
	}
	id := uint16(c.nextStreamID)
	c.nextStreamID++
	c.usedStreamIDs[id/8] |= 1 << (id % 8)
	return id, nil
}

// PathBiasProbe sends the path-spec §7.2 END-echo reachability probe on this
// circuit and reports whether the last hop echoed the probe's random 24-bit
// nonce.
//
// The probe reserves a fresh StreamID and stores probe state before the BEGIN
// is written, so a fast reply cannot be lost. It is interrupted by ctx, a
// caller deadline, or circuit teardown, and it removes its state before
// returning. A normal Stream can never own the probe StreamID, so it cannot
// consume the probe's RELAY_END. A caller context without a deadline is
// bounded by pathBiasProbeDefaultTimeout, so a silent exit cannot hang the
// caller forever; an existing caller deadline stays authoritative.
//
// A returned PathBiasProbeMismatched with a context error means the probe was
// sent but not confirmed: a sent probe is only ever reported as matched by a
// matching nonce echo.
func (c *Circuit) PathBiasProbe(ctx context.Context) (capi.PathBiasProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return capi.PathBiasProbeUnsent, context.Cause(ctx)
	}
	ctx, cancel := pathBiasProbeContext(ctx)
	defer cancel()
	if err := c.Ctx.Err(); err != nil {
		return capi.PathBiasProbeUnsent, circuitCause(c.Ctx)
	}
	// Only a completed circuit can be probed: C Tor requires the last hop's
	// cpath entry to be open, and a probe on a half-built circuit would test
	// extension state rather than the guard path.
	if !c.established.Load() || c.hops.Len() == 0 {
		return capi.PathBiasProbeUnsent, Public(ErrCircuit, "path bias probe requires a completed circuit")
	}

	nonce, err := newPathBiasProbeNonce()
	if err != nil {
		return capi.PathBiasProbeUnsent, fail(c.Ctx, ErrCircuit, "path bias probe nonce generation failed", err)
	}
	streamID, err := c.reservePathBiasProbeStreamID()
	if err != nil {
		return capi.PathBiasProbeUnsent, err
	}

	probe := &pathBiasProbe{nonce: nonce, responses: make(chan pathBiasProbeResponse, 1)}
	key := pathBiasProbeKey{circuit: c, streamID: streamID}
	pathBiasProbes.Store(key, probe)
	defer pathBiasProbes.Delete(key)

	log := logger(c.Ctx).With().
		Str("component", "pathbias").
		Uint16("probe_stream_id", streamID).
		Uint32("probe_nonce", nonce).
		Logger()

	begin := &relay.BeginCell{StreamID: streamID, Addrport: pathBiasProbeTarget(nonce)}
	if err := c.sendRelayContext(ctx, begin, c.hops.Len()-1, false); err != nil {
		log.Debug().Err(err).Msg("path bias probe not sent")
		return capi.PathBiasProbeUnsent, err
	}
	log.Debug().Msg("path bias probe sent")

	select {
	case response := <-probe.responses:
		if response.matched {
			log.Debug().Msg("path bias probe matched")
			return capi.PathBiasProbeMatched, nil
		}
		log.Debug().Msg("path bias probe did not match the echoed nonce")
		return capi.PathBiasProbeMismatched, nil
	case <-ctx.Done():
		log.Debug().Err(context.Cause(ctx)).Msg("path bias probe interrupted")
		return capi.PathBiasProbeMismatched, context.Cause(ctx)
	case <-c.Ctx.Done():
		log.Debug().Err(circuitCause(c.Ctx)).Msg("circuit died during path bias probe")
		return capi.PathBiasProbeMismatched, circuitCause(c.Ctx)
	}
}

// routePathBiasProbe delivers a relay cell addressed to an outstanding probe
// and reports whether the cell belonged to one. The read loop calls it before
// the generic stream lookup so a probe reply is never dropped as an unknown
// stream. Any cell other than a nonce-matching EXITPOLICY RELAY_END is
// reported as a mismatch, per path-spec §7.2: unrecognized cells after the
// probe make the usage a failure.
func (c *Circuit) routePathBiasProbe(cell relay.Cell) bool {
	if cell == nil {
		return false
	}
	value, ok := pathBiasProbes.Load(pathBiasProbeKey{circuit: c, streamID: cell.GetStreamID()})
	if !ok {
		return false
	}
	probe := value.(*pathBiasProbe)
	response := pathBiasProbeResponse{}
	if end, ok := cell.(*relay.RelayEndCell); ok {
		response.matched = end.Reason == relay.END_REASON_EXITPOLICY && probe.matchesEcho(end)
	}
	select {
	case probe.responses <- response:
	default:
		// The waiter returns on the first response; later cells change nothing.
	}
	return true
}

// matchesEcho compares the IPv4 address echoed in an EXITPOLICY RELAY_END
// with the probe nonce, exactly as C Tor's pathbias_check_probe_response does
// after its length check.
func (p *pathBiasProbe) matchesEcho(end *relay.RelayEndCell) bool {
	addr, ok := end.EchoedIPv4()
	if !ok {
		return false
	}
	return binary.BigEndian.Uint32(addr[:]) == p.nonce
}

// pathBiasProbeDefaultTimeout bounds PathBiasProbe when the caller supplies a
// context without a deadline. A probe is one relay round trip; without this
// bound a silent or hostile exit could hang a caller that used
// context.Background() until the circuit died. A deadline the caller or the
// capi guard wrapper already set is never replaced.
const pathBiasProbeDefaultTimeout = 30 * time.Second

// pathBiasProbeContext returns the caller's context unchanged when it already
// carries a deadline, and otherwise a copy bounded by
// pathBiasProbeDefaultTimeout.
func pathBiasProbeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, pathBiasProbeDefaultTimeout)
}

// rememberStreamFailure records the relay END reason received in response to
// the most recent failed stream attachment attempt (path-spec §7.2). A zero
// reason is never recorded: it means "no END reason", not a failure.
func (c *Circuit) rememberStreamFailure(reason uint8) {
	if reason != 0 {
		c.streamFailReason.Store(uint32(reason))
	}
}

// StreamFailureReason returns the END reason recorded by
// rememberStreamFailure, or zero when no failed stream attempt was recorded.
// It implements the optional capi.StreamFailureReasoner capability, which the
// guard wrapper consults before sending the close-time probe.
func (c *Circuit) StreamFailureReason() uint8 {
	if r := c.streamFailReason.Load(); r <= 0xff {
		return uint8(r)
	}
	return 0
}

// lockRelayContext acquires the circuit's relay marshal lock without blocking
// indefinitely: it returns the context's error once the wait can no longer
// succeed. Without the bound, a relay writer stuck while holding relayMu
// could defeat the bounded PathBiasProbe wait and any other
// deadline-carrying caller (a held lock previously blocked forever).
func (c *Circuit) lockRelayContext(ctx context.Context) error {
	if ctx == nil {
		ctx = c.Ctx
	}
	for {
		if c.relayMu.TryLock() {
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
}

// circuitCause returns the non-nil cancellation cause of a circuit context.
func circuitCause(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ErrClosed
}
